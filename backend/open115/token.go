package open115

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/lib/rest"
	"github.com/skip2/go-qrcode"

	"github.com/rclone/rclone/backend/open115/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/fserrors"
)

// ErrQRCodeTimeout is returned when QR code scanning times out.
var ErrQRCodeTimeout = errors.New("QR code scanning timeout, please run configuration again")

// ErrQRCodeExpired is returned when the authorization QR code expires.
var ErrQRCodeExpired = errors.New("QR code expired, please run configuration again")

// ErrQRCodeCanceled is returned when QR code authorization is canceled.
var ErrQRCodeCanceled = errors.New("QR code authorization canceled")

const (
	errorCodeNoAuth              = 40140116
	errorCodeRefreshTokenExpired = 40140119
	errorCodeRefreshTokenInvalid = 40140120
)

// OAuth related constants
const (
	tokenExpiryGrace     = 60 * time.Second   // Grace period before token expiry
	tokenRefreshDuration = 3600 * time.Second // Default token validity is 1 hour
	qrCodeTimeout        = 5 * time.Minute    // QR code validity period
	qrCodePollInterval   = 2 * time.Second    // Polling interval
)

// qrCodeStatus represents QR code scanning status
type qrCodeStatus int

// Scanning status
const (
	qrCodeStatusWaiting   qrCodeStatus = 0 // Waiting for scan
	qrCodeStatusScanned   qrCodeStatus = 1 // Scanned, waiting for confirmation
	qrCodeStatusConfirmed qrCodeStatus = 2 // Confirmed
	qrCodeStatusExpired   qrCodeStatus = -1
	qrCodeStatusCanceled  qrCodeStatus = -2
)

// TokenSource is a custom OAuth2 TokenSource implementation
type TokenSource struct {
	name   string           // Remote name
	ctx    context.Context  // Context
	c      *rest.Client     // API client
	token  *api.Token       // Current token
	expiry time.Time        // Token expiry time
	m      configmap.Mapper // Configuration mapper
	mu     sync.RWMutex     // Mutex
}

// NewTokenSource creates a new TokenSource
func NewTokenSource(ctx context.Context, name string, m configmap.Mapper, client *rest.Client) (*TokenSource, error) {
	ts := &TokenSource{
		c:    client,
		ctx:  ctx,
		name: name,
		m:    m,
	}
	// Try to load token from configuration
	err := ts.readToken()
	if err != nil {
		return nil, err
	}
	return ts, nil
}

// readToken reads token from configuration
func (ts *TokenSource) readToken() error {
	tokenJSON, found := ts.m.Get(config.ConfigToken)
	if !found || tokenJSON == "" {
		refreshToken, refreshTokenFound := ts.m.Get("refresh_token")
		if !refreshTokenFound || refreshToken == "" {
			return fmt.Errorf("token not found, please run 'rclone config reconnect %s:'", ts.name)
		}
		ts.token = &api.Token{
			RefreshToken: refreshToken,
		}
		return ts.refreshToken()
	}

	token := &api.Token{}
	err := json.Unmarshal([]byte(tokenJSON), token)
	if err != nil {
		return fmt.Errorf("unable to parse token: %w", err)
	}

	ts.token = token
	// Set expiry time, if not set calculate from current time
	if ts.token.ExpiresAt.IsZero() {
		ts.token.ExpiresAt = time.Now().Add(tokenRefreshDuration)
	}
	ts.expiry = ts.token.ExpiresAt

	return nil
}

// reReadToken reloads a token rotated by another rclone process.
// The caller must hold ts.mu for writing.
func (ts *TokenSource) reReadToken() (bool, error) {
	tokenJSON, found := ts.m.Get(config.ConfigToken)
	if !found || tokenJSON == "" {
		return false, nil
	}
	var token api.Token
	if err := json.Unmarshal([]byte(tokenJSON), &token); err != nil {
		return false, fmt.Errorf("unable to parse token: %w", err)
	}
	if token.ExpiresAt.IsZero() {
		token.ExpiresAt = time.Now().Add(tokenRefreshDuration)
	}
	if ts.token != nil && token.AccessToken == ts.token.AccessToken && token.RefreshToken == ts.token.RefreshToken && token.ExpiresAt.Equal(ts.token.ExpiresAt) {
		return false, nil
	}
	ts.token = &token
	ts.expiry = token.ExpiresAt
	return true, nil
}

// Token gets a valid token, refreshing if necessary
func (ts *TokenSource) Token() (string, error) {
	// First try to check if token is valid using read lock
	ts.mu.RLock()
	hasValidToken := ts.token != nil && !ts.isTokenExpired()
	accessToken := ""
	if hasValidToken {
		accessToken = ts.token.AccessToken
		ts.mu.RUnlock()
		return accessToken, nil
	} else {
		ts.mu.RUnlock()
	}

	// If token is invalid, acquire write lock to refresh
	ts.mu.Lock()
	defer ts.mu.Unlock()

	// Double check to avoid other goroutines refreshing the token while acquiring lock
	if ts.token != nil && !ts.isTokenExpired() {
		return ts.token.AccessToken, nil
	}
	if _, err := ts.reReadToken(); err != nil {
		return "", err
	}
	if ts.token != nil && !ts.isTokenExpired() {
		return ts.token.AccessToken, nil
	}

	// Refresh token
	err := ts.refreshToken()
	if err != nil {
		return "", err
	}
	return ts.token.AccessToken, nil
}

// Refresh refreshes a token rejected by the API, using a token rotated by another process when available.
func (ts *TokenSource) Refresh() (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	oldAccessToken := ""
	if ts.token != nil {
		oldAccessToken = ts.token.AccessToken
	}
	changed, err := ts.reReadToken()
	if err != nil {
		return "", err
	}
	if changed && ts.token.AccessToken != oldAccessToken && !ts.isTokenExpired() {
		return ts.token.AccessToken, nil
	}
	if err = ts.refreshToken(); err != nil {
		return "", err
	}
	return ts.token.AccessToken, nil
}

// isTokenExpired checks if token is expired
func (ts *TokenSource) isTokenExpired() bool {
	if ts.token == nil {
		return true
	}
	return time.Now().Add(tokenExpiryGrace).After(ts.expiry)
}

// refreshToken refreshes the token
func (ts *TokenSource) refreshToken() error {
	if ts.token == nil || ts.token.RefreshToken == "" {
		return fmt.Errorf("no valid refresh token, please run 'rclone config reconnect %s:'", ts.name)
	}
	formData := url.Values{}
	formData.Set("refresh_token", ts.token.RefreshToken)
	opts := rest.Opts{
		Method:      "POST",
		RootURL:     passportAPI,
		Path:        "/open/refreshToken",
		ContentType: "application/x-www-form-urlencoded",
		Body:        strings.NewReader(formData.Encode()),
	}
	var resp api.TokenResponse
	resetAPIResponse(&resp)
	_, err := ts.c.CallJSON(ts.ctx, &opts, nil, &resp)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w", err)
	}
	// Check if token expired
	if resp.Code == errorCodeRefreshTokenExpired || resp.Code == errorCodeRefreshTokenInvalid || resp.Code == errorCodeNoAuth {
		clearErr := ts.clearToken(true)
		return errors.Join(fmt.Errorf("refresh token expired or invalid: %s; please run 'rclone config reconnect %s:'", resp.ErrorDetails(), ts.name), clearErr)
	}

	// Check if response is valid
	if !resp.Success() {
		return fmt.Errorf("failed to get token from server: %s", resp.ErrorDetails())
	}
	if resp.Data.AccessToken == "" || resp.Data.RefreshToken == "" {
		clearErr := ts.clearToken(false)
		return errors.Join(errors.New("failed to get token from server: missing token data"), clearErr)
	}

	// Update token
	ts.token.AccessToken = resp.Data.AccessToken
	ts.token.RefreshToken = resp.Data.RefreshToken
	ts.expiry = time.Now().Add(time.Duration(resp.Data.ExpiresIn) * time.Second)
	ts.token.ExpiresAt = ts.expiry
	// Save new token to configuration
	err = ts.saveToken()
	if err != nil {
		return fmt.Errorf("failed to save token: %w", err)
	}
	return nil
}

func (ts *TokenSource) clearToken(clearRefreshToken bool) error {
	ts.token = nil
	ts.expiry = time.Time{}
	if clearRefreshToken {
		ts.m.Set("refresh_token", "")
	}
	return ts.saveToken()
}

// saveToken saves token to configuration
func (ts *TokenSource) saveToken() error {
	if ts.token == nil {
		ts.m.Set(config.ConfigToken, "")
		return nil
	}

	tokenJSON, err := json.Marshal(ts.token)
	if err != nil {
		return err
	}

	ts.m.Set(config.ConfigToken, string(tokenJSON))
	return nil
}

func (ts *TokenSource) callAPI(ctx context.Context, opts rest.Opts, response any, apiResp *api.Response) error {
	resetAPIResponse(response)
	_, err := ts.c.CallJSON(ctx, &opts, nil, response)
	if err != nil {
		return err
	}
	if apiResp != nil && !apiResp.Success() {
		return fmt.Errorf("API error: %s", apiResp.ErrorDetails())
	}
	return nil
}

func (ts *TokenSource) callAPIWithForm(ctx context.Context, opts rest.Opts, form url.Values, response any, apiResp *api.Response) error {
	opts.ContentType = "application/x-www-form-urlencoded"
	opts.Body = strings.NewReader(form.Encode())
	return ts.callAPI(ctx, opts, response, apiResp)
}

// Auth initiates the authorization process using QR code
func (ts *TokenSource) Auth(appID string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if appID == "" {
		return errors.New("Open115 application ID is required; create one at https://open.115.com/")
	}
	// Get QR code URL
	authData, err := ts.getAuthURL(ts.ctx, appID)
	if err != nil {
		return err
	}

	// Display QR code for user to scan
	fs.Logf(nil, "Please use the 115 mobile app to scan the QR code: %s", authData.QRCode)
	qrCode, err := qrcode.New(authData.QRCode, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %w", err)
	}
	fs.Print(nil, "\n"+qrCode.ToSmallString(false))

	// Wait for user to scan and confirm authorization
	token, err := ts.waitForQRCodeScan(ts.ctx, authData)
	if err != nil {
		return err
	}
	ts.token = token
	fs.Logf(nil, "open115 token successful, token saved to configuration")
	return ts.saveToken()
}

// getAuthURL generates QR code URL for user scanning
func (ts *TokenSource) getAuthURL(ctx context.Context, appID string) (authData *api.AuthDeviceCodeData, err error) {
	// Generate random code verifier
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, err
	}

	// Calculate code challenge
	codeChallenge := calculateCodeChallenge(codeVerifier)

	formData := url.Values{}
	formData.Set("client_id", appID)
	formData.Set("code_challenge", codeChallenge)
	formData.Set("code_challenge_method", "sha256")
	opts := rest.Opts{
		Method:  "POST",
		RootURL: passportAPI,
		Path:    "/open/authDeviceCode",
	}
	var resp api.AuthDeviceCodeResponse
	err = ts.callAPIWithForm(ctx, opts, formData, &resp, &resp.Response)
	if err != nil {
		return nil, fmt.Errorf("failed to get authorization code: %w", err)
	}
	// Save code verifier to response
	resp.Data.CodeVerifier = codeVerifier
	return &resp.Data, nil
}

// pollQRCodeStatus polls QR code status
func (ts *TokenSource) pollQRCodeStatus(ctx context.Context, authData *api.AuthDeviceCodeData) (qrCodeStatus, error) {
	opts := rest.Opts{
		Method:  "GET",
		RootURL: qrcodeAPI,
		Path:    "/get/status/",
		Parameters: url.Values{
			"uid":  []string{authData.UID},
			"time": []string{fmt.Sprintf("%d", authData.Time)},
			"sign": []string{authData.Sign},
		},
	}

	var resp api.QRCodeStatusResponse
	err := ts.callAPI(ctx, opts, &resp, &resp.Response)
	if err != nil {
		return qrCodeStatusWaiting, err
	}
	return qrCodeStatus(resp.Data.Status), nil
}

// waitForQRCodeScan waits for user to scan QR code and confirm authorization
func (ts *TokenSource) waitForQRCodeScan(ctx context.Context, authData *api.AuthDeviceCodeData) (*api.Token, error) {
	// Set timeout
	deadline := time.Now().Add(qrCodeTimeout)

	for time.Now().Before(deadline) {
		// Check if context is canceled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Poll QR code status
		status, err := ts.pollQRCodeStatus(ctx, authData)
		if err != nil {
			if !fserrors.ShouldRetry(err) {
				return nil, err
			}
			fs.Debugf(nil, "Temporary QR code status error: %v", err)
			status = qrCodeStatusWaiting
		}
		switch status {
		case qrCodeStatusConfirmed:
			return ts.codeToToken(ctx, authData)
		case qrCodeStatusScanned:
			fs.Logf(nil, "QR code scanned, waiting for authorization confirmation...")
		case qrCodeStatusWaiting:
			fs.Logf(nil, "Waiting for QR code scan...")
		case qrCodeStatusExpired:
			return nil, ErrQRCodeExpired
		case qrCodeStatusCanceled:
			return nil, ErrQRCodeCanceled
		default:
			return nil, fmt.Errorf("unknown QR code status %d", status)
		}

		// Wait for a while before polling again
		timer := time.NewTimer(qrCodePollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	return nil, ErrQRCodeTimeout
}

// codeToToken uses authorization code to get token
func (ts *TokenSource) codeToToken(ctx context.Context, authData *api.AuthDeviceCodeData) (*api.Token, error) {
	formData := url.Values{}
	formData.Set("uid", authData.UID)
	formData.Set("code_verifier", authData.CodeVerifier)
	opts := rest.Opts{
		Method:  "POST",
		RootURL: passportAPI,
		Path:    "/open/deviceCodeToToken",
	}
	var resp api.DeviceCodeToTokenResponse
	err := ts.callAPIWithForm(ctx, opts, formData, &resp, &resp.Response)
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}
	// Check if response is valid
	if resp.Data.AccessToken == "" || resp.Data.RefreshToken == "" {
		return nil, fmt.Errorf("failed to get token from server: %s", resp.ErrorDetails())
	}
	// Create Token object
	expiresAt := time.Now().Add(time.Duration(resp.Data.ExpiresIn) * time.Second)
	token := &api.Token{
		AccessToken:  resp.Data.AccessToken,
		RefreshToken: resp.Data.RefreshToken,
		ExpiresAt:    expiresAt,
	}
	return token, nil
}

// calculateCodeChallenge calculates the code challenge.
func calculateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// generateCodeVerifier generates a PKCE code verifier.
func generateCodeVerifier() (string, error) {
	data := make([]byte, 48)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("failed to generate PKCE verifier: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
