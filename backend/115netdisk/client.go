package netdisk115

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/backend/115netdisk/api"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/lib/rest"
	"golang.org/x/time/rate"
)

const (
	baseAPI              = "https://webapi.115.com"
	passportAPI          = "https://passportapi.115.com"
	uploadAPI            = "https://uplb.115.com"
	defaultListPageSize  = 1000
	defaultClientVersion = "37.3.1"
)

type client struct {
	*rest.Client
	httpClient *http.Client
	content    *rest.Client
	limiter    *rate.Limiter
	cookies    map[string]string
	userID     int64
	userAgent  string
	version    string
	keyMu      sync.Mutex
	userkey    string
}

func loadCookies(opt *Options) (map[string]string, error) {
	value := []byte(opt.Cookie)
	if len(value) == 0 {
		return nil, errors.New("paste a Cookie or run QR authorization")
	}
	cookies := make(map[string]string)
	if strings.HasPrefix(strings.TrimSpace(string(value)), "{") {
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(value, &raw); err != nil {
			return nil, fmt.Errorf("decode session JSON: %w", err)
		}
		if nested, ok := raw["cookies"]; ok {
			if user, present := raw["userId"]; present {
				var id api.String
				if err := json.Unmarshal(user, &id); err != nil {
					return nil, err
				}
				var saved map[string]string
				if err := json.Unmarshal(nested, &saved); err != nil {
					return nil, err
				}
				uid, _, _ := strings.Cut(saved["UID"], "_")
				if uid != string(id) {
					return nil, errors.New("saved session and Cookie accounts differ")
				}
			}
			value = nested
		} else if nested, ok := raw["cookie"]; ok {
			value = nested
		}
		if err := json.Unmarshal(value, &cookies); err != nil {
			return nil, fmt.Errorf("decode cookie dictionary: %w", err)
		}
	} else {
		for _, part := range strings.Split(string(value), ";") {
			key, val, found := strings.Cut(strings.TrimSpace(part), "=")
			if !found || key == "" {
				return nil, errors.New("invalid Cookie header syntax")
			}
			cookies[key] = val
		}
	}
	for _, key := range []string{"UID", "CID", "SEID"} {
		if cookies[key] == "" {
			return nil, fmt.Errorf("session is missing %s", key)
		}
	}
	for key, value := range cookies {
		if strings.ContainsAny(key, "\r\n;=") || strings.ContainsAny(value, "\r\n;") {
			return nil, errors.New("invalid session cookie character")
		}
	}
	return cookies, nil
}

func cookieHeader(cookies, download map[string]string) string {
	keys := make([]string, 0, len(cookies))
	values := make([]string, 0, len(cookies)+len(download))
	main := map[string]bool{"UID": true, "CID": true, "SEID": true, "KID": true, "115_lang": true}
	for _, key := range []string{"UID", "CID", "SEID", "KID"} {
		if value := cookies[key]; value != "" {
			values = append(values, key+"="+value)
		}
	}
	for key := range cookies {
		if main[key] {
			continue
		}
		if download != nil && len(key) == 32 {
			if _, err := strconv.ParseUint(key[:16], 16, 64); err == nil {
				if _, err = strconv.ParseUint(key[16:], 16, 64); err == nil {
					continue
				}
			}
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, key+"="+cookies[key])
	}
	language := cookies["115_lang"]
	if language == "" {
		language = "zh"
	}
	values = append(values, "115_lang="+language)
	keys = keys[:0]
	for key := range download {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values = append(values, key+"="+download[key])
	}
	return strings.Join(values, "; ")
}

func newClient(rc *rest.Client, hc *http.Client, opt *Options) (*client, error) {
	cookies, err := loadCookies(opt)
	if err != nil {
		return nil, err
	}
	uid, _, _ := strings.Cut(cookies["UID"], "_")
	userID, err := strconv.ParseInt(uid, 10, 32)
	if err != nil || userID <= 0 {
		return nil, errors.New("invalid user identifier in UID cookie")
	}
	if opt.ClientVersion == "" {
		opt.ClientVersion = defaultClientVersion
	}
	ua := opt.UserAgent
	if ua == "" {
		ua = "Mozilla/5.0; Mac OS X/13.0; 115Life/" + opt.ClientVersion
	}
	if strings.ContainsAny(ua, "\r\n") {
		return nil, errors.New("invalid User-Agent")
	}
	rc.SetHeader("Cookie", cookieHeader(cookies, nil)).SetHeader("User-Agent", ua).SetHeader("Accept", "application/json, text/plain, */*")
	return &client{Client: rc, httpClient: hc, content: rest.NewClient(hc).SetHeader("User-Agent", ua),
		limiter: rate.NewLimiter(5, 1), cookies: cookies, userID: userID, userAgent: ua, version: opt.ClientVersion}, nil
}

func (c *client) raw(ctx context.Context, opts *rest.Opts) (body []byte, resp *http.Response, err error) {
	if opts.Body != nil && opts.ContentLength == nil {
		if reader, ok := opts.Body.(interface{ Len() int }); ok {
			length := int64(reader.Len())
			opts.ContentLength = &length
		}
	}
	if err = c.limiter.Wait(ctx); err != nil {
		return nil, nil, err
	}
	resp, err = c.Client.Call(ctx, opts)
	if err != nil {
		return nil, resp, err
	}
	defer func() {
		closeErr := resp.Body.Close()
		if err == nil {
			err = closeErr
		}
	}()
	body, err = io.ReadAll(io.LimitReader(resp.Body, maxDecodedControl+1))
	if err == nil && len(body) > maxDecodedControl {
		err = errors.New("API response exceeds size limit")
	}
	return body, resp, err
}

func (c *client) CallJSON(ctx context.Context, opts *rest.Opts, request, response any) (*http.Response, error) {
	if request != nil {
		return nil, errors.New("115 API requires its explicit form encoding")
	}
	body, resp, err := c.raw(ctx, opts)
	if err != nil {
		return resp, err
	}
	if err = json.Unmarshal(body, response); err != nil {
		return resp, fmt.Errorf("decode 115 API response: %w", err)
	}
	return resp, nil
}

func (f *Fs) callAPI(ctx context.Context, opts rest.Opts, response any, state *api.Response) error {
	return f.pacer.Call(func() (bool, error) {
		res, err := f.client.CallJSON(ctx, &opts, nil, response)
		retry, err := shouldRetry(ctx, res, state, err)
		return opts.Method == http.MethodGet && retry, err
	})
}

func (f *Fs) callAPIWithForm(ctx context.Context, opts rest.Opts, form url.Values, response any, state *api.Response) error {
	opts.ContentType = "application/x-www-form-urlencoded; charset=utf-8"
	opts.Body = strings.NewReader(form.Encode())
	return f.callAPI(ctx, opts, response, state)
}

func shouldRetry(ctx context.Context, res *http.Response, state *api.Response, err error) (bool, error) {
	if fserrors.ContextError(ctx, &err) {
		return false, err
	}
	if err == nil && state != nil && !state.Success() {
		err = &apiError{response: *state}
		return strings.Contains(state.Message, "频繁") || strings.Contains(state.Message, "超时"), err
	}
	if res != nil && (res.StatusCode == 405 || res.StatusCode == 429) {
		return true, err
	}
	return fserrors.ShouldRetry(err) || fserrors.ShouldRetryHTTP(res, []int{408, 429, 500, 502, 503, 504}), err
}

type apiError struct{ response api.Response }

func (e *apiError) Error() string { return "115netdisk API error: " + e.response.ErrorDetails() }

func (c *client) uploadKey(ctx context.Context) (string, error) {
	c.keyMu.Lock()
	defer c.keyMu.Unlock()
	if c.userkey != "" {
		return c.userkey, nil
	}
	query := url.Values{"user_id": {strconv.FormatInt(c.userID, 10)}, "app_id": {"100"}}
	body, _, err := c.raw(ctx, &rest.Opts{Method: "GET", RootURL: "https://proapi.115.com", Path: "/ios/2.0/user/upload_key", Parameters: query})
	if err != nil {
		return "", err
	}
	var state api.Response
	if err = json.Unmarshal(body, &state); err != nil {
		return "", err
	}
	if !state.Success() {
		return "", &apiError{response: state}
	}
	var response struct {
		Data struct {
			Userkey string `json:"userkey"`
		} `json:"data"`
	}
	if err = json.Unmarshal(body, &response); err != nil {
		return "", err
	}
	if response.Data.Userkey == "" {
		return "", errors.New("upload key response is empty")
	}
	c.userkey = response.Data.Userkey
	return c.userkey, nil
}

var errUploadTokenExpired = errors.New("OSS upload credentials have expired")

func validateUploadToken(token *api.UploadTokenData, now time.Time) error {
	if token.AccessKeyID == "" || token.AccessKeySecret == "" || token.SecurityToken == "" {
		return errors.New("incomplete OSS credentials")
	}
	expiration, err := time.Parse(time.RFC3339Nano, token.Expiration)
	if err != nil {
		return fmt.Errorf("invalid OSS expiration: %w", err)
	}
	if !expiration.After(now.Add(time.Minute)) {
		return errUploadTokenExpired
	}
	if token.Endpoint == "" {
		token.Endpoint = "https://oss-cn-shenzhen.aliyuncs.com"
	}
	return nil
}

func (f *Fs) getValidUploadToken(ctx context.Context) (*api.UploadTokenData, error) {
	return f.validUploadToken(ctx, false)
}

func (f *Fs) validUploadToken(ctx context.Context, recovery bool) (*api.UploadTokenData, error) {
	for attempt := 0; attempt < 2; attempt++ {
		opts := rest.Opts{Method: "GET", RootURL: uploadAPI, Path: "/3.0/gettoken.php"}
		if recovery || attempt > 0 {
			opts.Method = "POST"
			opts.ContentType = "application/x-www-form-urlencoded; charset=utf-8"
			opts.Body = strings.NewReader(url.Values{"userid": {strconv.FormatInt(f.client.userID, 10)}}.Encode())
		}
		body, _, err := f.client.raw(ctx, &opts)
		if err != nil {
			return nil, err
		}
		var response struct {
			api.UploadTokenData
			StatusCode api.String `json:"StatusCode"`
		}
		if err = json.Unmarshal(body, &response); err != nil {
			return nil, err
		}
		if response.StatusCode != "200" {
			return nil, errors.New("STS request did not return StatusCode 200")
		}
		token := response.UploadTokenData
		if err = validateUploadToken(&token, time.Now()); err == nil {
			return &token, nil
		} else if !errors.Is(err, errUploadTokenExpired) {
			return nil, err
		}
	}
	return nil, errUploadTokenExpired
}
