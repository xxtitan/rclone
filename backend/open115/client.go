package open115

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"golang.org/x/time/rate"

	"github.com/rclone/rclone/backend/open115/api"
	"github.com/rclone/rclone/lib/rest"
)

const (
	baseAPI                     = "https://proapi.115.com"
	passportAPI                 = "https://passportapi.115.com"
	qrcodeAPI                   = "https://qrcodeapi.115.com"
	defaultAPIRequestsPerSecond = 2    // Default requests per second for API calls.
	defaultListPageSize         = 1000 // Default page size for listing items.
	open115InternalErrorCode    = 1001 // Open115 internal error code.
	open115AccessLimitCode      = 770004
	open115OperationPendingCode = 990019
)

// retryHTTPStatusCodes are HTTP status codes that we should retry on.
var retryHTTPStatusCodes = []int{
	429, // Too Many Requests.
	500, // Internal Server Error
	502, // Bad Gateway
	503, // Service Unavailable
	504, // Gateway Timeout
	509, // Bandwidth Limit Exceeded
}

// client is a wrapper around rest.Client to handle 115 Cloud Drive API calls.
type client struct {
	*rest.Client
	ts      *TokenSource
	limiter *rate.Limiter
}

// newClient creates a new API client.
func newClient(rc *rest.Client, ts *TokenSource) *client {
	return &client{
		Client:  rc,
		ts:      ts,
		limiter: rate.NewLimiter(rate.Limit(defaultAPIRequestsPerSecond), defaultAPIRequestsPerSecond),
	}
}

func (c *client) CallJSON(ctx context.Context, opts *rest.Opts, request any, response any) (resp *http.Response, err error) {
	if c.ts == nil {
		return c.Client.CallJSON(ctx, opts, request, response)
	}

	// use access token from TokenSource
	if opts.ExtraHeaders == nil {
		opts.ExtraHeaders = make(map[string]string)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err = c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		token, err := c.ts.Token()
		if err != nil {
			return nil, err
		}
		opts.ExtraHeaders["Authorization"] = fmt.Sprintf("Bearer %s", token)
		resp, err = c.Client.CallJSON(ctx, opts, request, response)
		if err != nil || !hasAuthError(response) {
			return resp, err
		}
		if attempt != 0 {
			return resp, err
		}
		if seeker, ok := opts.Body.(io.Seeker); ok {
			if _, err = seeker.Seek(0, io.SeekStart); err != nil {
				return resp, fmt.Errorf("failed to rewind authenticated request: %w", err)
			}
		} else if opts.Body != nil {
			return resp, fmt.Errorf("can't retry authenticated request with a non-replayable body")
		}
		if _, err = c.ts.Refresh(); err != nil {
			return resp, err
		}
		resetAPIResponse(response)
	}
	return resp, err
}

func hasAuthError(response any) bool {
	responseWithState, ok := response.(interface{ GetResponse() *api.Response })
	if !ok {
		return false
	}
	responseState := responseWithState.GetResponse()
	return isAuthCode(responseState.Code) || isAuthCode(responseState.Errno)
}

func isAuthCode(code int) bool {
	return code == 99 || strings.HasPrefix(strconv.Itoa(code), "401")
}
