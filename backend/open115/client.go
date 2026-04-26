package open115

import (
	"context"
	"fmt"
	"net/http"

	"golang.org/x/time/rate"

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
	if err = c.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	token, err := c.ts.Token()
	if err != nil {
		return nil, err
	}
	opts.ExtraHeaders["Authorization"] = fmt.Sprintf("Bearer %s", token)
	return c.Client.CallJSON(ctx, opts, request, response)
}
