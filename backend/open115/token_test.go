package open115

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/rclone/rclone/backend/open115/api"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCodeVerifier(t *testing.T) {
	verifier, err := generateCodeVerifier()
	require.NoError(t, err)
	assert.Len(t, verifier, 64)
	assert.NotContains(t, verifier, "=")
}

func TestAuthRequiresAppID(t *testing.T) {
	err := (&TokenSource{}).Auth("")
	assert.EqualError(t, err, "Open115 application ID is required; create one at https://open.115.com/")
}

func TestTokenSourceReReadToken(t *testing.T) {
	now := time.Now()
	stored := api.Token{AccessToken: "new access", RefreshToken: "new refresh", ExpiresAt: now.Add(time.Hour)}
	storedJSON, err := json.Marshal(stored)
	require.NoError(t, err)
	m := configmap.Simple{config.ConfigToken: string(storedJSON)}
	ts := &TokenSource{
		token:  &api.Token{AccessToken: "old access", RefreshToken: "old refresh", ExpiresAt: now.Add(time.Hour)},
		expiry: now.Add(time.Hour),
		m:      m,
	}

	changed, err := ts.reReadToken()
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, stored.AccessToken, ts.token.AccessToken)
	assert.Equal(t, stored.RefreshToken, ts.token.RefreshToken)
	assert.True(t, stored.ExpiresAt.Equal(ts.expiry))
}
