package codex

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

var _ schemas.Provider = (*codexProvider)(nil)

func TestRefreshOAuthTokenPersistsRotatedRefresh(t *testing.T) {
	var persisted atomic.Value
	SetKeyPersister(func(_ context.Context, key schemas.Key) error {
		persisted.Store(key.Value.GetValue())
		return nil
	})
	t.Cleanup(func() { SetKeyPersister(nil) })

	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		require.Contains(t, string(body), "grant_type=refresh_token")
		require.Contains(t, string(body), "refresh_token=old-rt")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"new-at","refresh_token":"new-rt","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)

	origURL := codexOAuthTokenURL
	codexOAuthTokenURL = srv.URL
	t.Cleanup(func() { codexOAuthTokenURL = origURL })

	client := &fasthttp.Client{
		TLSConfig: srv.TLS,
	}
	// httptest uses a self-signed cert; skip verify for this unit test.
	client.TLSConfig.InsecureSkipVerify = true

	expired := time.Now().Add(-time.Minute).Format(time.RFC3339)
	key := schemas.Key{
		ID:    "key-1",
		Value: *schemas.NewSecretVar(`{"access_token":"old-at","refresh_token":"old-rt","account_id":"acc","expired":"` + expired + `"}`),
	}

	creds, bErr := resolveCredentials(nil, key, client, "", nil)
	require.Nil(t, bErr)
	require.Equal(t, "new-at", creds.Token)
	require.Equal(t, "acc", creds.AccountID)
	require.Equal(t, int32(1), hits.Load())

	raw, ok := persisted.Load().(string)
	require.True(t, ok)
	oauth, err := parseOAuthJSON(raw)
	require.Nil(t, err)
	require.Equal(t, "new-rt", oauth.RefreshToken)
	require.Equal(t, "new-at", oauth.AccessToken)
}

func TestResolveCredentialsReusesCachedToken(t *testing.T) {
	SetKeyPersister(nil)
	future := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	key := schemas.Key{
		ID:    "key-cache",
		Value: *schemas.NewSecretVar(`{"access_token":"live-at","refresh_token":"rt","account_id":"acc","expired":"` + future + `"}`),
	}
	creds, bErr := resolveCredentials(nil, key, &fasthttp.Client{}, "", nil)
	require.Nil(t, bErr)
	require.Equal(t, "live-at", creds.Token)
	require.Equal(t, defaultCodexBaseURL, creds.BaseURL)
}

func TestNewCodexProviderKey(t *testing.T) {
	p, err := NewCodexProvider(&schemas.ProviderConfig{}, nil)
	require.NoError(t, err)
	require.Equal(t, schemas.Codex, p.GetProviderKey())
	require.Equal(t, defaultCodexBaseURL, p.networkConfig.BaseURL)
}
