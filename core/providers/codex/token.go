package codex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bytedance/sonic"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

const (
	tokenRefreshMargin   = 60 * time.Second
	maxExchangeBodyBytes = 64 * 1024
	exchangeTimeout      = 20 * time.Second
)

type codexCredentials struct {
	Token     string
	AccountID string
	BaseURL   string
}

type tokenSnapshot struct {
	creds     *codexCredentials
	oauth     *oauthJSON
	refreshAt time.Time
}

type tokenEntry struct {
	mu    sync.Mutex
	value atomic.Pointer[tokenSnapshot]
}

var tokenPool sync.Map

type KeyPersister func(ctx context.Context, key schemas.Key) error

var keyPersister atomic.Pointer[KeyPersister]

// SetKeyPersister registers a callback used after OAuth refresh so the rotated
// refresh_token is written back to the configured key store.
func SetKeyPersister(fn KeyPersister) {
	if fn == nil {
		keyPersister.Store(nil)
		return
	}
	keyPersister.Store(&fn)
}

func resolveCredentials(
	ctx *schemas.BifrostContext,
	key schemas.Key,
	client *fasthttp.Client,
	configuredBaseURL string,
	logger schemas.Logger,
) (*codexCredentials, *schemas.BifrostError) {
	oauth, bErr := parseOAuthJSON(key.Value.GetValue())
	if bErr != nil {
		return nil, bErr
	}

	baseURL := strings.TrimRight(strings.TrimSpace(configuredBaseURL), "/")
	if baseURL == "" {
		baseURL = defaultCodexBaseURL
	}

	cacheKey := credentialCacheKey(oauth)
	entry := loadOrCreateEntry(cacheKey)
	now := time.Now()
	if snap := entry.value.Load(); snap != nil && now.Before(snap.refreshAt) && snap.creds != nil {
		creds := *snap.creds
		creds.BaseURL = baseURL
		return &creds, nil
	}

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now = time.Now()
	if snap := entry.value.Load(); snap != nil && now.Before(snap.refreshAt) && snap.creds != nil {
		creds := *snap.creds
		creds.BaseURL = baseURL
		return &creds, nil
	}

	if oauth.accessTokenFresh(now) {
		if oauth.AccountID == "" {
			if accountID, ok := extractAccountIDFromJWT(oauth.AccessToken); ok {
				oauth.AccountID = accountID
			}
		}
		if oauth.AccountID == "" {
			return nil, configurationError("codex: account_id is required")
		}
		creds := &codexCredentials{Token: oauth.AccessToken, AccountID: oauth.AccountID, BaseURL: baseURL}
		entry.value.Store(&tokenSnapshot{creds: creds, oauth: oauth, refreshAt: refreshAtFor(oauth, now)})
		return creds, nil
	}

	if oauth.RefreshToken == "" {
		return nil, configurationError("codex: access_token is expired and refresh_token is missing")
	}

	parent := context.Background()
	if ctx != nil {
		parent = context.WithoutCancel(ctx)
	}
	refreshCtx, cancel := context.WithTimeout(parent, exchangeTimeout)
	defer cancel()

	refreshed, bErr := refreshOAuthToken(refreshCtx, client, oauth.RefreshToken)
	if bErr != nil {
		return nil, bErr
	}

	oauth.AccessToken = refreshed.AccessToken
	oauth.RefreshToken = refreshed.RefreshToken
	oauth.Expired = refreshed.ExpiresAt.Format(time.RFC3339)
	oauth.LastRefresh = time.Now().Format(time.RFC3339)
	if oauth.AccountID == "" {
		if accountID, ok := extractAccountIDFromJWT(oauth.AccessToken); ok {
			oauth.AccountID = accountID
		}
	}
	if oauth.AccountID == "" {
		return nil, configurationError("codex: account_id is required after refresh")
	}

	encoded, err := oauth.marshal()
	if err != nil {
		return nil, configurationError("codex: could not encode refreshed oauth json: " + err.Error())
	}
	updated := key
	updated.Value = *schemas.NewSecretVar(encoded)
	if persist := keyPersister.Load(); persist != nil && key.ID != "" {
		if err := (*persist)(context.WithoutCancel(parent), updated); err != nil && logger != nil {
			logger.Warn("[codex] failed to persist rotated oauth credential for key %s: %v", key.ID, err)
		}
	}

	newCacheKey := credentialCacheKey(oauth)
	if newCacheKey != cacheKey {
		tokenPool.Store(newCacheKey, entry)
	}

	creds := &codexCredentials{Token: oauth.AccessToken, AccountID: oauth.AccountID, BaseURL: baseURL}
	entry.value.Store(&tokenSnapshot{creds: creds, oauth: oauth, refreshAt: refreshAtFor(oauth, time.Now())})
	return creds, nil
}

func refreshAtFor(oauth *oauthJSON, now time.Time) time.Time {
	exp := oauth.expiresAt()
	if exp.IsZero() {
		return now.Add(10 * time.Minute)
	}
	at := exp.Add(-tokenRefreshMargin)
	if !at.After(now) {
		return now.Add(time.Second)
	}
	return at
}

func loadOrCreateEntry(cacheKey string) *tokenEntry {
	if existing, ok := tokenPool.Load(cacheKey); ok {
		return existing.(*tokenEntry)
	}
	actual, _ := tokenPool.LoadOrStore(cacheKey, &tokenEntry{})
	return actual.(*tokenEntry)
}

func credentialCacheKey(oauth *oauthJSON) string {
	h := sha256.Sum256([]byte(oauth.RefreshToken + "\n" + oauth.AccessToken + "\n" + oauth.AccountID))
	return hex.EncodeToString(h[:])
}

type oauthRefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func refreshOAuthToken(ctx context.Context, client *fasthttp.Client, refreshToken string) (*oauthRefreshResult, *schemas.BifrostError) {
	rt := strings.TrimSpace(refreshToken)
	if rt == "" {
		return nil, configurationError("codex: empty refresh_token")
	}

	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", rt)
	form.Set("client_id", codexOAuthClientID)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(codexOAuthTokenURL)
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBodyString(form.Encode())

	var err error
	if deadline, ok := ctx.Deadline(); ok {
		err = client.DoDeadline(req, resp, deadline)
	} else {
		err = client.DoTimeout(req, resp, exchangeTimeout)
	}
	if err != nil {
		return nil, providerUtils.NewProviderAPIError("codex: could not reach chatgpt oauth token endpoint", err, 0, nil, nil)
	}

	if status := resp.StatusCode(); status < http.StatusOK || status >= http.StatusMultipleChoices {
		bErr := parseCodexError(resp)
		bErr.AllowFallbacks = schemas.Ptr(false)
		if bErr.Error != nil && bErr.Error.Message != "" {
			bErr.Error.Message = "codex: oauth refresh failed: " + bErr.Error.Message
		}
		return nil, bErr
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := sonic.Unmarshal(resp.Body(), &payload); err != nil {
		return nil, providerUtils.NewProviderAPIError("codex: could not parse oauth refresh response", err, resp.StatusCode(), nil, nil)
	}
	if strings.TrimSpace(payload.AccessToken) == "" || payload.ExpiresIn <= 0 {
		return nil, configurationError("codex: oauth refresh response missing access_token or expires_in")
	}
	if strings.TrimSpace(payload.RefreshToken) == "" {
		payload.RefreshToken = rt
	}

	return &oauthRefreshResult{
		AccessToken:  strings.TrimSpace(payload.AccessToken),
		RefreshToken: strings.TrimSpace(payload.RefreshToken),
		ExpiresAt:    time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second),
	}, nil
}
