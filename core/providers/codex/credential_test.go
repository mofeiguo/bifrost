package codex

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/stretchr/testify/require"
)

func TestParseOAuthJSON_FlatAndNested(t *testing.T) {
	t.Parallel()

	flat, err := parseOAuthJSON(`{"access_token":"at","refresh_token":"rt","account_id":"acc"}`)
	require.Nil(t, err)
	require.Equal(t, "at", flat.AccessToken)
	require.Equal(t, "rt", flat.RefreshToken)
	require.Equal(t, "acc", flat.AccountID)

	nested, err := parseOAuthJSON(`{"auth_mode":"chatgpt","tokens":{"access_token":"at2","refresh_token":"rt2","account_id":"acc2"}}`)
	require.Nil(t, err)
	require.Equal(t, "at2", nested.AccessToken)
	require.Equal(t, "rt2", nested.RefreshToken)
	require.Equal(t, "acc2", nested.AccountID)
}

func TestParseOAuthJSON_RejectsEmpty(t *testing.T) {
	t.Parallel()
	_, err := parseOAuthJSON(`{"type":"codex"}`)
	require.NotNil(t, err)
	require.Contains(t, err.Error.Message, "access_token or refresh_token")
}

func TestValidateKeyValue(t *testing.T) {
	t.Parallel()
	require.NoError(t, ValidateKeyValue(`{"refresh_token":"rt"}`))
	require.Error(t, ValidateKeyValue(""))
	require.Error(t, ValidateKeyValue(`not-json`))
	require.Error(t, ValidateKeyValue(`{"type":"codex"}`))
}

func TestValidateKeyAcceptsEnvRef(t *testing.T) {
	t.Parallel()
	key := schemas.Key{Value: *schemas.NewSecretVar("env.CODEX_OAUTH_JSON_MISSING_XYZ")}
	require.NoError(t, ValidateKey(key))
}

func TestAccessTokenFreshUsesExpiredAndJWT(t *testing.T) {
	t.Parallel()

	future := time.Now().Add(2 * time.Hour).Format(time.RFC3339)
	oauth := &oauthJSON{AccessToken: "tok", Expired: future}
	require.True(t, oauth.accessTokenFresh(time.Now()))

	past := time.Now().Add(-time.Minute).Format(time.RFC3339)
	oauth.Expired = past
	require.False(t, oauth.accessTokenFresh(time.Now()))
}

func TestExtractAccountIDFromJWT(t *testing.T) {
	t.Parallel()

	payload := map[string]any{
		codexJWTClaimPath: map[string]any{"chatgpt_account_id": "acct-1"},
		"exp":             float64(time.Now().Add(time.Hour).Unix()),
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	token := "aaa." + base64.RawURLEncoding.EncodeToString(raw) + ".sig"

	id, ok := extractAccountIDFromJWT(token)
	require.True(t, ok)
	require.Equal(t, "acct-1", id)

	exp, ok := jwtExpiry(token)
	require.True(t, ok)
	require.True(t, exp.After(time.Now()))
}
