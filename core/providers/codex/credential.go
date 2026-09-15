package codex

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/bytedance/sonic"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	schemas "github.com/maximhq/bifrost/core/schemas"
)

// oauthJSON is the ChatGPT / Codex CLI credential stored in Key.Value.
//
// Two shapes are accepted:
//
//  1. new-api / gateway flat JSON:
//     {"access_token","refresh_token","account_id","expired","id_token",...}
//  2. ~/.codex/auth.json:
//     {"auth_mode":"chatgpt","tokens":{"access_token","refresh_token","account_id","id_token"},...}
type oauthJSON struct {
	IDToken      string `json:"id_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	LastRefresh  string `json:"last_refresh,omitempty"`
	Email        string `json:"email,omitempty"`
	Type         string `json:"type,omitempty"`
	Expired      string `json:"expired,omitempty"`
	AuthMode     string `json:"auth_mode,omitempty"`
	Tokens       *struct {
		IDToken      string `json:"id_token,omitempty"`
		AccessToken  string `json:"access_token,omitempty"`
		RefreshToken string `json:"refresh_token,omitempty"`
		AccountID    string `json:"account_id,omitempty"`
	} `json:"tokens,omitempty"`
}

// ValidateKey checks a Codex key at setup/save time. Environment and vault
// references are accepted without parsing; a resolved literal must be ChatGPT
// OAuth JSON with an access_token or refresh_token.
func ValidateKey(key schemas.Key) error {
	if key.Value.IsFromSecret() {
		if !key.Value.IsSet() {
			return fmt.Errorf("codex key value is required (chatgpt oauth json)")
		}
		if raw := strings.TrimSpace(key.Value.GetValue()); raw != "" {
			return ValidateKeyValue(raw)
		}
		return nil
	}
	return ValidateKeyValue(key.Value.GetValue())
}

// ValidateKeyValue checks that raw is ChatGPT OAuth JSON with an access_token
// or refresh_token.
func ValidateKeyValue(raw string) error {
	_, bErr := parseOAuthJSON(raw)
	if bErr == nil {
		return nil
	}
	if bErr.Error != nil && bErr.Error.Message != "" {
		return fmt.Errorf("%s", bErr.Error.Message)
	}
	return fmt.Errorf("codex key value must be chatgpt oauth json")
}

func parseOAuthJSON(raw string) (*oauthJSON, *schemas.BifrostError) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, configurationError("codex: key value is empty")
	}
	var parsed oauthJSON
	if err := sonic.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil, configurationError("codex: key value must be chatgpt oauth json")
	}
	if parsed.Tokens != nil {
		if parsed.AccessToken == "" {
			parsed.AccessToken = parsed.Tokens.AccessToken
		}
		if parsed.RefreshToken == "" {
			parsed.RefreshToken = parsed.Tokens.RefreshToken
		}
		if parsed.AccountID == "" {
			parsed.AccountID = parsed.Tokens.AccountID
		}
		if parsed.IDToken == "" {
			parsed.IDToken = parsed.Tokens.IDToken
		}
	}
	parsed.AccessToken = strings.TrimSpace(parsed.AccessToken)
	parsed.RefreshToken = strings.TrimSpace(parsed.RefreshToken)
	parsed.AccountID = strings.TrimSpace(parsed.AccountID)
	parsed.IDToken = strings.TrimSpace(parsed.IDToken)
	if parsed.AccessToken == "" && parsed.RefreshToken == "" {
		return nil, configurationError("codex: oauth json needs access_token or refresh_token")
	}
	if parsed.Type == "" {
		parsed.Type = "codex"
	}
	return &parsed, nil
}

func (o *oauthJSON) expiresAt() time.Time {
	if o == nil {
		return time.Time{}
	}
	if ts := strings.TrimSpace(o.Expired); ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t
		}
	}
	if exp, ok := jwtExpiry(o.AccessToken); ok {
		return exp
	}
	return time.Time{}
}

func (o *oauthJSON) accessTokenFresh(now time.Time) bool {
	if o == nil || o.AccessToken == "" {
		return false
	}
	exp := o.expiresAt()
	if exp.IsZero() {
		return true
	}
	return now.Add(tokenRefreshMargin).Before(exp)
}

func (o *oauthJSON) marshal() (string, error) {
	if o.Tokens != nil {
		o.Tokens.AccessToken = o.AccessToken
		o.Tokens.RefreshToken = o.RefreshToken
		o.Tokens.AccountID = o.AccountID
		o.Tokens.IDToken = o.IDToken
	}
	b, err := json.Marshal(o)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func jwtExpiry(token string) (time.Time, bool) {
	claims, ok := decodeJWTClaims(token)
	if !ok {
		return time.Time{}, false
	}
	raw, ok := claims["exp"]
	if !ok {
		return time.Time{}, false
	}
	var exp int64
	switch v := raw.(type) {
	case float64:
		exp = int64(v)
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return time.Time{}, false
		}
		exp = n
	default:
		return time.Time{}, false
	}
	if exp <= 0 {
		return time.Time{}, false
	}
	return time.Unix(exp, 0), true
}

func extractAccountIDFromJWT(token string) (string, bool) {
	claims, ok := decodeJWTClaims(token)
	if !ok {
		return "", false
	}
	raw, ok := claims[codexJWTClaimPath]
	if !ok {
		return "", false
	}
	obj, ok := raw.(map[string]any)
	if !ok {
		return "", false
	}
	v, ok := obj["chatgpt_account_id"]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	s = strings.TrimSpace(s)
	return s, s != ""
}

func decodeJWTClaims(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if err := sonic.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	return claims, true
}

func configurationError(message string) *schemas.BifrostError {
	bErr := providerUtils.NewConfigurationError(message)
	bErr.AllowFallbacks = schemas.Ptr(false)
	return bErr
}
