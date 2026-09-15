package codex

const (
	defaultCodexBaseURL = "https://chatgpt.com/backend-api/codex"
	codexOAuthClientID  = "app_EMoamEEZ73f0CkXaXp7hrann"
	codexJWTClaimPath   = "https://api.openai.com/auth"
	codexOriginator     = "codex_cli_rs"
	codexClientVersion  = "0.147.0"
)

var codexOAuthTokenURL = "https://auth.openai.com/oauth/token"

func buildAuthHeaders(accessToken, accountID string) map[string]string {
	headers := map[string]string{
		"Authorization":      "Bearer " + accessToken,
		"Originator":         codexOriginator,
		"User-Agent":         "codex-cli/" + codexClientVersion,
		"OpenAI-Beta":        "responses=experimental",
		"ChatGPT-Account-Id": accountID,
		"chatgpt-account-id": accountID,
	}
	return headers
}
