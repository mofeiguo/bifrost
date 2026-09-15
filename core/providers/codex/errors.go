package codex

import (
	"fmt"
	"strings"

	"github.com/bytedance/sonic"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

type codexErrorBody struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
	Message   string `json:"message"`
	Detail    string `json:"detail"`
	ErrorType string `json:"error_type"`
}

func parseCodexError(resp *fasthttp.Response) *schemas.BifrostError {
	var bifrostErr schemas.BifrostError
	_ = providerUtils.HandleProviderAPIError(resp, &bifrostErr)
	if bifrostErr.Error == nil {
		bifrostErr.Error = &schemas.ErrorField{}
	}

	body := resp.Body()
	if len(body) > 0 {
		var parsed codexErrorBody
		if err := sonic.Unmarshal(body, &parsed); err == nil {
			switch {
			case parsed.Error.Message != "":
				bifrostErr.Error.Message = parsed.Error.Message
			case parsed.Message != "":
				bifrostErr.Error.Message = parsed.Message
			case parsed.Detail != "":
				bifrostErr.Error.Message = parsed.Detail
			}
			if parsed.Error.Type != "" {
				bifrostErr.Error.Type = &parsed.Error.Type
			} else if parsed.ErrorType != "" {
				bifrostErr.Error.Type = &parsed.ErrorType
			}
		}
	}

	switch resp.StatusCode() {
	case fasthttp.StatusUnauthorized:
		bifrostErr.AllowFallbacks = schemas.Ptr(false)
		bifrostErr.Error.Message = "codex: chatgpt oauth token was rejected (401). " +
			"Refresh the subscription credential. Upstream said: " + upstreamDetail(bifrostErr.Error.Message)
	case fasthttp.StatusForbidden:
		bifrostErr.AllowFallbacks = schemas.Ptr(false)
		bifrostErr.Error.Message = "codex: chatgpt refused the request (403). " +
			"The Plus/Pro subscription may lack Codex access. Upstream said: " + upstreamDetail(bifrostErr.Error.Message)
	}

	if strings.TrimSpace(bifrostErr.Error.Message) == "" {
		if bifrostErr.StatusCode != nil {
			bifrostErr.Error.Message = fmt.Sprintf("codex: provider api error (status %d)", *bifrostErr.StatusCode)
		} else {
			bifrostErr.Error.Message = "codex: provider api error"
		}
	}
	return &bifrostErr
}

func upstreamDetail(message string) string {
	if strings.TrimSpace(message) == "" {
		return "(no detail)"
	}
	return message
}
