package codex

import (
	"net/url"
	"strings"

	"github.com/bytedance/sonic"
	providerUtils "github.com/maximhq/bifrost/core/providers/utils"
	schemas "github.com/maximhq/bifrost/core/schemas"
	"github.com/valyala/fasthttp"
)

var fallbackCodexModels = []string{
	"gpt-5.3-codex",
	"gpt-5.2-codex",
	"gpt-5.1-codex",
	"gpt-5.1-codex-max",
	"gpt-5.1-codex-mini",
	"gpt-5-codex",
	"codex-mini-latest",
}

func fetchCodexModels(ctx *schemas.BifrostContext, client *fasthttp.Client, creds *codexCredentials) ([]string, *schemas.BifrostError) {
	modelsURL, err := url.Parse(creds.BaseURL + "/models")
	if err != nil {
		return nil, configurationError("codex: invalid models url")
	}
	query := modelsURL.Query()
	query.Set("client_version", codexClientVersion)
	modelsURL.RawQuery = query.Encode()

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(modelsURL.String())
	req.Header.SetMethod(fasthttp.MethodGet)
	for k, v := range buildAuthHeaders(creds.Token, creds.AccountID) {
		req.Header.Set(k, v)
	}
	req.Header.Set("Accept", "application/json")

	if err := client.DoTimeout(req, resp, exchangeTimeout); err != nil {
		return nil, providerUtils.NewProviderAPIError("codex: could not list models", err, 0, nil, nil)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return nil, parseCodexError(resp)
	}

	var result struct {
		Models []struct {
			Slug string `json:"slug"`
			ID   string `json:"id"`
		} `json:"models"`
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := sonic.Unmarshal(resp.Body(), &result); err != nil {
		return nil, providerUtils.NewProviderAPIError("codex: could not parse models response", err, resp.StatusCode(), nil, nil)
	}

	seen := make(map[string]struct{})
	models := make([]string, 0, len(result.Models)+len(result.Data))
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		models = append(models, id)
	}
	for _, item := range result.Models {
		if item.Slug != "" {
			add(item.Slug)
		} else {
			add(item.ID)
		}
	}
	for _, item := range result.Data {
		add(item.ID)
	}
	if len(models) == 0 {
		return append([]string(nil), fallbackCodexModels...), nil
	}
	return models, nil
}

func listModelsResponse(models []string) *schemas.BifrostListModelsResponse {
	data := make([]schemas.Model, 0, len(models))
	for _, id := range models {
		name := id
		data = append(data, schemas.Model{ID: id, Name: &name})
	}
	return &schemas.BifrostListModelsResponse{Data: data}
}
