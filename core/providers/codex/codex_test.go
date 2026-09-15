package codex_test

import (
	"os"
	"strings"
	"testing"

	"github.com/maximhq/bifrost/core/internal/llmtests"
	"github.com/maximhq/bifrost/core/schemas"
)

func TestCodex(t *testing.T) {
	t.Parallel()
	if strings.TrimSpace(os.Getenv("CODEX_OAUTH_JSON")) == "" {
		t.Skip("Skipping Codex tests because CODEX_OAUTH_JSON is not set")
	}

	client, ctx, cancel, err := llmtests.SetupTest()
	if err != nil {
		t.Fatalf("Error initializing test setup: %v", err)
	}
	defer cancel()
	defer client.Shutdown()

	testConfig := llmtests.ComprehensiveTestConfig{
		Provider:  schemas.Codex,
		ChatModel: "gpt-5.3-codex",
		TextModel: "",
		Scenarios: llmtests.TestScenarios{
			TextCompletion:             false,
			TextCompletionStream:       false,
			SimpleChat:                 true,
			CompletionStream:           true,
			MultiTurnConversation:      true,
			ToolCalls:                  true,
			ToolCallsStreaming:         true,
			MultipleToolCalls:          false,
			MultipleToolCallsStreaming: false,
			End2EndToolCalling:         false,
			AutomaticFunctionCall:      false,
			ImageURL:                   false,
			ImageBase64:                false,
			MultipleImages:             false,
			FileBase64:                 false,
			FileURL:                    false,
			CompleteEnd2End:            false,
			Embedding:                  false,
			ListModels:                 true,
		},
	}
	t.Run("CodexTests", func(t *testing.T) {
		llmtests.RunAllComprehensiveTests(t, client, ctx, testConfig)
	})
}
