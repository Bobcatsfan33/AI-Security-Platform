// Package proxy is the LLM reverse-proxy core. Detects the upstream
// provider's wire format on the inbound request, extracts the user-
// visible prompt for policy inspection, forwards to the real provider,
// and emits telemetry on every call.
//
// Streaming response interception is deferred to Sprint 7 follow-on —
// for now non-streaming responses pass through; streaming responses
// are forwarded without inspection (the policy decision is made on the
// inbound prompt alone).
package proxy

import (
	"encoding/json"
	"errors"
	"strings"
)

// Provider identifies the upstream LLM API format.
type Provider string

const (
	ProviderOpenAI    Provider = "openai"
	ProviderAnthropic Provider = "anthropic"
	ProviderAzure     Provider = "azure_openai"
	ProviderBedrock   Provider = "bedrock"
	ProviderUnknown   Provider = "unknown"
)

// ErrNoPromptExtracted is returned when we recognized the provider
// format but couldn't pull a prompt out of the body — usually a
// malformed request the upstream will reject anyway.
var ErrNoPromptExtracted = errors.New("no prompt could be extracted from request body")

// ExtractedPrompt is what the policy pipeline inspects on the inbound
// hot path. We aggregate all user-role messages into one string so a
// regex rule against "ignore previous instructions" matches even if
// the attacker splits the payload across two messages.
type ExtractedPrompt struct {
	Provider     Provider
	SystemPrompt string
	UserText     string
	ToolName     string         // populated when the model is being asked to call a tool
	ToolArgs     map[string]any // raw args (NOT executed; only used by the tool-call firewall)
}

// DetectProvider classifies a request by URL path. Cheap; called per-
// request on the hot path.
func DetectProvider(path string) Provider {
	switch {
	case strings.Contains(path, "/openai/deployments/"):
		// Azure shape: /openai/deployments/<name>/chat/completions
		return ProviderAzure
	case strings.HasSuffix(path, "/v1/messages"):
		return ProviderAnthropic
	case strings.HasSuffix(path, "/v1/chat/completions"):
		return ProviderOpenAI
	case strings.Contains(path, "/model/") && strings.Contains(path, "/invoke"):
		// Bedrock: /model/<id>/invoke
		return ProviderBedrock
	default:
		return ProviderUnknown
	}
}

// Extract parses the request body for the given provider. Returns
// ErrNoPromptExtracted when the body is malformed or empty.
func Extract(provider Provider, body []byte) (ExtractedPrompt, error) {
	switch provider {
	case ProviderOpenAI, ProviderAzure:
		return extractOpenAI(provider, body)
	case ProviderAnthropic:
		return extractAnthropic(body)
	case ProviderBedrock:
		// Bedrock InvokeModel wraps a provider-specific body. Without
		// the model ID from the URL we can't disambiguate; the proxy
		// passes the body to its first guess and falls back to no-op
		// inspection. Sprint 7 follow-on.
		return ExtractedPrompt{Provider: provider}, ErrNoPromptExtracted
	default:
		return ExtractedPrompt{Provider: ProviderUnknown}, ErrNoPromptExtracted
	}
}

// ─────────────────────────────────────────── OpenAI / Azure

type openaiBody struct {
	Messages []struct {
		Role    string         `json:"role"`
		Content any            `json:"content"`
		Name    string         `json:"name,omitempty"`
	} `json:"messages"`
	Tools []struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	} `json:"tools,omitempty"`
}

func extractOpenAI(provider Provider, body []byte) (ExtractedPrompt, error) {
	var parsed openaiBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ExtractedPrompt{Provider: provider}, ErrNoPromptExtracted
	}
	if len(parsed.Messages) == 0 {
		return ExtractedPrompt{Provider: provider}, ErrNoPromptExtracted
	}

	var system, user strings.Builder
	for _, m := range parsed.Messages {
		text := stringifyContent(m.Content)
		switch m.Role {
		case "system":
			if system.Len() > 0 {
				system.WriteString("\n")
			}
			system.WriteString(text)
		case "user", "tool":
			if user.Len() > 0 {
				user.WriteString("\n")
			}
			user.WriteString(text)
		}
	}
	return ExtractedPrompt{
		Provider:     provider,
		SystemPrompt: system.String(),
		UserText:     user.String(),
	}, nil
}

// ─────────────────────────────────────────── Anthropic

type anthropicBody struct {
	System   any `json:"system"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"`
	} `json:"messages"`
}

func extractAnthropic(body []byte) (ExtractedPrompt, error) {
	var parsed anthropicBody
	if err := json.Unmarshal(body, &parsed); err != nil {
		return ExtractedPrompt{Provider: ProviderAnthropic}, ErrNoPromptExtracted
	}
	if len(parsed.Messages) == 0 {
		return ExtractedPrompt{Provider: ProviderAnthropic}, ErrNoPromptExtracted
	}
	system := stringifyContent(parsed.System)
	var user strings.Builder
	for _, m := range parsed.Messages {
		if m.Role != "user" {
			continue
		}
		text := stringifyContent(m.Content)
		if user.Len() > 0 {
			user.WriteString("\n")
		}
		user.WriteString(text)
	}
	return ExtractedPrompt{
		Provider:     ProviderAnthropic,
		SystemPrompt: system,
		UserText:     user.String(),
	}, nil
}

// stringifyContent collapses the various Content shapes used by OpenAI
// (string OR [{"type":"text","text":"..."}, ...]) and Anthropic (same
// pattern) into a single string for policy inspection. Non-text blocks
// (images, audio) are ignored — Stage 1 only inspects text.
func stringifyContent(v any) string {
	switch c := v.(type) {
	case nil:
		return ""
	case string:
		return c
	case []any:
		var b strings.Builder
		for _, item := range c {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			t, _ := block["type"].(string)
			if t == "text" || t == "" {
				if s, ok := block["text"].(string); ok {
					if b.Len() > 0 {
						b.WriteString("\n")
					}
					b.WriteString(s)
				}
			}
		}
		return b.String()
	default:
		return ""
	}
}
