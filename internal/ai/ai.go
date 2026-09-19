package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"secdoctor/internal/scan"
)

type chatRequest struct {
	Model    string    `json:"model"`
	Messages []message `json:"messages"`
	Stream   bool      `json:"stream"`
}
type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type chatResponse struct {
	Choices []struct {
		Message message `json:"message"`
	} `json:"choices"`
	Message  message `json:"message"`
	Response string  `json:"response"`
}

func Explain(ctx context.Context, result scan.Result) (string, string, error) {
	safe := struct {
		Files    int            `json:"files_scanned"`
		Findings []scan.Finding `json:"findings"`
	}{Files: result.Files, Findings: result.Findings}
	for i := range safe.Findings {
		safe.Findings[i].Evidence = ""
	}
	payload, _ := json.MarshalIndent(safe, "", "  ")

	prompt := `You are a defensive application-security assistant.
Analyze only the supplied scanner findings. Do not invent vulnerabilities.
Separate observed facts from interpretation.
Prioritize the findings and give concise remediation steps.
Never provide instructions for attacking third-party systems.

Scanner findings:
` + string(payload)

	if url := os.Getenv("SECDOCTOR_AI_URL"); url != "" {
		model := getenv("SECDOCTOR_AI_MODEL", "default")
		text, err := openAICompatible(ctx, url, os.Getenv("SECDOCTOR_AI_KEY"), model, prompt)
		return text, "configured OpenAI-compatible endpoint", err
	}

	text, err := ollama(ctx, getenv("SECDOCTOR_OLLAMA_URL", "http://127.0.0.1:11434/api/generate"), getenv("SECDOCTOR_AI_MODEL", "llama3.2"), prompt)
	if err == nil {
		return text, "local Ollama", nil
	}
	return "", "", errors.New("no AI provider available; start Ollama or configure SECDOCTOR_AI_URL")
}

func openAICompatible(ctx context.Context, url, key, model, prompt string) (string, error) {
	body, _ := json.Marshal(chatRequest{
		Model: model, Stream: false,
		Messages: []message{
			{Role: "system", Content: "You explain defensive security findings accurately and concisely."},
			{Role: "user", Content: prompt},
		},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("AI endpoint returned HTTP %d", resp.StatusCode)
	}
	var out chatResponse
	if err := json.Unmarshal(data, &out); err != nil || len(out.Choices) == 0 {
		return "", errors.New("unexpected AI response")
	}
	return strings.TrimSpace(out.Choices[0].Message.Content), nil
}

func ollama(ctx context.Context, url, model, prompt string) (string, error) {
	body, _ := json.Marshal(map[string]any{"model": model, "prompt": prompt, "stream": false})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("Ollama returned HTTP %d", resp.StatusCode)
	}
	var out chatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.Response) == "" {
		return "", errors.New("empty Ollama response")
	}
	return strings.TrimSpace(out.Response), nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
