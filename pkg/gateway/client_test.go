package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/calitti/mcp-api-gateway/pkg/storage"
)

type MockVault struct{}

func (m *MockVault) GetSecret(ctx context.Context, secretName string) (string, error) {
	if secretName == "test-key" {
		return "super-secret-api-token", nil
	}
	return "", nil
}

func (m *MockVault) SetSecret(ctx context.Context, secretName string, secretValue string) error {
	return nil
}

func (m *MockVault) ListSecrets(ctx context.Context) ([]string, error) {
	return []string{"test-key"}, nil
}

func (m *MockVault) DeleteSecret(ctx context.Context, secretName string) error {
	return nil
}

func TestExecuteCall_GET(t *testing.T) {
	// Start a mock server to check parameters
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/users/123" {
			t.Errorf("expected path /v1/users/123, got %q", r.URL.Path)
		}
		if r.URL.Query().Get("filter") != "active" {
			t.Errorf("expected query filter=active, got %q", r.URL.Query().Get("filter"))
		}
		if r.Header.Get("Authorization") != "Bearer super-secret-api-token" {
			t.Errorf("expected auth header Bearer super-secret-api-token, got %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	client := NewGatewayClient(&MockVault{}, EgressPolicy{AllowPrivate: true})
	conn := &storage.APIConnection{
		BaseURL:       server.URL,
		AuthType:      "bearer",
		AuthSecretRef: "test-key",
		Enabled:       true,
	}

	ep := &storage.APIEndpoint{
		Path:   "/v1/users/{{user_id}}",
		Method: "GET",
	}

	params := map[string]interface{}{
		"user_id": 123,
		"filter":  "active",
	}

	resp, err := client.ExecuteCall(context.Background(), conn, ep, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var data map[string]string
	if err := json.Unmarshal([]byte(resp), &data); err != nil {
		t.Fatalf("failed to parse json response: %v", err)
	}

	if data["status"] != "ok" {
		t.Errorf("expected status ok, got %q", data["status"])
	}
}

func TestExecuteCall_POST_JSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqData map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqData); err != nil {
			t.Fatalf("failed to parse body: %v", err)
		}
		if reqData["id"] != "inv-999" {
			t.Errorf("expected id inv-999, got %v", reqData["id"])
		}
		if reqData["amount"] != float64(150) {
			t.Errorf("expected amount 150, got %v", reqData["amount"])
		}
		w.Write([]byte(`{"result":"created"}`))
	}))
	defer server.Close()

	client := NewGatewayClient(&MockVault{}, EgressPolicy{AllowPrivate: true})
	conn := &storage.APIConnection{
		BaseURL:  server.URL,
		AuthType: "none",
		Enabled:  true,
	}

	ep := &storage.APIEndpoint{
		Path:     "/v1/invoices",
		Method:   "POST",
		Template: `{"id": "{{invoice_id}}", "amount": {{amount}} }`,
	}

	params := map[string]interface{}{
		"invoice_id": "inv-999",
		"amount":     150,
	}

	resp, err := client.ExecuteCall(context.Background(), conn, ep, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "{\n  \"result\": \"created\"\n}"
	if resp != expected {
		t.Errorf("expected result body %q, got %q", expected, resp)
	}
}

func TestExecuteCall_ResponseCache(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte(`{"n":1}`))
	}))
	defer server.Close()

	client := NewGatewayClient(&MockVault{}, EgressPolicy{AllowPrivate: true})
	client.EnableResponseCache(time.Minute)
	conn := &storage.APIConnection{BaseURL: server.URL, AuthType: "none", Enabled: true}
	ep := &storage.APIEndpoint{Path: "/stats", Method: "GET"}

	for i := 0; i < 3; i++ {
		if _, err := client.ExecuteCall(context.Background(), conn, ep, map[string]interface{}{}); err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
	}
	if hits != 1 {
		t.Fatalf("expected exactly 1 upstream hit (rest cached), got %d", hits)
	}
}

func TestExecuteCall_SecretCacheReducesVaultCalls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	mv := &countingVault{}
	client := NewGatewayClient(mv, EgressPolicy{AllowPrivate: true})
	client.EnableSecretCache(time.Minute)
	conn := &storage.APIConnection{BaseURL: server.URL, AuthType: "bearer", AuthSecretRef: "test-key", Enabled: true}
	ep := &storage.APIEndpoint{Path: "/x", Method: "POST"}

	for i := 0; i < 3; i++ {
		if _, err := client.ExecuteCall(context.Background(), conn, ep, map[string]interface{}{}); err != nil {
			t.Fatalf("call %d failed: %v", i, err)
		}
	}
	if mv.calls != 1 {
		t.Fatalf("expected secret fetched once and cached, got %d vault calls", mv.calls)
	}
}

type countingVault struct{ calls int }

func (c *countingVault) GetSecret(ctx context.Context, name string) (string, error) {
	c.calls++
	return "super-secret-api-token", nil
}
func (c *countingVault) SetSecret(ctx context.Context, name, val string) error { return nil }
func (c *countingVault) ListSecrets(ctx context.Context) ([]string, error)     { return nil, nil }
func (c *countingVault) DeleteSecret(ctx context.Context, name string) error   { return nil }

func TestExecuteCall_BlocksPrivateEgress(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	// Default policy (AllowPrivate=false) must block the loopback test server.
	client := NewGatewayClient(&MockVault{}, EgressPolicy{})
	conn := &storage.APIConnection{BaseURL: server.URL, AuthType: "none", Enabled: true}
	ep := &storage.APIEndpoint{Path: "/", Method: "GET"}

	_, err := client.ExecuteCall(context.Background(), conn, ep, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected egress to be denied for a private/loopback target, got nil error")
	}
}
