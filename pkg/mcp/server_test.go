package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"strings"
	"testing"

	"github.com/calitti/mcp-api-gateway/pkg/auth"
	"github.com/calitti/mcp-api-gateway/pkg/gateway"
	"github.com/calitti/mcp-api-gateway/pkg/redaction"
	"github.com/calitti/mcp-api-gateway/pkg/storage"
	"github.com/calitti/mcp-api-gateway/pkg/storage/storetest"
	"github.com/calitti/mcp-api-gateway/pkg/toolintegrity"
)

// --- test helpers ------------------------------------------------------

// newTestServer builds an MCPServer wired to in-memory fakes. gatewayToken
// is the master GATEWAY_TOKEN configured on the AuthManager; jwtSecret is
// irrelevant to pkg/mcp but AuthManager requires one.
func newTestServer(t *testing.T, gatewayToken string) (*MCPServer, *storetest.MockStore, *storetest.MockVault) {
	t.Helper()
	store := storetest.NewMockStore()
	vlt := storetest.NewMockVault()
	am := auth.NewAuthManager("test-jwt-secret-does-not-matter-here", gatewayToken)
	// A real GatewayClient with the default (deny-private) EgressPolicy.
	// Endpoints in these tests target loopback/private base URLs, so any
	// call that reaches ExecuteCall is rejected deterministically by the
	// SSRF guard before any network I/O — letting tests that only care
	// about "did we get past the auth/scope/pinning gates" observe a real,
	// clean error instead of relying on a nil-client panic.
	client := gateway.NewGatewayClient(vlt, gateway.EgressPolicy{})
	s := NewMCPServer(store, client, vlt, am, nil)
	return s, store, vlt
}

// --- matchScope ----------------------------------------------------------

func TestMatchScope(t *testing.T) {
	tests := []struct {
		name     string
		toolName string
		scopes   []string
		want     bool
	}{
		{"exact match", "weather_get", []string{"weather_get"}, true},
		{"wildcard star matches anything", "anything_at_all", []string{"*"}, true},
		{"prefix wildcard matches", "weather_get_forecast", []string{"weather_*"}, true},
		{"prefix wildcard non-matching prefix", "stripe_get_charge", []string{"weather_*"}, false},
		{"empty scope list denies", "weather_get", []string{}, false},
		{"nil scope list denies", "weather_get", nil, false},
		{"case sensitive exact mismatch", "Weather_Get", []string{"weather_get"}, false},
		{"case sensitive prefix mismatch", "Weather_get_forecast", []string{"weather_*"}, false},
		{"no match among several scopes", "billing_get", []string{"weather_*", "stripe_get"}, false},
		{"match among several scopes", "stripe_get", []string{"weather_*", "stripe_get"}, true},
		{"admin tool exact scope", "admin_add_connection", []string{"admin_add_connection"}, true},
		{"admin tool prefix wildcard", "admin_add_connection", []string{"admin_*"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchScope(tt.toolName, tt.scopes)
			if got != tt.want {
				t.Errorf("matchScope(%q, %v) = %v, want %v", tt.toolName, tt.scopes, got, tt.want)
			}
		})
	}
}

// --- resolveAuth -----------------------------------------------------------

func TestResolveAuth_MasterGatewayToken(t *testing.T) {
	s, _, _ := newTestServer(t, "super-secret-master-token-1234567890")

	identity, role, scopes, ok := s.resolveAuth(context.Background(), "super-secret-master-token-1234567890")
	if !ok {
		t.Fatalf("expected master token to authenticate")
	}
	if identity != "master" || role != "admin" {
		t.Errorf("got identity=%q role=%q, want identity=master role=admin", identity, role)
	}
	if len(scopes) != 1 || scopes[0] != "*" {
		t.Errorf("got scopes=%v, want [*]", scopes)
	}
}

func TestResolveAuth_ValidClientToken(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	store.SeedClientToken("client-plaintext-token", &storage.ClientToken{
		ClientName: "weather-app",
		ClientRole: "user",
		Scopes:     "weather_*, billing_get",
		Enabled:    true,
	})

	identity, role, scopes, ok := s.resolveAuth(context.Background(), "client-plaintext-token")
	if !ok {
		t.Fatalf("expected valid client token to authenticate")
	}
	if identity != "weather-app" || role != "user" {
		t.Errorf("got identity=%q role=%q, want identity=weather-app role=user", identity, role)
	}
	want := []string{"weather_*", "billing_get"}
	if len(scopes) != len(want) {
		t.Fatalf("got scopes=%v, want %v", scopes, want)
	}
	for i := range want {
		if scopes[i] != want[i] {
			t.Errorf("scopes[%d] = %q, want %q", i, scopes[i], want[i])
		}
	}
}

func TestResolveAuth_DisabledClientTokenRejected(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	store.SeedClientToken("disabled-token", &storage.ClientToken{
		ClientName: "old-app",
		ClientRole: "user",
		Scopes:     "*",
		Enabled:    false,
	})

	_, _, _, ok := s.resolveAuth(context.Background(), "disabled-token")
	if ok {
		t.Fatalf("expected disabled client token to be rejected")
	}
}

func TestResolveAuth_InvalidTokenRejected(t *testing.T) {
	s, _, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")

	identity, role, scopes, ok := s.resolveAuth(context.Background(), "totally-unknown-token")
	if ok {
		t.Fatalf("expected unknown token to be rejected")
	}
	if identity != "" || role != "" || scopes != nil {
		t.Errorf("expected zero values on failed auth, got identity=%q role=%q scopes=%v", identity, role, scopes)
	}
}

func TestResolveAuth_ClientTokenPrecedenceOverMaster(t *testing.T) {
	// A client token that happens to differ from the master token must
	// resolve to its own identity, not silently become master.
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	store.SeedClientToken("client-token-abc", &storage.ClientToken{
		ClientName: "svc-a",
		ClientRole: "user",
		Scopes:     "svc_a_*",
		Enabled:    true,
	})

	identity, role, _, ok := s.resolveAuth(context.Background(), "client-token-abc")
	if !ok || identity != "svc-a" || role != "user" {
		t.Fatalf("got identity=%q role=%q ok=%v, want svc-a/user/true", identity, role, ok)
	}
}

// --- admin_ prefix tool gate (handleRequest / tools/call) ------------------

func rawParams(t *testing.T, v CallToolRequest) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	return b
}

func TestHandleRequest_AdminToolDeniedForNonAdmin(t *testing.T) {
	s, _, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      1,
		Params: rawParams(t, CallToolRequest{
			Name:      "admin_add_connection",
			Arguments: map[string]interface{}{"name": "x", "base_url": "https://example.com", "auth_type": "none"},
		}),
	}

	// Non-admin role but with a scope that WOULD match the tool name, to
	// isolate the role check from the scope check.
	resp := s.handleRequest(context.Background(), "some-user", "user", []string{"*"}, req)

	if resp.Error == nil {
		t.Fatalf("expected admin tool call to be denied for non-admin role")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("got error code %d, want -32601 (method not found)", resp.Error.Code)
	}
}

func TestHandleRequest_AdminToolAllowedForAdmin(t *testing.T) {
	s, _, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      1,
		Params: rawParams(t, CallToolRequest{
			Name:      "admin_add_connection",
			Arguments: map[string]interface{}{"name": "x", "base_url": "https://example.com", "auth_type": "none"},
		}),
	}

	resp := s.handleRequest(context.Background(), "master", "admin", []string{"*"}, req)

	if resp.Error != nil {
		t.Fatalf("expected admin tool call to succeed for admin role, got error: %+v", resp.Error)
	}
	if resp.Result == nil {
		t.Fatalf("expected a result for successful admin_add_connection call")
	}
}

// --- scope denial on tools/call ---------------------------------------------

func TestHandleRequest_ScopeDenied(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")

	conn := store.SeedConnection(&storage.APIConnection{ID: "conn-1", Name: "weather", BaseURL: "https://weather.example.com", AuthType: "none", Enabled: true})
	store.SeedEndpoint(&storage.APIEndpoint{ID: "ep-1", ConnectionID: conn.ID, ToolName: "get_forecast", ToolDescription: "get forecast", Path: "/forecast", Method: "GET"})

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      1,
		Params: rawParams(t, CallToolRequest{
			Name:      "get_forecast",
			Arguments: map[string]interface{}{},
		}),
	}

	// Scoped only to "billing_*" — must not be allowed to call get_forecast.
	resp := s.handleRequest(context.Background(), "svc-a", "user", []string{"billing_*"}, req)

	if resp.Error == nil {
		t.Fatalf("expected scope-denied tools/call to error")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("got error code %d, want -32601 (method not found / denied)", resp.Error.Code)
	}
}

func TestHandleRequest_ScopeAllowedReachesExecution(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")

	// Loopback base URL: irrelevant to the scope gate under test, but lets
	// us prove we got PAST the auth/scope gates by observing a clean
	// egress-denied error from ExecuteCall's SSRF guard, rather than a
	// "method not found" (scope-denial) error.
	conn := store.SeedConnection(&storage.APIConnection{ID: "conn-1", Name: "weather", BaseURL: "http://127.0.0.1:1", AuthType: "none", Enabled: true})
	store.SeedEndpoint(&storage.APIEndpoint{ID: "ep-1", ConnectionID: conn.ID, ToolName: "get_forecast", ToolDescription: "get forecast", Path: "/forecast", Method: "GET"})

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      1,
		Params: rawParams(t, CallToolRequest{
			Name:      "get_forecast",
			Arguments: map[string]interface{}{},
		}),
	}

	resp := s.handleRequest(context.Background(), "svc-a", "user", []string{"get_forecast"}, req)
	if resp.Error == nil {
		t.Fatalf("expected the loopback target to be rejected by the egress guard once execution was reached")
	}
	if resp.Error.Code == -32601 {
		t.Fatalf("scope-allowed call was incorrectly denied as method-not-found: %+v", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "egress denied") {
		t.Errorf("expected an egress-denied error proving we reached execution, got: %+v", resp.Error)
	}
}

// --- tool-hash pinning -------------------------------------------------------

func TestToolDefinitionChanged_EmptyStoredHashNeverBlocks(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	conn := store.SeedConnection(&storage.APIConnection{ID: "conn-1", Name: "svc", BaseURL: "https://svc.example.com", AuthType: "none", Enabled: true})
	store.SeedEndpoint(&storage.APIEndpoint{
		ID: "ep-1", ConnectionID: conn.ID, ToolName: "get_thing", ToolDescription: "desc",
		Path: "/thing", Method: "GET", DefinitionHash: "", // no baseline yet
	})

	changed, err := s.toolDefinitionChanged(context.Background(), "get_thing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Errorf("expected empty stored hash to never count as changed")
	}
}

func TestToolDefinitionChanged_MatchingHashProceeds(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	conn := store.SeedConnection(&storage.APIConnection{ID: "conn-1", Name: "svc", BaseURL: "https://svc.example.com", AuthType: "none", Enabled: true})

	ep := &storage.APIEndpoint{
		ID: "ep-1", ConnectionID: conn.ID, ToolName: "get_thing", ToolDescription: "desc",
		Path: "/thing", Method: "GET", ParametersSchema: `{"type":"object"}`,
	}
	// Mirror toolDefinitionChanged's construction of the hashable ToolDef
	// exactly (name = resolved tool name post-prefix, which here equals
	// ep.ToolName since the connection has no ToolPrefix).
	hash := toolintegrity.Hash(toolintegrity.ToolDef{
		Name:             "get_thing",
		Description:      ep.ToolDescription,
		Method:           ep.Method,
		Path:             ep.Path,
		ParametersSchema: ep.ParametersSchema,
	})
	ep.DefinitionHash = hash
	store.SeedEndpoint(ep)

	changed, err := s.toolDefinitionChanged(context.Background(), "get_thing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if changed {
		t.Errorf("expected matching hash to not be reported as changed")
	}
}

func TestToolDefinitionChanged_DifferingHashRefuses(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	conn := store.SeedConnection(&storage.APIConnection{ID: "conn-1", Name: "svc", BaseURL: "https://svc.example.com", AuthType: "none", Enabled: true})

	store.SeedEndpoint(&storage.APIEndpoint{
		ID: "ep-1", ConnectionID: conn.ID, ToolName: "get_thing", ToolDescription: "desc",
		Path: "/thing", Method: "GET", DefinitionHash: "stale-hash-that-will-never-match",
	})

	changed, err := s.toolDefinitionChanged(context.Background(), "get_thing")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !changed {
		t.Errorf("expected mismatched stored hash to be reported as changed")
	}
}

func TestHandleRequest_StrictPinningRefusesChangedTool(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	s.SetToolPinningStrict(true)

	conn := store.SeedConnection(&storage.APIConnection{ID: "conn-1", Name: "svc", BaseURL: "https://svc.example.com", AuthType: "none", Enabled: true})
	store.SeedEndpoint(&storage.APIEndpoint{
		ID: "ep-1", ConnectionID: conn.ID, ToolName: "get_thing", ToolDescription: "desc",
		Path: "/thing", Method: "GET", DefinitionHash: "stale-hash-that-will-never-match",
	})

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      1,
		Params: rawParams(t, CallToolRequest{
			Name:      "get_thing",
			Arguments: map[string]interface{}{},
		}),
	}

	resp := s.handleRequest(context.Background(), "master", "admin", []string{"*"}, req)
	if resp.Error == nil {
		t.Fatalf("expected strict pinning to refuse a call to a tool whose definition changed")
	}
	if resp.Error.Code != -32001 {
		t.Errorf("got error code %d, want -32001 (tool pinning refusal)", resp.Error.Code)
	}
}

func TestHandleRequest_StrictPinningAllowsEmptyHash(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	s.SetToolPinningStrict(true)

	// Loopback base URL so a call that gets past the pinning gate is
	// deterministically rejected by the SSRF guard, proving execution was
	// reached without depending on real network I/O.
	conn := store.SeedConnection(&storage.APIConnection{ID: "conn-1", Name: "svc", BaseURL: "http://127.0.0.1:1", AuthType: "none", Enabled: true})
	store.SeedEndpoint(&storage.APIEndpoint{
		ID: "ep-1", ConnectionID: conn.ID, ToolName: "get_thing", ToolDescription: "desc",
		Path: "/thing", Method: "GET", DefinitionHash: "",
	})

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      1,
		Params: rawParams(t, CallToolRequest{
			Name:      "get_thing",
			Arguments: map[string]interface{}{},
		}),
	}

	resp := s.handleRequest(context.Background(), "master", "admin", []string{"*"}, req)
	if resp.Error == nil {
		t.Fatalf("expected the loopback target to be rejected by the egress guard once execution was reached")
	}
	if resp.Error.Code == -32001 {
		t.Fatalf("empty stored hash incorrectly blocked the call as a pinning refusal: %+v", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "egress denied") {
		t.Errorf("expected an egress-denied error proving we reached execution, got: %+v", resp.Error)
	}
}

// --- redaction -----------------------------------------------------------

func TestHandleRequest_RedactsArgsAndResult(t *testing.T) {
	s, store, _ := newTestServer(t, "master-token-xxxxxxxxxxxxxxxxxxxx")
	redactor, err := redaction.New(redaction.Config{Enabled: true})
	if err != nil {
		t.Fatalf("failed to build redactor: %v", err)
	}
	s.EnableRedaction(redactor)

	// admin_register_vault_secret is a convenient admin tool whose "value"
	// argument is echoed back only as a key name in the success message, so
	// instead we verify redaction on the *result* by using an admin tool
	// whose response text we control: admin_add_connection's success
	// message embeds conn.Name verbatim. We put an email address in the
	// connection name so it shows up in the response text and gets
	// redacted.
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		ID:      1,
		Params: rawParams(t, CallToolRequest{
			Name: "admin_add_connection",
			Arguments: map[string]interface{}{
				"name":      "contact-me-at-secret.user@example.com",
				"base_url":  "https://example.com",
				"auth_type": "none",
			},
		}),
	}

	resp := s.handleRequest(context.Background(), "master", "admin", []string{"*"}, req)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %+v", resp.Error)
	}

	callResp, ok := resp.Result.(CallToolResponse)
	if !ok {
		t.Fatalf("unexpected result type %T", resp.Result)
	}
	if len(callResp.Content) != 1 {
		t.Fatalf("expected exactly one content block, got %d", len(callResp.Content))
	}
	text := callResp.Content[0].Text
	if text == "" {
		t.Fatalf("expected non-empty result text")
	}
	if strings.Contains(text, "secret.user@example.com") {
		t.Errorf("expected email address to be redacted from result, got: %q", text)
	}
	if !strings.Contains(text, "[REDACTED:"+redaction.ClassEmail+"]") {
		t.Errorf("expected redaction tag in result text, got: %q", text)
	}

	_ = store // store is only used to satisfy newTestServer's return signature here
}

func TestRedactor_MasksEmailInArguments(t *testing.T) {
	// Directly exercise the redactor the way handleRequest does on
	// callReq.Arguments, without depending on a specific tool's echo
	// behavior — a more isolated unit test of the redaction wiring.
	redactor, err := redaction.New(redaction.Config{Enabled: true})
	if err != nil {
		t.Fatalf("failed to build redactor: %v", err)
	}

	args := map[string]interface{}{"email": "someone@example.com", "note": "no secrets here"}
	redacted, findings := redactor.RedactMap(args)

	if redacted["email"] == args["email"] {
		t.Errorf("expected email argument to be redacted, got unchanged: %v", redacted["email"])
	}
	if redacted["note"] != "no secrets here" {
		t.Errorf("expected non-sensitive argument to pass through unchanged, got: %v", redacted["note"])
	}
	if len(findings) != 1 || findings[0].Class != redaction.ClassEmail || findings[0].Count != 1 {
		t.Errorf("expected exactly one email finding, got: %+v", findings)
	}
}

// --- ServeMessages anti-hijack ---------------------------------------------
//
// ServeMessages requires a live SSE session (http.Flusher-backed
// ResponseWriter, an active goroutine holding the session in s.sessions,
// etc.) which is impractical to construct in a unit test without a real
// HTTP round trip. Instead we cover the underlying comparison it relies on
// directly: sessionTokenHash + the constant-time compare, which is exactly
// the anti-hijack check ServeMessages performs (see server.go's
// `subtle.ConstantTimeCompare([]byte(presented), []byte(session.TokenHash))`).

func TestSessionTokenHash_MismatchedTokenRejected(t *testing.T) {
	boundToken := "session-owner-token"
	presentedToken := "attacker-token"

	boundHash := sessionTokenHash(boundToken)
	presentedHash := sessionTokenHash(presentedToken)

	if subtle.ConstantTimeCompare([]byte(presentedHash), []byte(boundHash)) == 1 {
		t.Fatalf("expected mismatched token hashes to fail the constant-time compare")
	}
}

func TestSessionTokenHash_MatchingTokenAccepted(t *testing.T) {
	token := "session-owner-token"

	boundHash := sessionTokenHash(token)
	presentedHash := sessionTokenHash(token)

	if subtle.ConstantTimeCompare([]byte(presentedHash), []byte(boundHash)) != 1 {
		t.Fatalf("expected matching token hashes to pass the constant-time compare")
	}
}
