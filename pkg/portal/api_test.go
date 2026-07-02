package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/calitti/mcp-api-gateway/pkg/auth"
	"github.com/calitti/mcp-api-gateway/pkg/config"
	"github.com/calitti/mcp-api-gateway/pkg/gateway"
	"github.com/calitti/mcp-api-gateway/pkg/mcp"
	"github.com/calitti/mcp-api-gateway/pkg/storage/storetest"
)

// --- test helpers -----------------------------------------------------------

// testConfig returns a minimally valid *config.Config for wiring a
// PortalServer in tests. adminPassword controls whether local login is
// enabled (empty = disabled, fail-closed).
func testConfig(adminPassword string) *config.Config {
	return &config.Config{
		Port:          "8080",
		VaultProvider: "local",
		JWTSecret:     strings.Repeat("a", 32),
		GatewayToken:  strings.Repeat("b", 32),
		AdminUsername: "admin",
		AdminPassword: adminPassword,
	}
}

// newTestServer wires a PortalServer with in-memory fakes: a MockStore, a
// MockVault, a real AuthManager (so JWTs mint/validate exactly as in
// production), and a real MCPServer built on the same fakes.
func newTestServer(t *testing.T, adminPassword string) (*PortalServer, *storetest.MockStore, *auth.AuthManager, *http.ServeMux) {
	t.Helper()

	store := storetest.NewMockStore()
	mv := storetest.NewMockVault()
	cfg := testConfig(adminPassword)

	am := auth.NewAuthManager(cfg.JWTSecret, cfg.GatewayToken)

	gwClient := gateway.NewGatewayClient(mv, gateway.EgressPolicy{AllowPrivate: true})
	mcpServer := mcp.NewMCPServer(store, gwClient, mv, am, nil)

	p := NewPortalServer(store, mv, am, cfg, mcpServer)

	mux := http.NewServeMux()
	p.RegisterRoutes(mux)

	return p, store, am, mux
}

// adminToken mints a valid admin-role JWT via the same AuthManager the
// server uses to validate requests.
func adminToken(t *testing.T, am *auth.AuthManager) string {
	t.Helper()
	tok, err := am.GenerateJWT("test-admin", "admin")
	if err != nil {
		t.Fatalf("GenerateJWT(admin) failed: %v", err)
	}
	return tok
}

// viewerToken mints a valid but non-admin JWT, to prove AdminAuthMiddleware
// enforces authorization (role), not just authentication.
func viewerToken(t *testing.T, am *auth.AuthManager) string {
	t.Helper()
	tok, err := am.GenerateJWT("test-viewer", "viewer")
	if err != nil {
		t.Fatalf("GenerateJWT(viewer) failed: %v", err)
	}
	return tok
}

// --- admin-middleware route coverage -----------------------------------------

// adminRoutes lists every mutating/administrative /api/* route registered
// behind AdminAuthMiddleware in RegisterRoutes. If a future route is added to
// RegisterRoutes but omitted here, the "all registered admin routes are
// covered" test below will not catch it directly, but any accidentally
// unwrapped route will show up as a regression against this list when it is
// exercised without a token.
var adminRoutes = []struct {
	name   string
	method string
	path   string
}{
	{"connections GET", http.MethodGet, "/api/connections"},
	{"connections POST", http.MethodPost, "/api/connections"},
	{"connections DELETE", http.MethodDelete, "/api/connections/some-id"},
	{"endpoints GET", http.MethodGet, "/api/endpoints"},
	{"endpoints POST", http.MethodPost, "/api/endpoints"},
	{"endpoints DELETE", http.MethodDelete, "/api/endpoints/some-id"},
	{"openapi import", http.MethodPost, "/api/import/openapi"},
	{"vault GET", http.MethodGet, "/api/vault"},
	{"vault POST", http.MethodPost, "/api/vault"},
	{"vault DELETE", http.MethodDelete, "/api/vault?key=k"},
	{"logs GET", http.MethodGet, "/api/logs"},
	{"settings GET", http.MethodGet, "/api/settings"},
	{"operational-stats GET", http.MethodGet, "/api/operational-stats"},
	{"tokens GET", http.MethodGet, "/api/tokens"},
	{"tokens POST", http.MethodPost, "/api/tokens"},
	{"tokens DELETE", http.MethodDelete, "/api/tokens?client_name=x"},
	{"openapi.json GET", http.MethodGet, "/api/openapi.json"},
}

// TestAdminRoutes_RejectWithoutToken drives every known admin route with no
// Authorization header and asserts it is rejected (never 200/2xx). This
// guards against a future route being registered on the mux without being
// wrapped by admin(...).
func TestAdminRoutes_RejectWithoutToken(t *testing.T) {
	_, _, _, mux := newTestServer(t, "")

	for _, rt := range adminRoutes {
		t.Run(rt.name, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s %s: expected 401 without token, got %d (body=%s)",
					rt.method, rt.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAdminRoutes_RejectNonAdminToken proves the middleware enforces the
// admin role specifically, not just "any authenticated user."
func TestAdminRoutes_RejectNonAdminToken(t *testing.T) {
	_, _, am, mux := newTestServer(t, "")
	tok := viewerToken(t, am)

	for _, rt := range adminRoutes {
		t.Run(rt.name, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s %s: expected 403 with non-admin token, got %d (body=%s)",
					rt.method, rt.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAdminRoutes_AcceptAdminToken proves a valid admin JWT passes the
// middleware for every route (i.e. we reach the handler rather than being
// stopped at auth/authz). We only assert the response is NOT 401/403 —
// individual handlers are exercised in detail elsewhere in this file.
func TestAdminRoutes_AcceptAdminToken(t *testing.T) {
	_, _, am, mux := newTestServer(t, "")
	tok := adminToken(t, am)

	for _, rt := range adminRoutes {
		t.Run(rt.name, func(t *testing.T) {
			req := httptest.NewRequest(rt.method, rt.path, http.NoBody)
			req.Header.Set("Authorization", "Bearer "+tok)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
				t.Fatalf("%s %s: expected admin token to pass middleware, got %d (body=%s)",
					rt.method, rt.path, rec.Code, rec.Body.String())
			}
		})
	}
}

// --- handleOpenAPIImport -----------------------------------------------------

const minimalOpenAPISpec = `{
  "openapi": "3.0.0",
  "info": { "title": "Widget Service" },
  "servers": [ { "url": "https://widgets.example.com" } ],
  "paths": {
    "/widgets": {
      "get": {
        "operationId": "listWidgets",
        "summary": "List widgets",
        "responses": { "200": { "description": "OK" } }
      }
    },
    "/widgets/{id}": {
      "get": {
        "operationId": "getWidget",
        "summary": "Get a widget",
        "parameters": [
          { "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
        ],
        "responses": { "200": { "description": "OK" } }
      }
    }
  }
}`

func TestHandleOpenAPIImport_DryRun_MakesNoWrites(t *testing.T) {
	_, store, am, mux := newTestServer(t, "")
	tok := adminToken(t, am)

	req := httptest.NewRequest(http.MethodPost, "/api/import/openapi?dry_run=true", strings.NewReader(minimalOpenAPISpec))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("dry_run import: expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		DryRun     bool `json:"dry_run"`
		Connection struct {
			Name     string `json:"name"`
			BaseURL  string `json:"base_url"`
			AuthType string `json:"auth_type"`
		} `json:"connection"`
		ToolCount int `json:"tool_count"`
		Tools     []struct {
			ToolName string `json:"tool_name"`
			Path     string `json:"path"`
			Method   string `json:"method"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}

	if !resp.DryRun {
		t.Fatalf("expected dry_run:true in response, got %+v", resp)
	}
	if resp.Connection.BaseURL != "https://widgets.example.com" {
		t.Fatalf("expected preview base_url to reflect the spec, got %q", resp.Connection.BaseURL)
	}
	if resp.ToolCount != 2 || len(resp.Tools) != 2 {
		t.Fatalf("expected 2 previewed tools, got tool_count=%d tools=%+v", resp.ToolCount, resp.Tools)
	}

	// The critical assertion: dry-run must not write anything to the store.
	conns, err := store.GetConnections(t.Context())
	if err != nil {
		t.Fatalf("GetConnections: %v", err)
	}
	if len(conns) != 0 {
		t.Fatalf("dry_run must not persist connections; found %d", len(conns))
	}
	eps, err := store.GetAllEndpoints(t.Context())
	if err != nil {
		t.Fatalf("GetAllEndpoints: %v", err)
	}
	if len(eps) != 0 {
		t.Fatalf("dry_run must not persist endpoints; found %d", len(eps))
	}
}

func TestHandleOpenAPIImport_Persists_ConnectionAndEndpoints(t *testing.T) {
	_, store, am, mux := newTestServer(t, "")
	tok := adminToken(t, am)

	req := httptest.NewRequest(http.MethodPost, "/api/import/openapi", strings.NewReader(minimalOpenAPISpec))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("import: expected 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		DryRun           bool     `json:"dry_run"`
		ConnectionID     string   `json:"connection_id"`
		ConnectionName   string   `json:"connection_name"`
		EndpointsCreated int      `json:"endpoints_created"`
		ToolNames        []string `json:"tool_names"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, rec.Body.String())
	}

	if resp.DryRun {
		t.Fatalf("expected dry_run:false, got true")
	}
	if resp.ConnectionID == "" {
		t.Fatalf("expected a generated connection_id")
	}
	if resp.EndpointsCreated != 2 || len(resp.ToolNames) != 2 {
		t.Fatalf("expected 2 created endpoints, got endpoints_created=%d tool_names=%v",
			resp.EndpointsCreated, resp.ToolNames)
	}

	// Verify the store side effects directly, not just the HTTP response.
	conns, err := store.GetConnections(t.Context())
	if err != nil {
		t.Fatalf("GetConnections: %v", err)
	}
	if len(conns) != 1 {
		t.Fatalf("expected exactly 1 persisted connection, got %d", len(conns))
	}
	if conns[0].ID != resp.ConnectionID {
		t.Fatalf("persisted connection ID %q does not match response %q", conns[0].ID, resp.ConnectionID)
	}
	if conns[0].BaseURL != "https://widgets.example.com" {
		t.Fatalf("persisted connection base_url = %q, want https://widgets.example.com", conns[0].BaseURL)
	}

	eps, err := store.GetEndpoints(t.Context(), resp.ConnectionID)
	if err != nil {
		t.Fatalf("GetEndpoints: %v", err)
	}
	if len(eps) != 2 {
		t.Fatalf("expected 2 persisted endpoints for the connection, got %d", len(eps))
	}

	gotNames := map[string]bool{}
	for _, ep := range eps {
		gotNames[ep.ToolName] = true
		if ep.ConnectionID != resp.ConnectionID {
			t.Fatalf("endpoint %q has ConnectionID %q, want %q", ep.ToolName, ep.ConnectionID, resp.ConnectionID)
		}
	}
	for _, want := range resp.ToolNames {
		if !gotNames[want] {
			t.Fatalf("expected persisted endpoint with tool_name %q, got %v", want, gotNames)
		}
	}
}

func TestHandleOpenAPIImport_RequiresAdminAuth(t *testing.T) {
	_, _, _, mux := newTestServer(t, "")

	req := httptest.NewRequest(http.MethodPost, "/api/import/openapi", strings.NewReader(minimalOpenAPISpec))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without auth, got %d", rec.Code)
	}
}

func TestHandleOpenAPIImport_EmptyBody_BadRequest(t *testing.T) {
	_, _, am, mux := newTestServer(t, "")
	tok := adminToken(t, am)

	req := httptest.NewRequest(http.MethodPost, "/api/import/openapi", strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty body, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleOpenAPIImport_InvalidSpec_BadRequest(t *testing.T) {
	_, _, am, mux := newTestServer(t, "")
	tok := adminToken(t, am)

	req := httptest.NewRequest(http.MethodPost, "/api/import/openapi", strings.NewReader(`{"not":"a spec"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid spec, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// --- audienceContains ---------------------------------------------------------

func TestAudienceContains(t *testing.T) {
	tests := []struct {
		name     string
		aud      interface{}
		clientID string
		want     bool
	}{
		{"string match", "my-client", "my-client", true},
		{"string mismatch", "other-client", "my-client", false},
		{"slice match", []interface{}{"a", "my-client", "b"}, "my-client", true},
		{"slice mismatch", []interface{}{"a", "b"}, "my-client", false},
		{"slice with non-string element", []interface{}{1, "my-client"}, "my-client", true},
		{"empty client id", "my-client", "", false},
		{"nil aud", nil, "my-client", false},
		{"empty slice", []interface{}{}, "my-client", false},
		{"unsupported type", 42, "my-client", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := audienceContains(tt.aud, tt.clientID)
			if got != tt.want {
				t.Errorf("audienceContains(%#v, %q) = %v, want %v", tt.aud, tt.clientID, got, tt.want)
			}
		})
	}
}

// --- hostIsInternal (SSRF-relevant OIDC/health-check helper) -----------------

func TestHostIsInternal(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"loopback", "http://127.0.0.1:8080/x", true},
		{"private 10.x", "http://10.0.0.5/x", true},
		{"private 192.168.x", "http://192.168.1.1/x", true},
		{"unspecified", "http://0.0.0.0/x", true},
		{"invalid URL", "://not-a-url", true},
		{"empty host", "file:///etc/passwd", true},
		{"public IP literal", "http://93.184.216.34/x", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostIsInternal(tt.url)
			if got != tt.want {
				t.Errorf("hostIsInternal(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

// --- local login fail-closed behaviour ---------------------------------------

func TestHandleLogin_DisabledWhenNoAdminPassword(t *testing.T) {
	_, _, _, mux := newTestServer(t, "") // empty ADMIN_PASSWORD

	body := `{"username":"admin","password":"whatever-it-does-not-matter"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when local login disabled, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "local login disabled") {
		t.Fatalf("expected disabled-login error message, got body=%s", rec.Body.String())
	}
}

func TestHandleLogin_SucceedsWithCorrectCredentials(t *testing.T) {
	const pw = "a-strong-enough-password"
	_, _, _, mux := newTestServer(t, pw)

	body := `{"username":"admin","password":"` + pw + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct credentials, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	var resp struct {
		Token    string `json:"token"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Token == "" {
		t.Fatalf("expected a non-empty JWT in response")
	}
	if resp.Username != "admin" {
		t.Fatalf("expected username 'admin', got %q", resp.Username)
	}
}

func TestHandleLogin_RejectsWrongPassword(t *testing.T) {
	_, _, _, mux := newTestServer(t, "a-strong-enough-password")

	body := `{"username":"admin","password":"totally-wrong"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(body))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestHandleLogin_MethodNotAllowed(t *testing.T) {
	_, _, _, mux := newTestServer(t, "a-strong-enough-password")

	req := httptest.NewRequest(http.MethodGet, "/api/auth/login", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for GET login, got %d", rec.Code)
	}
}
