package portal

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/calitti/mcp-api-gateway/pkg/auth"
	"github.com/calitti/mcp-api-gateway/pkg/config"
	"github.com/calitti/mcp-api-gateway/pkg/mcp"
	"github.com/calitti/mcp-api-gateway/pkg/storage"
	"github.com/calitti/mcp-api-gateway/pkg/vault"
	"github.com/google/uuid"
)

// Global embed for static web assets (HTML/CSS/JS)
//
//go:embed static/*
var assets embed.FS

type PortalServer struct {
	db          *storage.DB
	vault       vault.VaultProvider
	authManager *auth.AuthManager
	config      *config.Config
	mcpServer   *mcp.MCPServer
}

func NewPortalServer(db *storage.DB, vp vault.VaultProvider, am *auth.AuthManager, cfg *config.Config, mcpServer *mcp.MCPServer) *PortalServer {
	return &PortalServer{
		db:          db,
		vault:       vp,
		authManager: am,
		config:      cfg,
		mcpServer:   mcpServer,
	}
}

func (p *PortalServer) RegisterRoutes(mux *http.ServeMux) {
	// Authentication
	mux.HandleFunc("/api/auth/login", p.handleLogin)
	mux.HandleFunc("/api/auth/sso/login", p.handleSSOLogin)
	mux.HandleFunc("/api/auth/sso/callback", p.handleSSOCallback)

	// All administrative APIs require the admin role (authorization, not just
	// authentication). The middleware rejects valid-but-non-admin tokens.
	admin := p.authManager.AdminAuthMiddleware

	// API Connections
	mux.HandleFunc("/api/connections", admin(p.handleConnections))
	mux.HandleFunc("/api/connections/", admin(p.handleConnections))

	// API Endpoints
	mux.HandleFunc("/api/endpoints", admin(p.handleEndpoints))
	mux.HandleFunc("/api/endpoints/", admin(p.handleEndpoints))

	// Vault Secrets Management
	mux.HandleFunc("/api/vault", admin(p.handleVault))

	// Audit Logs
	mux.HandleFunc("/api/logs", admin(p.handleAuditLogs))

	// Global Configurations
	mux.HandleFunc("/api/settings", admin(p.handleSettings))

	// Operational Statistics
	mux.HandleFunc("/api/operational-stats", admin(p.handleOperationalStats))

	// Client Tokens
	mux.HandleFunc("/api/tokens", admin(p.handleTokens))

	// OpenAPI unified reference
	mux.HandleFunc("/api/openapi.json", admin(p.handleOpenAPI))

	// Mock Downstream APIs for LCH DPG & Collateral services
	mux.HandleFunc("/api/mock/dpg/trade-volume", p.handleMockTradeVolume)
	mux.HandleFunc("/api/mock/collateral/non-cash", p.handleMockNonCashCollateral)

	// Serving the SPA Frontend
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		panic(fmt.Sprintf("failed to load embedded static assets: %v", err))
	}
	fileServer := http.FileServer(http.FS(staticFS))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Clean the path to prevent directory traversal
		cleanedPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if cleanedPath == "" {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Check if the requested file exists in the embedded static assets
		_, err := fs.Stat(staticFS, cleanedPath)
		if err != nil {
			// File does not exist, rewrite to index.html for SPA client-side routing
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	})
}

// REST Handlers

func (p *PortalServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
		return
	}

	// Local admin login is enabled only when ADMIN_PASSWORD is configured.
	// Credentials are compared in constant time. When unset, only SSO/OIDC is allowed.
	if p.config.AdminPassword == "" {
		http.Error(w, `{"error":"local login disabled; use SSO"}`, http.StatusUnauthorized)
		return
	}

	userOK := subtle.ConstantTimeCompare([]byte(credentials.Username), []byte(p.config.AdminUsername)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(credentials.Password), []byte(p.config.AdminPassword)) == 1
	if userOK && passOK {
		token, err := p.authManager.GenerateJWT(p.config.AdminUsername, "admin")
		if err != nil {
			http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
			return
		}
		resp, _ := json.Marshal(map[string]string{"token": token, "username": p.config.AdminUsername})
		w.Header().Set("Content-Type", "application/json")
		w.Write(resp)
		return
	}

	http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
}

// redirectURI returns the gateway's own OIDC callback URL. It must point at this
// gateway (not the issuer), and must match between the auth request and the
// token exchange.
func (p *PortalServer) redirectURI(r *http.Request) string {
	base := strings.TrimSuffix(p.config.PublicBaseURL, "/")
	if base == "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		base = fmt.Sprintf("%s://%s", scheme, r.Host)
	}
	return base + "/api/auth/sso/callback"
}

// randomState returns a URL-safe random string for OIDC CSRF protection.
func randomState() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateClientToken returns a cryptographically random bearer token.
func generateClientToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "mcp_" + base64.RawURLEncoding.EncodeToString(b)
}

// audienceContains reports whether the OIDC "aud" claim (string or []string)
// includes the expected client ID.
func audienceContains(aud interface{}, clientID string) bool {
	if clientID == "" {
		return false
	}
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

func (p *PortalServer) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	if p.config.OIDCIssuer == "" {
		http.Error(w, `{"error":"SSO/OIDC not configured"}`, http.StatusBadRequest)
		return
	}

	// CSRF protection: bind the auth request to an unguessable state stored in a
	// short-lived cookie and echoed back on the callback.
	state := randomState()
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/api/auth/sso",
		MaxAge:   300,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	redirectURI := p.redirectURI(r)
	authURL := fmt.Sprintf("%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s",
		strings.TrimSuffix(p.config.OIDCIssuer, "/"),
		url.QueryEscape(p.config.OIDCClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape("openid profile email"),
		url.QueryEscape(state))

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (p *PortalServer) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	if p.config.OIDCIssuer == "" {
		http.Error(w, `{"error":"SSO/OIDC not configured"}`, http.StatusForbidden)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, `{"error":"missing code"}`, http.StatusBadRequest)
		return
	}

	// Verify the state parameter against the cookie to prevent login CSRF.
	stateCookie, err := r.Cookie("oidc_state")
	if err != nil || stateCookie.Value == "" ||
		subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(r.URL.Query().Get("state"))) != 1 {
		http.Error(w, `{"error":"invalid or missing state"}`, http.StatusBadRequest)
		return
	}
	// Clear the one-time state cookie.
	http.SetCookie(w, &http.Cookie{Name: "oidc_state", Path: "/api/auth/sso", MaxAge: -1})

	// Exchange the authorization code with the IDP token endpoint. The redirect_uri
	// must match the one sent in the auth request.
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", strings.TrimSuffix(p.config.OIDCIssuer, "/"))
	redirectURI := p.redirectURI(r)

	formVals := url.Values{}
	formVals.Set("grant_type", "authorization_code")
	formVals.Set("code", code)
	formVals.Set("redirect_uri", redirectURI)
	formVals.Set("client_id", p.config.OIDCClientID)
	formVals.Set("client_secret", p.config.OIDCClientSecret)

	resp, err := http.PostForm(tokenURL, formVals)
	if err != nil {
		http.Redirect(w, r, "/login?error=sso-exchange-failed", http.StatusFound)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Redirect(w, r, "/login?error=sso-invalid-code", http.StatusFound)
		return
	}

	var tokenResp struct {
		AccessSlice string `json:"access_token"`
		IDToken     string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		http.Redirect(w, r, "/login?error=sso-parse-failed", http.StatusFound)
		return
	}

	// Extract and validate claims from the ID token. NOTE: signature verification
	// against the issuer JWKS is a recommended follow-up; the token is obtained
	// server-to-server over TLS directly from the IdP token endpoint, and the
	// issuer / audience / expiry claims are validated below.
	username := "sso-user"
	if tokenResp.IDToken == "" {
		http.Redirect(w, r, "/login?error=sso-missing-id-token", http.StatusFound)
		return
	}

	parts := strings.Split(tokenResp.IDToken, ".")
	if len(parts) < 2 {
		http.Redirect(w, r, "/login?error=sso-malformed-id-token", http.StatusFound)
		return
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		http.Redirect(w, r, "/login?error=sso-parse-failed", http.StatusFound)
		return
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		http.Redirect(w, r, "/login?error=sso-parse-failed", http.StatusFound)
		return
	}

	// Validate issuer.
	if iss, _ := claims["iss"].(string); strings.TrimSuffix(iss, "/") != strings.TrimSuffix(p.config.OIDCIssuer, "/") {
		http.Redirect(w, r, "/login?error=sso-issuer-mismatch", http.StatusFound)
		return
	}
	// Validate audience contains our client ID.
	if !audienceContains(claims["aud"], p.config.OIDCClientID) {
		http.Redirect(w, r, "/login?error=sso-audience-mismatch", http.StatusFound)
		return
	}
	// Validate expiry.
	if exp, ok := claims["exp"].(float64); !ok || time.Now().Unix() >= int64(exp) {
		http.Redirect(w, r, "/login?error=sso-token-expired", http.StatusFound)
		return
	}

	if prefUser, ok := claims["preferred_username"].(string); ok && prefUser != "" {
		username = prefUser
	} else if email, ok := claims["email"].(string); ok && email != "" {
		username = email
	}

	role := p.config.OIDCDefaultRole
	if role == "" {
		role = "viewer"
	}
	token, err := p.authManager.GenerateJWT(username, role)
	if err != nil {
		http.Redirect(w, r, "/login?error=sso-generation-failed", http.StatusFound)
		return
	}

	// Redirect back to portal dashboard with the JWT token
	http.Redirect(w, r, fmt.Sprintf("/#token=%s&username=%s", token, username), http.StatusFound)
}

func (p *PortalServer) handleConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// GET all connections
	if r.Method == http.MethodGet && (r.URL.Path == "/api/connections" || r.URL.Path == "/api/connections/") {
		conns, err := p.db.GetConnections(r.Context())
		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(conns)
		return
	}

	// POST save connection
	if r.Method == http.MethodPost {
		var conn storage.APIConnection
		if err := json.NewDecoder(r.Body).Decode(&conn); err != nil {
			http.Error(w, `{"error":"invalid payload"}`, http.StatusBadRequest)
			return
		}

		if conn.ID == "" {
			conn.ID = uuid.New().String()
		}

		if err := p.db.SaveConnection(r.Context(), &conn); err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(conn)
		return
	}

	// DELETE connection
	if r.Method == http.MethodDelete {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 || parts[3] == "" {
			http.Error(w, `{"error":"missing ID"}`, http.StatusBadRequest)
			return
		}
		id := parts[3]
		if err := p.db.DeleteConnection(r.Context(), id); err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (p *PortalServer) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// GET all endpoints or filter by connection ID
	if r.Method == http.MethodGet {
		connID := r.URL.Query().Get("connection_id")
		var eps []*storage.APIEndpoint
		var err error

		if connID != "" {
			eps, err = p.db.GetEndpoints(r.Context(), connID)
		} else {
			eps, err = p.db.GetAllEndpoints(r.Context())
		}

		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(eps)
		return
	}

	// POST save endpoint
	if r.Method == http.MethodPost {
		var ep storage.APIEndpoint
		if err := json.NewDecoder(r.Body).Decode(&ep); err != nil {
			http.Error(w, `{"error":"invalid payload"}`, http.StatusBadRequest)
			return
		}

		if ep.ID == "" {
			ep.ID = uuid.New().String()
		}

		if err := p.db.SaveEndpoint(r.Context(), &ep); err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(ep)
		return
	}

	// DELETE endpoint
	if r.Method == http.MethodDelete {
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 || parts[3] == "" {
			http.Error(w, `{"error":"missing ID"}`, http.StatusBadRequest)
			return
		}
		id := parts[3]
		if err := p.db.DeleteEndpoint(r.Context(), id); err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (p *PortalServer) handleVault(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// GET: List all keys in the Vault (values redacted for security)
	if r.Method == http.MethodGet {
		keys, err := p.vault.ListSecrets(r.Context())
		if err != nil {
			http.Error(w, `{"error":"failed to list vault keys"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(keys)
		return
	}

	// POST: Store/Update a secret key-value pair in the Vault
	if r.Method == http.MethodPost {
		var req struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Key == "" || req.Value == "" {
			http.Error(w, `{"error":"key and value are required"}`, http.StatusBadRequest)
			return
		}

		err := p.vault.SetSecret(r.Context(), req.Key, req.Value)
		if err != nil {
			http.Error(w, `{"error":"failed to store secret"}`, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"status":"success"}`)
		return
	}

	// DELETE: Remove a secret key from the Vault
	if r.Method == http.MethodDelete {
		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, `{"error":"missing key parameter"}`, http.StatusBadRequest)
			return
		}

		err := p.vault.DeleteSecret(r.Context(), key)
		if err != nil {
			http.Error(w, `{"error":"failed to delete secret"}`, http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (p *PortalServer) handleSettings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Expose only non-sensitive status booleans. Filesystem paths, client IDs,
	// and provider internals are not disclosed.
	settings := map[string]interface{}{
		"port":                  p.config.Port,
		"vault_provider":        p.config.VaultProvider,
		"jwt_secret_configured": p.config.JWTSecret != "",
		"oidc_configured":       p.config.OIDCIssuer != "",
		"tls_enabled":           p.config.TLSCertPath != "",
		"mtls_enabled":          p.config.ClientCAPath != "",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (p *PortalServer) handleOperationalStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	conns, err := p.db.GetConnections(r.Context())
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	type ConnectionHealth struct {
		Name      string `json:"name"`
		URL       string `json:"url"`
		Enabled   bool   `json:"enabled"`
		Status    string `json:"status"`
		LatencyMS int64  `json:"latency_ms"`
	}

	healths := make([]ConnectionHealth, len(conns))
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 1 * time.Second}

	for i, conn := range conns {
		wg.Add(1)
		go func(idx int, c *storage.APIConnection) {
			defer wg.Done()
			h := ConnectionHealth{
				Name:    c.Name,
				URL:     c.BaseURL,
				Enabled: c.Enabled,
			}

			if !c.Enabled {
				h.Status = "DISABLED"
				h.LatencyMS = 0
				healths[idx] = h
				return
			}

			start := time.Now()
			resp, err := client.Get(c.BaseURL)
			elapsed := time.Since(start).Milliseconds()

			if err != nil {
				h.Status = "UNREACHABLE"
				h.LatencyMS = elapsed
			} else {
				resp.Body.Close()
				h.Status = fmt.Sprintf("OK (HTTP %d)", resp.StatusCode)
				h.LatencyMS = elapsed
			}
			healths[idx] = h
		}(i, conn)
	}

	wg.Wait()

	activeSessions := 0
	activeQueries := int64(0)
	if p.mcpServer != nil {
		activeSessions = p.mcpServer.GetActiveSessionCount()
		activeQueries = p.mcpServer.GetActiveQueries()
	}

	stats := map[string]interface{}{
		"connected_users":    activeSessions,
		"active_queries":     activeQueries,
		"connections_health": healths,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (p *PortalServer) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logs, err := p.db.GetAuditLogs(r.Context())
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logs)
}

func (p *PortalServer) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	conns, err := p.db.GetConnections(r.Context())
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	endpoints, err := p.db.GetAllEndpoints(r.Context())
	if err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	connMap := make(map[string]*storage.APIConnection)
	for _, c := range conns {
		connMap[c.ID] = c
	}

	paths := make(map[string]map[string]interface{})

	// 1. Pre-populate administrative/monitoring REST APIs documentation
	adminPathsJSON := `{
		"/api/auth/login": {
			"post": {
				"tags": ["Gateway Administration"],
				"summary": "Authenticate Portal User",
				"description": "Exchanges admin credentials for a JWT token",
				"requestBody": {
					"required": true,
					"content": {
						"application/json": {
							"schema": {
								"type": "object",
								"properties": {
									"username": { "type": "string" },
									"password": { "type": "string" }
								},
								"required": ["username", "password"]
							}
						}
					}
				},
				"responses": {
					"200": { "description": "Successfully authenticated" },
					"401": { "description": "Invalid credentials" }
				}
			}
		},
		"/api/connections": {
			"get": {
				"tags": ["Gateway Administration"],
				"summary": "List API Connections",
				"description": "Returns list of registered target connections",
				"responses": {
					"200": { "description": "Array of connections" }
				}
			},
			"post": {
				"tags": ["Gateway Administration"],
				"summary": "Save/Create API Connection",
				"description": "Registers or updates a connection",
				"requestBody": {
					"required": true,
					"content": {
						"application/json": {
							"schema": {
								"type": "object",
								"properties": {
									"id": { "type": "string" },
									"name": { "type": "string" },
									"description": { "type": "string" },
									"base_url": { "type": "string" },
									"auth_type": { "type": "string" },
									"auth_secret_ref": { "type": "string" },
									"enabled": { "type": "boolean" },
									"tool_prefix": { "type": "string" }
								},
								"required": ["name", "base_url"]
							}
						}
					}
				},
				"responses": {
					"200": { "description": "Connection successfully saved" }
				}
			}
		},
		"/api/connections/{id}": {
			"delete": {
				"tags": ["Gateway Administration"],
				"summary": "Delete API Connection",
				"description": "Deletes a connection and all its endpoints",
				"parameters": [
					{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
				],
				"responses": {
					"204": { "description": "Connection deleted" }
				}
			}
		},
		"/api/endpoints": {
			"get": {
				"tags": ["Gateway Administration"],
				"summary": "List Tool Endpoints",
				"description": "Returns all registered endpoints/tools",
				"responses": {
					"200": { "description": "Array of tools" }
				}
			},
			"post": {
				"tags": ["Gateway Administration"],
				"summary": "Save/Create Tool Endpoint",
				"description": "Registers or updates a tool endpoint",
				"requestBody": {
					"required": true,
					"content": {
						"application/json": {
							"schema": {
								"type": "object",
								"properties": {
									"id": { "type": "string" },
									"connection_id": { "type": "string" },
									"tool_name": { "type": "string" },
									"tool_description": { "type": "string" },
									"path": { "type": "string" },
									"method": { "type": "string" },
									"parameters_schema": { "type": "string" },
									"template": { "type": "string" }
								},
								"required": ["connection_id", "tool_name", "path"]
							}
						}
					}
				},
				"responses": {
					"200": { "description": "Endpoint successfully saved" }
				}
			}
		},
		"/api/endpoints/{id}": {
			"delete": {
				"tags": ["Gateway Administration"],
				"summary": "Delete Tool Endpoint",
				"description": "Deletes a registered endpoint/tool",
				"parameters": [
					{ "name": "id", "in": "path", "required": true, "schema": { "type": "string" } }
				],
				"responses": {
					"204": { "description": "Endpoint deleted" }
				}
			}
		},
		"/api/vault": {
			"get": {
				"tags": ["Gateway Administration"],
				"summary": "List Vault Keys",
				"description": "Lists all keys in the Vault (values redacted)",
				"responses": {
					"200": { "description": "List of vault keys" }
				}
			},
			"post": {
				"tags": ["Gateway Administration"],
				"summary": "Write Vault Secret",
				"description": "Stores a credentials token key-value pair in the vault",
				"requestBody": {
					"required": true,
					"content": {
						"application/json": {
							"schema": {
								"type": "object",
								"properties": {
									"key": { "type": "string" },
									"value": { "type": "string" }
								},
								"required": ["key", "value"]
							}
						}
					}
				},
				"responses": {
					"200": { "description": "Secret stored" }
				}
			},
			"delete": {
				"tags": ["Gateway Administration"],
				"summary": "Delete Vault Secret",
				"description": "Removes a secret key from the vault",
				"parameters": [
					{ "name": "key", "in": "query", "required": true, "schema": { "type": "string" } }
				],
				"responses": {
					"204": { "description": "Secret deleted" }
				}
			}
		},
		"/api/logs": {
			"get": {
				"tags": ["Gateway Administration"],
				"summary": "List Audit Logs",
				"description": "Fetch last 100 tool executions history",
				"responses": {
					"200": { "description": "Array of audit logs" }
				}
			}
		},
		"/api/settings": {
			"get": {
				"tags": ["Gateway Administration"],
				"summary": "Get Server Settings",
				"description": "Retrieve active configuration files and services setup",
				"responses": {
					"200": { "description": "Server settings object" }
				}
			}
		},
		"/metrics": {
			"get": {
				"tags": ["Gateway Monitoring"],
				"summary": "Scrape Telemetry Metrics",
				"description": "Returns scrapable Prometheus stats",
				"responses": {
					"200": { "description": "Prometheus raw stream output" }
				}
			}
		}
	}`
	_ = json.Unmarshal([]byte(adminPathsJSON), &paths)

	// 2. Populate proxied tool endpoints
	for _, ep := range endpoints {
		conn, exists := connMap[ep.ConnectionID]
		if !exists || !conn.Enabled {
			continue
		}

		// Prevent clashing paths in the consolidated gateway docs
		namespaceSlug := strings.ToLower(strings.ReplaceAll(conn.Name, " ", "-"))
		docPath := fmt.Sprintf("/connections/%s/tools/%s", namespaceSlug, ep.ToolName)

		methodLower := strings.ToLower(ep.Method)

		var parameters []map[string]interface{}
		if ep.ParametersSchema != "" {
			var parsedSchema struct {
				Properties map[string]struct {
					Type        string `json:"type"`
					Description string `json:"description"`
				} `json:"properties"`
				Required []string `json:"required"`
			}

			if json.Unmarshal([]byte(ep.ParametersSchema), &parsedSchema) == nil {
				for name, prop := range parsedSchema.Properties {
					required := false
					for _, req := range parsedSchema.Required {
						if req == name {
							required = true
							break
						}
					}

					param := map[string]interface{}{
						"name":        name,
						"in":          "query",
						"required":    required,
						"description": prop.Description,
						"schema": map[string]string{
							"type": prop.Type,
						},
					}

					if strings.Contains(ep.Path, fmt.Sprintf("{{%s}}", name)) {
						param["in"] = "path"
						param["required"] = true
					}

					parameters = append(parameters, param)
				}
			}
		}

		op := map[string]interface{}{
			"tags":        []string{"Exposed MCP Tools - " + conn.Name},
			"summary":     ep.ToolDescription,
			"description": fmt.Sprintf("MCP Tool: %s. Proxied to downstream target: %s%s", ep.ToolName, conn.BaseURL, ep.Path),
			"operationId": ep.ToolName,
			"parameters":  parameters,
			"responses": map[string]interface{}{
				"200": map[string]interface{}{
					"description": "Successful call execution",
					"content": map[string]interface{}{
						"application/json": map[string]interface{}{
							"schema": map[string]interface{}{
								"type": "object",
							},
						},
					},
				},
			},
		}

		if paths[docPath] == nil {
			paths[docPath] = make(map[string]interface{})
		}
		paths[docPath][methodLower] = op
	}

	doc := map[string]interface{}{
		"openapi": "3.0.0",
		"info": map[string]interface{}{
			"title":       "Janus API Gateway Consolidated Reference",
			"description": "Unified OpenAPI reference mapping all active connection endpoints exposed as MCP tools alongside Gateway administration APIs.",
			"version":     "1.0.0",
		},
		"paths": paths,
		"components": map[string]interface{}{
			"securitySchemes": map[string]interface{}{
				"BearerAuth": map[string]interface{}{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
			},
		},
		"security": []map[string][]string{
			{
				"BearerAuth": {},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc)
}

func (p *PortalServer) handleTokens(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// GET all client tokens
	if r.Method == http.MethodGet {
		tokens, err := p.db.GetClientTokens(r.Context())
		if err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(tokens)
		return
	}

	// POST save/create client token
	if r.Method == http.MethodPost {
		var token storage.ClientToken
		if err := json.NewDecoder(r.Body).Decode(&token); err != nil {
			http.Error(w, `{"error":"invalid payload"}`, http.StatusBadRequest)
			return
		}

		if token.ClientName == "" {
			http.Error(w, `{"error":"client_name is required"}`, http.StatusBadRequest)
			return
		}

		// Generate a strong random token when the caller does not supply one.
		// The plaintext is returned exactly once below; storage keeps only its hash.
		if token.Token == "" {
			token.Token = generateClientToken()
		}
		plaintext := token.Token

		if err := p.db.SaveClientToken(r.Context(), &token); err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}

		// Surface the plaintext token a single time; it cannot be recovered later.
		json.NewEncoder(w).Encode(map[string]interface{}{
			"client_name": token.ClientName,
			"client_role": token.ClientRole,
			"scopes":      token.Scopes,
			"enabled":     token.Enabled,
			"token":       plaintext,
			"warning":     "Store this token now; it will not be shown again.",
		})
		return
	}

	// DELETE client token (by client_name, since plaintext tokens are not stored).
	if r.Method == http.MethodDelete {
		if name := r.URL.Query().Get("client_name"); name != "" {
			if err := p.db.DeleteClientTokenByName(r.Context(), name); err != nil {
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if token := r.URL.Query().Get("token"); token != "" {
			if err := p.db.DeleteClientToken(r.Context(), token); err != nil {
				http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Error(w, `{"error":"missing client_name parameter"}`, http.StatusBadRequest)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (p *PortalServer) handleMockTradeVolume(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	memberID := r.URL.Query().Get("member_id")
	if memberID == "" {
		memberID = "MEM-LCH-001"
	}
	date := r.URL.Query().Get("date")
	if date == "" {
		date = "2026-06-29"
	}

	response := map[string]interface{}{
		"date":             date,
		"member_id":        memberID,
		"total_volume_usd": 12450800000.50,
		"trade_count":      8420,
		"clearing_status":  "Active",
		"currency_breakdown": map[string]float64{
			"USD": 6500000000.00,
			"EUR": 4200000000.00,
			"GBP": 1750800000.50,
		},
		"notes": "DPG Trade Volume details for LCH Ltd clearing services.",
	}

	json.NewEncoder(w).Encode(response)
}

func (p *PortalServer) handleMockNonCashCollateral(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	memberID := r.URL.Query().Get("member_id")
	if memberID == "" {
		memberID = "MEM-LCH-001"
	}

	response := []map[string]interface{}{
		{
			"isin":                 "US912828GD97",
			"asset_name":           "US TREASURY N/B 2.000% 2026-11-15",
			"market_value_eur":     25000000.00,
			"haircut_pct":          2.0,
			"collateral_value_eur": 24500000.00,
			"asset_type":           "Government Bond",
			"issuer":               "US Government",
			"member_id":            memberID,
		},
		{
			"isin":                 "DE0001102408",
			"asset_name":           "GERMAN BUND 0.000% 2026-08-15",
			"market_value_eur":     18000000.00,
			"haircut_pct":          1.5,
			"collateral_value_eur": 17730000.00,
			"asset_type":           "Government Bond",
			"issuer":               "German Federal Republic",
			"member_id":            memberID,
		},
	}

	json.NewEncoder(w).Encode(response)
}
