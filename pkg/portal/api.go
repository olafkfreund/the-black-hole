package portal

import (
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/calitti/mcp-api-gateway/pkg/auth"
	"github.com/calitti/mcp-api-gateway/pkg/config"
	"github.com/calitti/mcp-api-gateway/pkg/storage"
	"github.com/calitti/mcp-api-gateway/pkg/vault"
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
}

func NewPortalServer(db *storage.DB, vp vault.VaultProvider, am *auth.AuthManager, cfg *config.Config) *PortalServer {
	return &PortalServer{
		db:          db,
		vault:       vp,
		authManager: am,
		config:      cfg,
	}
}

func (p *PortalServer) RegisterRoutes(mux *http.ServeMux) {
	// Authentication
	mux.HandleFunc("/api/auth/login", p.handleLogin)
	mux.HandleFunc("/api/auth/sso/login", p.handleSSOLogin)
	mux.HandleFunc("/api/auth/sso/callback", p.handleSSOCallback)

	// API Connections (JWT protected)
	mux.HandleFunc("/api/connections", p.authManager.PortalAuthMiddleware(p.handleConnections))
	mux.HandleFunc("/api/connections/", p.authManager.PortalAuthMiddleware(p.handleConnections))

	// API Endpoints (JWT protected)
	mux.HandleFunc("/api/endpoints", p.authManager.PortalAuthMiddleware(p.handleEndpoints))
	mux.HandleFunc("/api/endpoints/", p.authManager.PortalAuthMiddleware(p.handleEndpoints))

	// Vault Secrets Management (JWT protected)
	mux.HandleFunc("/api/vault", p.authManager.PortalAuthMiddleware(p.handleVault))

	// Audit Logs (JWT protected)
	mux.HandleFunc("/api/logs", p.authManager.PortalAuthMiddleware(p.handleAuditLogs))

	// Settings (JWT protected)
	mux.HandleFunc("/api/settings", p.authManager.PortalAuthMiddleware(p.handleSettings))

	// Client Tokens (JWT protected)
	mux.HandleFunc("/api/tokens", p.authManager.PortalAuthMiddleware(p.handleTokens))

	// OpenAPI unified reference (JWT protected)
	mux.HandleFunc("/api/openapi.json", p.authManager.PortalAuthMiddleware(p.handleOpenAPI))

	// Serving the SPA Frontend
	staticFS, err := fs.Sub(assets, "static")
	if err != nil {
		panic(fmt.Sprintf("failed to load embedded static assets: %v", err))
	}
	fileServer := http.FileServer(http.FS(staticFS))
	
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// If path doesn't point to a file with extension, serve index.html (SPA Router support)
		if !strings.Contains(r.URL.Path, ".") {
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

	// Simple fallback admin credential checks for air-gapped/initial setups
	// In production, configure SSO/OIDC
	if credentials.Username == "admin" && credentials.Password == "admin-gateway-secret" {
		token, err := p.authManager.GenerateJWT(credentials.Username, "admin")
		if err != nil {
			http.Error(w, `{"error":"failed to generate token"}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"token":"%s","username":"admin"}`, token)
		return
	}

	http.Error(w, `{"error":"invalid credentials"}`, http.StatusUnauthorized)
}

func (p *PortalServer) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	if p.config.OIDCIssuer == "" {
		http.Error(w, `{"error":"SSO/OIDC not configured"}`, http.StatusBadRequest)
		return
	}

	// Build OIDC authorization URI
	redirectURI := fmt.Sprintf("%s/api/auth/sso/callback", p.config.OIDCIssuer)
	authURL := fmt.Sprintf("%s/protocol/openid-connect/auth?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+profile+email",
		p.config.OIDCIssuer, p.config.OIDCClientID, redirectURI)

	http.Redirect(w, r, authURL, http.StatusFound)
}

func (p *PortalServer) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, `{"error":"missing code"}`, http.StatusBadRequest)
		return
	}

	// In full production, you verify the authorization code with the IDP token endpoint:
	// resp, err := http.PostForm(p.config.OIDCIssuer + "/protocol/openid-connect/token", ...)
	// Here, we simulate token swap and claim reading
	username := "sso-user" // Read from IDP JWT access token claims

	token, err := p.authManager.GenerateJWT(username, "user")
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
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":"failed to list vault keys: %v"}`, err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":"failed to store secret: %v"}`, err), http.StatusInternalServerError)
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
			http.Error(w, fmt.Sprintf(`{"error":"failed to delete secret: %v"}`, err), http.StatusInternalServerError)
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

	settings := map[string]interface{}{
		"port":                  p.config.Port,
		"database_path":         p.config.DatabasePath,
		"vault_provider":        p.config.VaultProvider,
		"vault_local_path":      p.config.VaultLocalPath,
		"jwt_secret_configured": p.config.JWTSecret != "",
		"oidc_issuer":           p.config.OIDCIssuer,
		"oidc_client_id":        p.config.OIDCClientID,
		"tls_cert_path":         p.config.TLSCertPath,
		"client_ca_path":        p.config.ClientCAPath,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(settings)
}

func (p *PortalServer) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	logs, err := p.db.GetAuditLogs(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
		return
	}

	endpoints, err := p.db.GetAllEndpoints(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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
			"title":       "MCP API Gateway Consolidated Reference",
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
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
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

		if token.Token == "" {
			http.Error(w, `{"error":"token is required"}`, http.StatusBadRequest)
			return
		}
		if token.ClientName == "" {
			http.Error(w, `{"error":"client_name is required"}`, http.StatusBadRequest)
			return
		}

		if err := p.db.SaveClientToken(r.Context(), &token); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(token)
		return
	}

	// DELETE client token
	if r.Method == http.MethodDelete {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, `{"error":"missing token parameter"}`, http.StatusBadRequest)
			return
		}
		if err := p.db.DeleteClientToken(r.Context(), token); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%v"}`, err), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}
