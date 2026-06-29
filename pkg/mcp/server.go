package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/calitti/mcp-api-gateway/pkg/auth"
	"github.com/calitti/mcp-api-gateway/pkg/gateway"
	"github.com/calitti/mcp-api-gateway/pkg/storage"
	"github.com/calitti/mcp-api-gateway/pkg/telemetry"
	"github.com/calitti/mcp-api-gateway/pkg/vault"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// MCP JSON-RPC structs
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ListToolsResponse struct {
	Tools []Tool `json:"tools"`
}

type Tool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

type CallToolRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type CallToolResponse struct {
	Content []Content `json:"content"`
}

type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Session represents an SSE client session
type Session struct {
	ID             string
	SSEWriter      http.ResponseWriter
	Flusher        http.Flusher
	Ctx            context.Context
	ClientIdentity string
	ClientRole     string
	Scopes         []string
}

type MCPServer struct {
	db            *storage.DB
	client        *gateway.GatewayClient
	vault         vault.VaultProvider
	authManager   *auth.AuthManager
	sessions      map[string]*Session
	mu            sync.RWMutex
	activeQueries int64
}

func NewMCPServer(db *storage.DB, client *gateway.GatewayClient, vp vault.VaultProvider, am *auth.AuthManager) *MCPServer {
	return &MCPServer{
		db:          db,
		client:      client,
		vault:       vp,
		authManager: am,
		sessions:    make(map[string]*Session),
	}
}

func (s *MCPServer) GetActiveSessionCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

func (s *MCPServer) GetActiveQueries() int64 {
	return atomic.LoadInt64(&s.activeQueries)
}

func matchScope(toolName string, scopes []string) bool {
	for _, scope := range scopes {
		if scope == "*" {
			return true
		}
		if strings.HasSuffix(scope, "*") {
			prefix := scope[:len(scope)-1]
			if strings.HasPrefix(toolName, prefix) {
				return true
			}
		}
		if toolName == scope {
			return true
		}
	}
	return false
}

// StartStdioMode runs the server over Stdio (useful for Claude Desktop integration)
func (s *MCPServer) StartStdioMode(ctx context.Context) {
	dec := json.NewDecoder(os.Stdin)
	enc := json.NewEncoder(os.Stdout)

	clientIdentity := "master"
	clientRole := "admin"
	clientScopes := []string{"*"}

	token := os.Getenv("MCP_GATEWAY_TOKEN")
	if token != "" {
		if s.authManager.VerifyGatewayToken(token) {
			clientIdentity = "master"
			clientRole = "admin"
			clientScopes = []string{"*"}
		} else {
			ct, err := s.db.GetClientToken(ctx, token)
			if err == nil && ct != nil && ct.Enabled {
				clientIdentity = ct.ClientName
				clientRole = ct.ClientRole
				clientScopes = nil
				for _, sc := range strings.Split(ct.Scopes, ",") {
					trimmed := strings.TrimSpace(sc)
					if trimmed != "" {
						clientScopes = append(clientScopes, trimmed)
					}
				}
			} else {
				log.Printf("Stdio auth error: Invalid token configured in MCP_GATEWAY_TOKEN")
				clientIdentity = "invalid-token"
				clientRole = "unauthenticated"
				clientScopes = []string{}
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
			var req JSONRPCRequest
			if err := dec.Decode(&req); err != nil {
				if err == io.EOF {
					return
				}
				log.Printf("Stdio decode error: %v", err)
				return
			}

			resp := s.handleRequest(ctx, clientIdentity, clientRole, clientScopes, &req)
			if err := enc.Encode(resp); err != nil {
				log.Printf("Stdio encode error: %v", err)
				return
			}
		}
	}
}

// ServeSSE handles the SSE endpoint connection
func (s *MCPServer) ServeSSE(w http.ResponseWriter, r *http.Request) {
	// Authenticate the gateway client
	token := r.URL.Query().Get("token")
	if token == "" {
		// Fallback to Authorization Header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			token = authHeader[7:]
		}
	}

	var clientIdentity string
	var clientRole string
	var clientScopes []string

	if s.authManager.VerifyGatewayToken(token) {
		clientIdentity = "master"
		clientRole = "admin"
		clientScopes = []string{"*"}
	} else {
		ct, err := s.db.GetClientToken(r.Context(), token)
		if err != nil || ct == nil || !ct.Enabled {
			http.Error(w, "Unauthorized: Invalid gateway token", http.StatusUnauthorized)
			return
		}
		clientIdentity = ct.ClientName
		clientRole = ct.ClientRole
		for _, sc := range strings.Split(ct.Scopes, ",") {
			trimmed := strings.TrimSpace(sc)
			if trimmed != "" {
				clientScopes = append(clientScopes, trimmed)
			}
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	sessionID := uuid.New().String()
	session := &Session{
		ID:             sessionID,
		SSEWriter:      w,
		Flusher:        flusher,
		Ctx:            r.Context(),
		ClientIdentity: clientIdentity,
		ClientRole:     clientRole,
		Scopes:         clientScopes,
	}

	s.mu.Lock()
	s.sessions[sessionID] = session
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
	}()

	// Send endpoint configuration redirect event to client
	// The client will use POST /messages?sessionId=sessionID to send RPC calls
	fmt.Fprintf(w, "event: endpoint\ndata: /messages?sessionId=%s\n\n", sessionID)
	flusher.Flush()

	// Keep connection alive
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-session.Ctx.Done():
			return
		case <-ticker.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

// ServeMessages handles incoming JSON-RPC calls over HTTP POST for SSE clients
func (s *MCPServer) ServeMessages(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("sessionId")
	s.mu.RLock()
	session, active := s.sessions[sessionID]
	s.mu.RUnlock()

	if !active {
		http.Error(w, "Session not found or expired", http.StatusBadRequest)
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON-RPC request", http.StatusBadRequest)
		return
	}

	resp := s.handleRequest(r.Context(), session.ClientIdentity, session.ClientRole, session.Scopes, &req)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *MCPServer) handleRequest(ctx context.Context, clientIdentity string, clientRole string, clientScopes []string, req *JSONRPCRequest) *JSONRPCResponse {
	resp := &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
	}

	switch req.Method {
	case "initialize":
		// Return capabilities
		resp.Result = map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "mcp-api-gateway",
				"version": "1.0.0",
			},
		}

	case "tools/list":
		tools, err := s.listTools(ctx, clientRole, clientScopes)
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32603, Message: err.Error()}
		} else {
			resp.Result = ListToolsResponse{Tools: tools}
		}

	case "tools/call":
		var callReq CallToolRequest
		if err := json.Unmarshal(req.Params, &callReq); err != nil {
			resp.Error = &JSONRPCError{Code: -32602, Message: "Invalid tools/call params"}
			return resp
		}

		// Enforce role-based checks and scope-based checks
		if strings.HasPrefix(callReq.Name, "admin_") && clientRole != "admin" {
			resp.Error = &JSONRPCError{Code: -32601, Message: fmt.Sprintf("Method %s not found (Unauthorized: Admin role required)", callReq.Name)}
			return resp
		}
		if !matchScope(callReq.Name, clientScopes) {
			resp.Error = &JSONRPCError{Code: -32601, Message: fmt.Sprintf("Method %s not found (Unauthorized: Scope matching failed)", callReq.Name)}
			return resp
		}

		startTime := time.Now()
		atomic.AddInt64(&s.activeQueries, 1)
		result, err := s.callTool(ctx, callReq.Name, callReq.Arguments)
		atomic.AddInt64(&s.activeQueries, -1)
		duration := time.Since(startTime).Milliseconds()

		logID := uuid.New().String()
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32603, Message: err.Error()}
			_ = s.db.LogAudit(ctx, logID, clientIdentity, callReq.Name, "failure", duration, err.Error())
		} else {
			resp.Result = CallToolResponse{
				Content: []Content{
					{Type: "text", Text: result},
				},
			}
			_ = s.db.LogAudit(ctx, logID, clientIdentity, callReq.Name, "success", duration, "")
		}

	default:
		resp.Error = &JSONRPCError{
			Code:    -32601,
			Message: fmt.Sprintf("Method %s not found", req.Method),
		}
	}

	return resp
}

func (s *MCPServer) listTools(ctx context.Context, clientRole string, clientScopes []string) ([]Tool, error) {
	endpoints, err := s.db.GetAllEndpoints(ctx)
	if err != nil {
		return nil, err
	}

	conns, err := s.db.GetConnections(ctx)
	if err != nil {
		return nil, err
	}

	connMap := make(map[string]*storage.APIConnection)
	for _, c := range conns {
		connMap[c.ID] = c
	}

	var mcpTools []Tool
	for _, ep := range endpoints {
		conn, exists := connMap[ep.ConnectionID]
		if !exists || !conn.Enabled {
			continue
		}

		// Prepend connection prefix if configured (solves namespace conflicts)
		toolName := ep.ToolName
		if conn.ToolPrefix != "" {
			toolName = conn.ToolPrefix + toolName
		}

		// Enforce scope check
		if !matchScope(toolName, clientScopes) {
			continue
		}

		var schemaMap map[string]interface{}
		if ep.ParametersSchema != "" {
			if err := json.Unmarshal([]byte(ep.ParametersSchema), &schemaMap); err != nil {
				// Fallback to empty schema on error
				schemaMap = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
			}
		} else {
			schemaMap = map[string]interface{}{"type": "object", "properties": map[string]interface{}{}}
		}

		mcpTools = append(mcpTools, Tool{
			Name:        toolName,
			Description: ep.ToolDescription,
			InputSchema: schemaMap,
		})
	}

	// Expose Administrative Management Tools natively via MCP only if role is admin
	if clientRole == "admin" {
		if matchScope("admin_add_connection", clientScopes) {
			mcpTools = append(mcpTools, Tool{
				Name:        "admin_add_connection",
				Description: "Administratively register a new target API Connection into the Gateway.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"name":            map[string]interface{}{"type": "string", "description": "Human name for connection"},
						"base_url":        map[string]interface{}{"type": "string", "description": "Base target URL, e.g. https://api.stripe.com"},
						"auth_type":       map[string]interface{}{"type": "string", "description": "none, basic, bearer, custom_headers"},
						"auth_secret_ref": map[string]interface{}{"type": "string", "description": "Secret path inside the vault proxy"},
						"tool_prefix":     map[string]interface{}{"type": "string", "description": "Optional namespacing prefix prepended to all tools"},
						"enabled":         map[string]interface{}{"type": "boolean", "description": "Active state"},
					},
					"required": []string{"name", "base_url", "auth_type"},
				},
			})
		}
		if matchScope("admin_add_endpoint", clientScopes) {
			mcpTools = append(mcpTools, Tool{
				Name:        "admin_add_endpoint",
				Description: "Administratively expose a target HTTP endpoint path as an MCP tool.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"connection_id":     map[string]interface{}{"type": "string", "description": "Target API connection ID UUID"},
						"tool_name":         map[string]interface{}{"type": "string", "description": "Exposed tool method identifier, e.g. get_billing_records"},
						"tool_description":  map[string]interface{}{"type": "string", "description": "Description explaining when the LLM should invoke this tool"},
						"path":              map[string]interface{}{"type": "string", "description": "Endpoint URI path, e.g. /v1/records/{{id}}"},
						"method":            map[string]interface{}{"type": "string", "description": "GET, POST, PUT, DELETE"},
						"parameters_schema": map[string]interface{}{"type": "string", "description": "JSON Schema string defining expected variables"},
						"template":          map[string]interface{}{"type": "string", "description": "Optional JSON post template body mapping parameters"},
					},
					"required": []string{"connection_id", "tool_name", "tool_description", "path", "method"},
				},
			})
		}
		if matchScope("admin_register_vault_secret", clientScopes) {
			mcpTools = append(mcpTools, Tool{
				Name:        "admin_register_vault_secret",
				Description: "Administratively insert secure private credentials directly into the integrated Vault.",
				InputSchema: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"key":   map[string]interface{}{"type": "string", "description": "Secret lookup path reference"},
						"value": map[string]interface{}{"type": "string", "description": "Plain private credential or JSON header map"},
					},
					"required": []string{"key", "value"},
				},
			})
		}
	}

	return mcpTools, nil
}

func (s *MCPServer) callTool(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	startTime := time.Now()

	// Start OpenTelemetry Tracer Span
	var span trace.Span
	if telemetry.Tracer != nil {
		ctx, span = telemetry.Tracer.Start(ctx, fmt.Sprintf("MCP Tool execution: %s", name))
		defer span.End()
	}

	var result string
	var execErr error

	// Direct routing to management tools
	if strings.HasPrefix(name, "admin_") {
		result, execErr = s.handleAdminTool(ctx, name, args)
	} else {
		// Fetch endpoints and connections dynamically
		endpoints, err := s.db.GetAllEndpoints(ctx)
		if err != nil {
			execErr = fmt.Errorf("failed to load endpoints: %w", err)
		} else {
			conns, err := s.db.GetConnections(ctx)
			if err != nil {
				execErr = fmt.Errorf("failed to load connections: %w", err)
			} else {
				connMap := make(map[string]*storage.APIConnection)
				for _, c := range conns {
					connMap[c.ID] = c
				}

				var matchedEP *storage.APIEndpoint
				var matchedConn *storage.APIConnection

				for _, ep := range endpoints {
					conn, exists := connMap[ep.ConnectionID]
					if !exists || !conn.Enabled {
						continue
					}

					resolvedName := ep.ToolName
					if conn.ToolPrefix != "" {
						resolvedName = conn.ToolPrefix + resolvedName
					}

					if resolvedName == name {
						matchedEP = ep
						matchedConn = conn
						break
					}
				}

				if matchedEP == nil {
					execErr = fmt.Errorf("tool %q not found or target connection is disabled", name)
				} else {
					result, execErr = s.client.ExecuteCall(ctx, matchedConn, matchedEP, args)
				}
			}
		}
	}

	// Capture metrics attributes
	status := "success"
	if execErr != nil {
		status = "failure"
		if span != nil {
			span.RecordError(execErr)
		}
	}
	duration := time.Since(startTime).Seconds()

	// Record OpenTelemetry metrics
	if telemetry.ToolCallsCounter != nil {
		telemetry.ToolCallsCounter.Add(ctx, 1, 
			metric.WithAttributes(
				attribute.String("tool_name", name),
				attribute.String("status", status),
			),
		)
	}
	if telemetry.ToolDurationHistogram != nil {
		telemetry.ToolDurationHistogram.Record(ctx, duration,
			metric.WithAttributes(
				attribute.String("tool_name", name),
			),
		)
	}

	return result, execErr
}

func (s *MCPServer) handleAdminTool(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	switch name {
	case "admin_add_connection":
		conn := &storage.APIConnection{
			Name:     fmt.Sprintf("%v", args["name"]),
			BaseURL:  fmt.Sprintf("%v", args["base_url"]),
			AuthType: fmt.Sprintf("%v", args["auth_type"]),
		}
		if ref, ok := args["auth_secret_ref"]; ok {
			conn.AuthSecretRef = fmt.Sprintf("%v", ref)
		}
		if prefix, ok := args["tool_prefix"]; ok {
			conn.ToolPrefix = fmt.Sprintf("%v", prefix)
		}
		conn.Enabled = true
		if en, ok := args["enabled"].(bool); ok {
			conn.Enabled = en
		}
		conn.ID = uuid.New().String()
		if err := s.db.SaveConnection(ctx, conn); err != nil {
			return "", fmt.Errorf("failed to register connection: %w", err)
		}
		return fmt.Sprintf("Successfully registered connection %q. ID: %s", conn.Name, conn.ID), nil

	case "admin_add_endpoint":
		ep := &storage.APIEndpoint{
			ConnectionID:    fmt.Sprintf("%v", args["connection_id"]),
			ToolName:        fmt.Sprintf("%v", args["tool_name"]),
			ToolDescription: fmt.Sprintf("%v", args["tool_description"]),
			Path:            fmt.Sprintf("%v", args["path"]),
			Method:          fmt.Sprintf("%v", args["method"]),
		}
		if schema, ok := args["parameters_schema"]; ok {
			ep.ParametersSchema = fmt.Sprintf("%v", schema)
		}
		if temp, ok := args["template"]; ok {
			ep.Template = fmt.Sprintf("%v", temp)
		}
		ep.ID = uuid.New().String()
		if err := s.db.SaveEndpoint(ctx, ep); err != nil {
			return "", fmt.Errorf("failed to register tool endpoint: %w", err)
		}
		return fmt.Sprintf("Successfully registered tool %q. ID: %s", ep.ToolName, ep.ID), nil

	case "admin_register_vault_secret":
		key := fmt.Sprintf("%v", args["key"])
		val := fmt.Sprintf("%v", args["value"])
		if err := s.vault.SetSecret(ctx, key, val); err != nil {
			return "", fmt.Errorf("failed to register vault secret: %w", err)
		}
		return fmt.Sprintf("Successfully stored secret reference %q", key), nil

	default:
		return "", fmt.Errorf("unknown admin management tool %q", name)
	}
}
