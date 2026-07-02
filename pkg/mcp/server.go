package mcp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/calitti/mcp-api-gateway/pkg/auth"
	"github.com/calitti/mcp-api-gateway/pkg/gateway"
	"github.com/calitti/mcp-api-gateway/pkg/oauth"
	"github.com/calitti/mcp-api-gateway/pkg/redaction"
	"github.com/calitti/mcp-api-gateway/pkg/storage"
	"github.com/calitti/mcp-api-gateway/pkg/telemetry"
	"github.com/calitti/mcp-api-gateway/pkg/toolintegrity"
	"github.com/calitti/mcp-api-gateway/pkg/vault"
	"github.com/google/uuid"
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
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id"`
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
	// Meta carries out-of-band tool metadata (e.g. the tool-pinning
	// definitionHash) under the MCP "_meta" convention. Omitted entirely
	// when there is nothing to report, so tool-pinning-unaware clients see
	// no change in shape.
	Meta map[string]interface{} `json:"_meta,omitempty"`
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
	TokenHash      string     // hash of the token presented at session creation
	writeMu        sync.Mutex // serializes writes to the SSE stream (keepalive + responses)
}

// writeEvent writes a raw SSE event to the stream, serialized so concurrent
// keepalives and RPC responses never interleave.
func (s *Session) writeEvent(event string) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	fmt.Fprint(s.SSEWriter, event)
	s.Flusher.Flush()
}

type MCPServer struct {
	db            storage.Store
	client        *gateway.GatewayClient
	vault         vault.VaultProvider
	authManager   *auth.AuthManager
	sessions      map[string]*Session
	mu            sync.RWMutex
	activeQueries int64
	corsOrigins   []string
	maxSessions   int
	auditCh       chan auditLogEntry

	// oauthValidator, when non-nil (via EnableOAuth), lets resolveAuth accept
	// a valid OAuth 2.1 access token as an alternative to the master/client
	// token, in addition to the existing gateway-token auth. Nil (default)
	// preserves current master/client-token-only behavior.
	oauthValidator    *oauth.Validator
	oauthChallengeCfg oauth.Config

	// redactor, when non-nil (via EnableRedaction), masks PII/secrets in
	// tool-call arguments before execution and in tool results before they
	// are returned to the client. Nil (default) disables redaction entirely.
	redactor *redaction.Redactor

	// toolPinningStrict, when true (via SetToolPinningStrict), refuses
	// tools/call for any tool whose live definition hash no longer matches
	// the DefinitionHash recorded on the endpoint. False (default) preserves
	// current behavior: tools/list still reports the hash, but calls are
	// never blocked on it.
	toolPinningStrict bool
}

// auditLogEntry captures a single tools/call audit record for async persistence.
type auditLogEntry struct {
	id       string
	identity string
	tool     string
	status   string
	duration int64
	errMsg   string
	// redaction is a "class=count,class=count" summary of any redaction
	// findings for this call (arguments + result combined). It never
	// contains matched values. Empty when redaction is disabled or found
	// nothing.
	redaction string
}

// envInt reads a positive integer from the named environment variable,
// falling back to def if unset, empty, or invalid.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func NewMCPServer(db storage.Store, client *gateway.GatewayClient, vp vault.VaultProvider, am *auth.AuthManager, corsOrigins []string) *MCPServer {
	s := &MCPServer{
		db:          db,
		client:      client,
		vault:       vp,
		authManager: am,
		sessions:    make(map[string]*Session),
		corsOrigins: corsOrigins,
		maxSessions: envInt("MCP_MAX_SESSIONS", 1000),
		auditCh:     make(chan auditLogEntry, 1000),
	}
	// Single background worker drains audit log writes so the hot tools/call
	// path never blocks on a DB INSERT.
	go s.auditWorker()
	return s
}

// EnableOAuth turns on OAuth 2.1 bearer-token acceptance alongside the
// existing master/client-token auth: resolveAuth will additionally accept
// any access token that validates against v (RFC 8707 audience + trusted
// issuer). challengeCfg is used to build the WWW-Authenticate challenge
// (RFC 9728 §5.1) on a 401. Off by default — pass v == nil to leave OAuth
// disabled (equivalent to never calling this method).
func (s *MCPServer) EnableOAuth(v *oauth.Validator, challengeCfg oauth.Config) {
	s.oauthValidator = v
	s.oauthChallengeCfg = challengeCfg
}

// EnableRedaction turns on PII/secret redaction of tool-call arguments
// (before execution) and tool results (before the response is returned to
// the client). Off by default — pass r == nil to leave redaction disabled.
func (s *MCPServer) EnableRedaction(r *redaction.Redactor) {
	s.redactor = r
}

// SetToolPinningStrict controls whether tools/call refuses to execute a
// tool whose live definition hash (see pkg/toolintegrity) no longer matches
// the DefinitionHash recorded on its endpoint. tools/list always reports
// the current hash regardless of this setting. Off by default.
func (s *MCPServer) SetToolPinningStrict(strict bool) {
	s.toolPinningStrict = strict
}

// auditWorker drains s.auditCh and persists each entry via db.LogAudit. It
// runs for the lifetime of the process (the channel is never closed).
func (s *MCPServer) auditWorker() {
	for e := range s.auditCh {
		// storage.DB.LogAudit has a fixed signature with no dedicated
		// redaction column, so fold the (value-free) class=count summary
		// into the existing error_message field rather than dropping it.
		msg := e.errMsg
		if e.redaction != "" {
			if msg != "" {
				msg = msg + "; redacted: " + e.redaction
			} else {
				msg = "redacted: " + e.redaction
			}
		}
		if err := s.db.LogAudit(context.Background(), e.id, e.identity, e.tool, e.status, e.duration, msg); err != nil {
			log.Printf("audit log write failed for tool %q: %v", e.tool, err)
		}
	}
}

// formatFindings renders redaction findings as a deterministic
// "class=count,class=count" summary for the audit log. It never includes
// the matched values themselves — only the detector class and hit count.
func formatFindings(findings []redaction.Finding) string {
	if len(findings) == 0 {
		return ""
	}
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, fmt.Sprintf("%s=%d", f.Class, f.Count))
	}
	return strings.Join(parts, ",")
}

// logAuditAsync enqueues an audit entry for background persistence. If the
// buffer is full, the entry is dropped (logged) rather than blocking the
// caller's request path.
func (s *MCPServer) logAuditAsync(entry auditLogEntry) {
	select {
	case s.auditCh <- entry:
	default:
		log.Printf("audit log dropped (buffer full): tool=%s status=%s identity=%s", entry.tool, entry.status, entry.identity)
	}
}

// sessionTokenHash hashes a presented token for constant-time session binding.
func sessionTokenHash(token string) string {
	return storage.HashToken(token)
}

// extractToken pulls a bearer token from the Authorization header, falling back
// to the query parameter (required by the MCP SSE transport convention).
func extractToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}
	return r.URL.Query().Get("token")
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

// resolveAuth maps a presented token to a client identity/role/scopes.
// Master GATEWAY_TOKEN → admin/*; an enabled DB client token → its
// role+scopes; and, when EnableOAuth has been called, a valid OAuth 2.1
// access token → its scopes, mapped to a non-admin "user" role (OAuth
// clients can never reach admin_-prefixed tools regardless of the token's
// own scopes — admin access is only ever granted via the master token or a
// client token explicitly provisioned with the admin role).
func (s *MCPServer) resolveAuth(ctx context.Context, token string) (identity, role string, scopes []string, ok bool) {
	if s.authManager.VerifyGatewayToken(token) {
		return "master", "admin", []string{"*"}, true
	}
	if ct, err := s.db.GetClientToken(ctx, token); err == nil && ct != nil && ct.Enabled {
		for _, sc := range strings.Split(ct.Scopes, ",") {
			if t := strings.TrimSpace(sc); t != "" {
				scopes = append(scopes, t)
			}
		}
		return ct.ClientName, ct.ClientRole, scopes, true
	}
	if s.oauthValidator != nil {
		if claims, err := s.oauthValidator.ValidateToken(ctx, token); err == nil {
			identity = claims.Subject
			if identity == "" {
				identity = "oauth-client"
			}
			return identity, "user", claims.Scopes, true
		}
	}
	return "", "", nil, false
}

// ServeStreamable implements the MCP Streamable HTTP transport (2025 spec): the
// client POSTs a JSON-RPC request and gets the JSON-RPC response in the body.
// It is STATELESS — each request is authenticated by its bearer token — so any
// replica can serve any request (no SSE-stream pinning). Used by Antigravity and
// by Claude Code when configured with type "http".
func (s *MCPServer) ServeStreamable(w http.ResponseWriter, r *http.Request) {
	if origin := s.allowedOrigin(r); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
	identity, role, scopes, ok := s.resolveAuth(r.Context(), extractToken(r))
	if !ok {
		s.writeUnauthorized(w)
		return
	}
	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON-RPC request", http.StatusBadRequest)
		return
	}
	// Notifications (no id) get no response.
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	resp := s.handleRequest(r.Context(), identity, role, scopes, &req)
	// Supply a session id on initialize for clients that track one (we stay stateless).
	if req.Method == "initialize" {
		w.Header().Set("Mcp-Session-Id", uuid.New().String())
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ServeSSE handles the legacy HTTP+SSE transport (GET stream + POST /messages).
func (s *MCPServer) ServeSSE(w http.ResponseWriter, r *http.Request) {
	// Authenticate the gateway client
	token := extractToken(r)

	clientIdentity, clientRole, clientScopes, ok := s.resolveAuth(r.Context(), token)
	if !ok {
		s.writeUnauthorized(w)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if origin := s.allowedOrigin(r); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}

	// Clear the write deadline for this long-lived stream. The server's
	// global WriteTimeout (set in main.go, ~60s) otherwise terminates every
	// SSE connection at that mark. Not every ResponseWriter supports this
	// (e.g. in tests) — log and continue rather than failing the request.
	if err := http.NewResponseController(w).SetWriteDeadline(time.Time{}); err != nil {
		log.Printf("SSE: failed to clear write deadline (stream may be time-limited): %v", err)
	}

	sessionID := uuid.New().String()
	session := &Session{
		ID:             sessionID,
		SSEWriter:      w,
		Flusher:        flusher,
		Ctx:            r.Context(),
		ClientIdentity: clientIdentity,
		ClientRole:     clientRole,
		Scopes:         clientScopes,
		TokenHash:      sessionTokenHash(token),
	}

	s.mu.Lock()
	if len(s.sessions) >= s.maxSessions {
		s.mu.Unlock()
		http.Error(w, "Too many active SSE sessions", http.StatusTooManyRequests)
		return
	}
	s.sessions[sessionID] = session
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
	}()

	// Send endpoint event: tells the client where to POST JSON-RPC requests.
	session.writeEvent(fmt.Sprintf("event: endpoint\ndata: /messages?sessionId=%s\n\n", sessionID))

	// Keep connection alive
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-session.Ctx.Done():
			return
		case <-ticker.C:
			session.writeEvent(": keepalive\n\n")
		}
	}
}

// writeUnauthorized responds 401 to a failed auth attempt. When OAuth is
// enabled it also emits the RFC 9728 §5.1 WWW-Authenticate challenge so
// OAuth-aware clients can discover how to obtain a token; this is additive
// and does not change behavior for master/client-token-only deployments.
func (s *MCPServer) writeUnauthorized(w http.ResponseWriter) {
	if s.oauthValidator != nil {
		w.Header().Set("WWW-Authenticate", oauth.ChallengeHeader(s.oauthChallengeCfg, "invalid_token"))
	}
	http.Error(w, "Unauthorized: Invalid gateway token", http.StatusUnauthorized)
}

// allowedOrigin returns the request's Origin if it is in the configured allowlist,
// otherwise an empty string (meaning: do not emit a CORS allow header).
func (s *MCPServer) allowedOrigin(r *http.Request) string {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return ""
	}
	for _, o := range s.corsOrigins {
		if o == "*" || strings.EqualFold(o, origin) {
			return o
		}
	}
	return ""
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

	// Re-authenticate: the POSTer must present the same token that created the
	// session. This prevents session hijacking by anyone who learns the sessionId
	// (which travels in URLs/logs).
	presented := sessionTokenHash(extractToken(r))
	if subtle.ConstantTimeCompare([]byte(presented), []byte(session.TokenHash)) != 1 {
		http.Error(w, "Unauthorized: token does not match session", http.StatusUnauthorized)
		return
	}

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON-RPC request", http.StatusBadRequest)
		return
	}

	// MCP HTTP+SSE transport: the POST only delivers the client's message. The
	// response is pushed back over the SSE stream (not the POST body), and the
	// POST returns 202 Accepted. Notifications (no id) get no response.
	if req.ID == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	resp := s.handleRequest(r.Context(), session.ClientIdentity, session.ClientRole, session.Scopes, &req)
	payload, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
		return
	}
	// Dual-delivery for client compatibility:
	//  - push over the SSE stream (spec-compliant clients, e.g. Claude Code, read here)
	//  - also return it in the POST body (clients that read the response synchronously,
	//    e.g. Antigravity, read here)
	session.writeEvent(fmt.Sprintf("event: message\ndata: %s\n\n", payload))
	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
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

		// Tool-pinning ("rug-pull" defense): if the caller opted into strict
		// mode, refuse to execute a tool whose live definition no longer
		// matches the hash it was approved under. An empty stored hash (no
		// baseline yet) never blocks.
		if s.toolPinningStrict {
			changed, checkErr := s.toolDefinitionChanged(ctx, callReq.Name)
			if checkErr != nil {
				resp.Error = &JSONRPCError{Code: -32603, Message: checkErr.Error()}
				return resp
			}
			if changed {
				resp.Error = &JSONRPCError{Code: -32001, Message: fmt.Sprintf("tool %q definition has changed since it was approved; refusing call (strict tool pinning enabled)", callReq.Name)}
				return resp
			}
		}

		// Redact PII/secrets out of the arguments BEFORE execution, so a
		// value lifted from the LLM's context can't be smuggled out through
		// a downstream API call.
		var findings []redaction.Finding
		if s.redactor != nil && len(callReq.Arguments) > 0 {
			redactedArgs, argFindings := s.redactor.RedactMap(callReq.Arguments)
			callReq.Arguments = redactedArgs
			findings = append(findings, argFindings...)
		}

		startTime := time.Now()
		atomic.AddInt64(&s.activeQueries, 1)
		result, err := s.callTool(ctx, callReq.Name, callReq.Arguments)
		atomic.AddInt64(&s.activeQueries, -1)
		duration := time.Since(startTime).Milliseconds()

		// Redact the result body before it ever reaches the client.
		if err == nil && s.redactor != nil {
			redactedResult, resultFindings := s.redactor.RedactBytes([]byte(result))
			result = string(redactedResult)
			findings = append(findings, resultFindings...)
		}

		logID := uuid.New().String()
		if err != nil {
			resp.Error = &JSONRPCError{Code: -32603, Message: err.Error()}
			s.logAuditAsync(auditLogEntry{id: logID, identity: clientIdentity, tool: callReq.Name, status: "failure", duration: duration, errMsg: err.Error(), redaction: formatFindings(findings)})
		} else {
			resp.Result = CallToolResponse{
				Content: []Content{
					{Type: "text", Text: result},
				},
			}
			s.logAuditAsync(auditLogEntry{id: logID, identity: clientIdentity, tool: callReq.Name, status: "success", duration: duration, redaction: formatFindings(findings)})
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
			Meta:        toolMeta(ep),
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

// findEndpoint resolves an exposed tool name (post tool-prefix) to its
// endpoint and owning connection, applying the same enabled/prefix
// resolution rules as listTools. It returns (nil, nil, nil) — not an error
// — when no enabled endpoint matches; callers decide how to report that.
func (s *MCPServer) findEndpoint(ctx context.Context, name string) (*storage.APIEndpoint, *storage.APIConnection, error) {
	endpoints, err := s.db.GetAllEndpoints(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load endpoints: %w", err)
	}
	conns, err := s.db.GetConnections(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load connections: %w", err)
	}

	connMap := make(map[string]*storage.APIConnection)
	for _, c := range conns {
		connMap[c.ID] = c
	}

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
			return ep, conn, nil
		}
	}

	return nil, nil, nil
}

// toolDefinitionChanged reports whether name's live endpoint definition
// hashes differently than the DefinitionHash recorded when it was last
// approved/pinned (pkg/toolintegrity — the "rug-pull" defense). Admin
// management tools have no backing endpoint and are never considered
// changed. A missing endpoint or an empty stored hash also never counts as
// "changed" — there is nothing to compare against, and callTool's own
// not-found handling covers the missing-endpoint case.
func (s *MCPServer) toolDefinitionChanged(ctx context.Context, name string) (bool, error) {
	if strings.HasPrefix(name, "admin_") {
		return false, nil
	}
	ep, _, err := s.findEndpoint(ctx, name)
	if err != nil {
		return false, err
	}
	if ep == nil {
		return false, nil
	}
	def := toolintegrity.ToolDef{
		Name:             name,
		Description:      ep.ToolDescription,
		Method:           ep.Method,
		Path:             ep.Path,
		ParametersSchema: ep.ParametersSchema,
	}
	return toolintegrity.Changed(ep.DefinitionHash, def), nil
}

// toolMeta builds the tools/list "_meta" payload for an endpoint-backed
// tool, surfacing its content-hash pin (and version, if tracked) so
// integrity-aware clients can detect drift between listing and calling a
// tool. Returns nil (omitted entirely) when the endpoint has no hash yet.
func toolMeta(ep *storage.APIEndpoint) map[string]interface{} {
	if ep.DefinitionHash == "" {
		return nil
	}
	meta := map[string]interface{}{"definitionHash": ep.DefinitionHash}
	if ep.Version != 0 {
		meta["version"] = ep.Version
	}
	return meta
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
		matchedEP, matchedConn, err := s.findEndpoint(ctx, name)
		if err != nil {
			execErr = err
		} else if matchedEP == nil {
			execErr = fmt.Errorf("tool %q not found or target connection is disabled", name)
		} else {
			result, execErr = s.client.ExecuteCall(ctx, matchedConn, matchedEP, args)
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

// requireStringArg extracts a required, non-empty string argument from an
// admin tool call, returning a clear error instead of silently coercing a
// missing/wrong-typed value (e.g. via fmt.Sprintf("%v", nil) == "<nil>").
func requireStringArg(args map[string]interface{}, key string) (string, error) {
	v, ok := args[key].(string)
	if !ok || v == "" {
		return "", fmt.Errorf("missing or invalid required argument %q", key)
	}
	return v, nil
}

// optionalStringArg extracts an optional string argument, returning "" if
// absent. It does not error on a wrong type — it simply treats it as unset.
func optionalStringArg(args map[string]interface{}, key string) string {
	v, _ := args[key].(string)
	return v
}

func (s *MCPServer) handleAdminTool(ctx context.Context, name string, args map[string]interface{}) (string, error) {
	switch name {
	case "admin_add_connection":
		connName, err := requireStringArg(args, "name")
		if err != nil {
			return "", fmt.Errorf("admin_add_connection: %w", err)
		}
		baseURL, err := requireStringArg(args, "base_url")
		if err != nil {
			return "", fmt.Errorf("admin_add_connection: %w", err)
		}
		authType, err := requireStringArg(args, "auth_type")
		if err != nil {
			return "", fmt.Errorf("admin_add_connection: %w", err)
		}
		conn := &storage.APIConnection{
			Name:          connName,
			BaseURL:       baseURL,
			AuthType:      authType,
			AuthSecretRef: optionalStringArg(args, "auth_secret_ref"),
			ToolPrefix:    optionalStringArg(args, "tool_prefix"),
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
		connectionID, err := requireStringArg(args, "connection_id")
		if err != nil {
			return "", fmt.Errorf("admin_add_endpoint: %w", err)
		}
		toolName, err := requireStringArg(args, "tool_name")
		if err != nil {
			return "", fmt.Errorf("admin_add_endpoint: %w", err)
		}
		toolDescription, err := requireStringArg(args, "tool_description")
		if err != nil {
			return "", fmt.Errorf("admin_add_endpoint: %w", err)
		}
		path, err := requireStringArg(args, "path")
		if err != nil {
			return "", fmt.Errorf("admin_add_endpoint: %w", err)
		}
		method, err := requireStringArg(args, "method")
		if err != nil {
			return "", fmt.Errorf("admin_add_endpoint: %w", err)
		}
		ep := &storage.APIEndpoint{
			ConnectionID:     connectionID,
			ToolName:         toolName,
			ToolDescription:  toolDescription,
			Path:             path,
			Method:           method,
			ParametersSchema: optionalStringArg(args, "parameters_schema"),
			Template:         optionalStringArg(args, "template"),
		}
		ep.ID = uuid.New().String()
		if err := s.db.SaveEndpoint(ctx, ep); err != nil {
			return "", fmt.Errorf("failed to register tool endpoint: %w", err)
		}
		return fmt.Sprintf("Successfully registered tool %q. ID: %s", ep.ToolName, ep.ID), nil

	case "admin_register_vault_secret":
		key, err := requireStringArg(args, "key")
		if err != nil {
			return "", fmt.Errorf("admin_register_vault_secret: %w", err)
		}
		val, err := requireStringArg(args, "value")
		if err != nil {
			return "", fmt.Errorf("admin_register_vault_secret: %w", err)
		}
		if err := s.vault.SetSecret(ctx, key, val); err != nil {
			return "", fmt.Errorf("failed to register vault secret: %w", err)
		}
		return fmt.Sprintf("Successfully stored secret reference %q", key), nil

	default:
		return "", fmt.Errorf("unknown admin management tool %q", name)
	}
}
