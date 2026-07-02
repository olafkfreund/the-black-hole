package portal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/calitti/mcp-api-gateway/pkg/auth"
	"github.com/calitti/mcp-api-gateway/pkg/config"
	"github.com/calitti/mcp-api-gateway/pkg/mcp"
	"github.com/calitti/mcp-api-gateway/pkg/openapiimport"
	"github.com/calitti/mcp-api-gateway/pkg/storage"
	"github.com/calitti/mcp-api-gateway/pkg/vault"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Global embed for static web assets (HTML/CSS/JS)
//
//go:embed static/*
var assets embed.FS

type PortalServer struct {
	db          storage.Store
	vault       vault.VaultProvider
	authManager *auth.AuthManager
	config      *config.Config
	mcpServer   *mcp.MCPServer
}

func NewPortalServer(db storage.Store, vp vault.VaultProvider, am *auth.AuthManager, cfg *config.Config, mcpServer *mcp.MCPServer) *PortalServer {
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

	// OpenAPI Import — parses an OpenAPI 3.x spec into a connection + tool
	// endpoints. Supports a dry-run preview (?dry_run=true) that makes no writes.
	mux.HandleFunc("/api/import/openapi", admin(p.handleOpenAPIImport))

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

	// Mock Downstream APIs for LCH DPG & Collateral services.
	// These are unauthenticated demo fixtures — only expose them when explicitly
	// enabled for a demo/dev environment, never in a default (production) deploy.
	if strings.EqualFold(os.Getenv("ENABLE_DEMO_ENDPOINTS"), "true") {
		mux.HandleFunc("/api/mock/dpg/trade-volume", p.handleMockTradeVolume)
		mux.HandleFunc("/api/mock/collateral/non-cash", p.handleMockNonCashCollateral)
	}

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

// oidcHTTPClient returns an HTTP client with a bounded timeout for all outbound
// OIDC calls (token exchange, discovery, JWKS). Never use http.DefaultClient
// (no timeout) for these.
func oidcHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// jwksCacheEntry holds the RSA signing keys published by an issuer, keyed by kid.
type jwksCacheEntry struct {
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

const jwksCacheTTL = 5 * time.Minute

var (
	jwksCacheMu sync.Mutex
	jwksCache   = map[string]*jwksCacheEntry{}
)

// fetchJWKS resolves and returns the issuer's RSA signing keys (by kid). It
// discovers the jwks_uri from the issuer's OIDC configuration document, fetches
// the JWKS, and caches the result in-memory for a short TTL. The issuer (and the
// discovered jwks_uri) must be https://.
func fetchJWKS(ctx context.Context, issuer string) (map[string]*rsa.PublicKey, error) {
	issuer = strings.TrimSuffix(issuer, "/")
	if !strings.HasPrefix(issuer, "https://") {
		return nil, fmt.Errorf("oidc issuer must be https, got %q", issuer)
	}

	jwksCacheMu.Lock()
	if e, ok := jwksCache[issuer]; ok && time.Since(e.fetchedAt) < jwksCacheTTL {
		keys := e.keys
		jwksCacheMu.Unlock()
		return keys, nil
	}
	jwksCacheMu.Unlock()

	client := oidcHTTPClient()

	jwksURI, err := fetchJWKSURI(ctx, client, issuer+"/.well-known/openid-configuration")
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(jwksURI, "https://") {
		return nil, fmt.Errorf("oidc jwks_uri must be https, got %q", jwksURI)
	}

	keys, err := fetchJWKSKeys(ctx, client, jwksURI)
	if err != nil {
		return nil, err
	}

	jwksCacheMu.Lock()
	jwksCache[issuer] = &jwksCacheEntry{keys: keys, fetchedAt: time.Now()}
	jwksCacheMu.Unlock()
	return keys, nil
}

// fetchJWKSURI reads the OIDC discovery document and returns its jwks_uri.
func fetchJWKSURI(ctx context.Context, client *http.Client, discoveryURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("build oidc discovery request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery returned HTTP %d", resp.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", fmt.Errorf("decode oidc discovery: %w", err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("oidc discovery document missing jwks_uri")
	}
	return doc.JWKSURI, nil
}

// fetchJWKSKeys fetches a JWKS document and parses its RSA signing keys by kid.
func fetchJWKSKeys(ctx context.Context, client *http.Client, jwksURI string) (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("build jwks request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned HTTP %d", resp.StatusCode)
	}
	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode jwks: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey)
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := rsaPublicKeyFromJWK(k.N, k.E)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("jwks contained no usable RSA signing keys")
	}
	return keys, nil
}

// rsaPublicKeyFromJWK builds an RSA public key from the base64url-encoded
// modulus (n) and exponent (e) of a JWK.
func rsaPublicKeyFromJWK(nB64, eB64 string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		return nil, fmt.Errorf("decode jwk modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eB64)
	if err != nil {
		return nil, fmt.Errorf("decode jwk exponent: %w", err)
	}
	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 2 {
		return nil, fmt.Errorf("invalid jwk exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(e.Int64())}, nil
}

// verifyIDToken verifies an OIDC ID token's signature against the issuer's JWKS
// and validates the standard claims (iss, aud, exp) plus nonce when one was
// requested. It pins the signing algorithm to RSA (RS256/384/512) so "none" and
// symmetric algorithms are rejected. The verified claims are returned on success.
func (p *PortalServer) verifyIDToken(ctx context.Context, rawIDToken, expectedNonce string) (jwt.MapClaims, error) {
	keys, err := fetchJWKS(ctx, p.config.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("resolve issuer signing keys: %w", err)
	}

	keyfunc := func(token *jwt.Token) (interface{}, error) {
		// Pin to RSA; never accept "none" or HMAC signing.
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			if len(keys) == 1 {
				for _, k := range keys {
					return k, nil
				}
			}
			return nil, fmt.Errorf("id token missing kid")
		}
		key, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("no jwks key for kid %q", kid)
		}
		return key, nil
	}

	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(rawIDToken, claims, keyfunc,
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512"}),
		jwt.WithExpirationRequired(),
	); err != nil {
		return nil, fmt.Errorf("verify id token: %w", err)
	}

	// Issuer must match the configured issuer (ignoring a trailing slash).
	if iss, _ := claims["iss"].(string); strings.TrimSuffix(iss, "/") != strings.TrimSuffix(p.config.OIDCIssuer, "/") {
		return nil, fmt.Errorf("id token issuer mismatch")
	}
	// Audience must contain our client ID.
	if !audienceContains(claims["aud"], p.config.OIDCClientID) {
		return nil, fmt.Errorf("id token audience mismatch")
	}
	// Nonce must match when one was requested.
	if expectedNonce != "" {
		n, _ := claims["nonce"].(string)
		if n == "" || subtle.ConstantTimeCompare([]byte(n), []byte(expectedNonce)) != 1 {
			return nil, fmt.Errorf("id token nonce mismatch")
		}
	}
	return claims, nil
}

// hostIsInternal reports whether the URL's host is, or resolves to, a private,
// loopback, link-local, or unspecified IP address. Parse/resolution failures
// are treated as internal (fail closed) so ambiguous targets are not probed.
func hostIsInternal(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	host := u.Hostname()
	if host == "" {
		return true
	}

	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = append(addrs, a.Unmap())
	} else {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return true
		}
		for _, ip := range ips {
			if a, ok := netip.AddrFromSlice(ip); ok {
				addrs = append(addrs, a.Unmap())
			}
		}
	}

	for _, a := range addrs {
		if a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
			a.IsLinkLocalMulticast() || a.IsUnspecified() {
			return true
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

	// Use a bounded-timeout client so a slow/unresponsive IdP cannot hang this
	// request goroutine indefinitely (http.DefaultClient has no timeout).
	exchangeCtx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tokenReq, err := http.NewRequestWithContext(exchangeCtx, http.MethodPost, tokenURL, strings.NewReader(formVals.Encode()))
	if err != nil {
		http.Redirect(w, r, "/login?error=sso-exchange-failed", http.StatusFound)
		return
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.Header.Set("Accept", "application/json")

	resp, err := oidcHTTPClient().Do(tokenReq)
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

	// Verify the ID token: its signature must validate against the issuer's JWKS
	// (fetched via OIDC discovery), and the standard claims (iss/aud/exp) must
	// hold. Never trust the payload without checking the signature.
	username := "sso-user"
	if tokenResp.IDToken == "" {
		http.Redirect(w, r, "/login?error=sso-missing-id-token", http.StatusFound)
		return
	}

	verifyCtx, cancelVerify := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancelVerify()
	// No nonce is issued in the auth request today; pass "" to skip the nonce
	// check. If a nonce is later added to handleSSOLogin, thread it through here.
	claims, err := p.verifyIDToken(verifyCtx, tokenResp.IDToken, "")
	if err != nil {
		http.Redirect(w, r, "/login?error=sso-id-token-invalid", http.StatusFound)
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

// openAPIImportToolPreview is the dry-run preview shape for a single tool
// that an OpenAPI import would create.
type openAPIImportToolPreview struct {
	ToolName         string `json:"tool_name"`
	ToolDescription  string `json:"tool_description"`
	Path             string `json:"path"`
	Method           string `json:"method"`
	ParametersSchema string `json:"parameters_schema"`
}

// handleOpenAPIImport parses an OpenAPI 3.x spec (JSON or YAML) from the
// request body into a connection and its tool endpoints. With
// ?dry_run=true it returns a preview of what would be created and makes no
// writes; otherwise it persists the connection and endpoints exactly as
// handleConnections/handleEndpoints do and returns a creation summary.
// ?prefix= is passed through to the parser as a tool-name prefix.
func (p *PortalServer) handleOpenAPIImport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Cap the spec size to guard against abusive uploads; OpenAPI documents
	// are text and rarely approach this size even for large APIs.
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}
	if len(body) == 0 {
		http.Error(w, `{"error":"request body is empty"}`, http.StatusBadRequest)
		return
	}

	prefix := r.URL.Query().Get("prefix")
	dryRun := strings.EqualFold(r.URL.Query().Get("dry_run"), "true")

	parsed, err := openapiimport.Parse(body, openapiimport.Options{ToolNamePrefix: prefix})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
		return
	}
	if parsed.Name == "" || parsed.BaseURL == "" {
		http.Error(w, `{"error":"OpenAPI spec is missing a usable info.title or servers[0].url"}`, http.StatusBadRequest)
		return
	}

	if dryRun {
		tools := make([]openAPIImportToolPreview, 0, len(parsed.Endpoints))
		for _, pe := range parsed.Endpoints {
			tools = append(tools, openAPIImportToolPreview{
				ToolName:         pe.ToolName,
				ToolDescription:  pe.ToolDescription,
				Path:             pe.Path,
				Method:           pe.Method,
				ParametersSchema: pe.ParametersSchema,
			})
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dry_run": true,
			"connection": map[string]interface{}{
				"name":      parsed.Name,
				"base_url":  parsed.BaseURL,
				"auth_type": parsed.AuthType,
			},
			"tool_count": len(tools),
			"tools":      tools,
		})
		return
	}

	// Persist: construct the connection/endpoint structs the same way
	// handleConnections/handleEndpoints do (generated UUID, SaveConnection
	// then SaveEndpoint per tool) so imported data behaves identically to
	// data entered through the existing admin API.
	conn := storage.APIConnection{
		ID:       uuid.New().String(),
		Name:     parsed.Name,
		BaseURL:  parsed.BaseURL,
		AuthType: parsed.AuthType,
		Enabled:  true,
	}
	if err := p.db.SaveConnection(r.Context(), &conn); err != nil {
		http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
		return
	}

	createdTools := make([]string, 0, len(parsed.Endpoints))
	for _, pe := range parsed.Endpoints {
		ep := storage.APIEndpoint{
			ID:               uuid.New().String(),
			ConnectionID:     conn.ID,
			ToolName:         pe.ToolName,
			ToolDescription:  pe.ToolDescription,
			Path:             pe.Path,
			Method:           pe.Method,
			ParametersSchema: pe.ParametersSchema,
		}
		if err := p.db.SaveEndpoint(r.Context(), &ep); err != nil {
			http.Error(w, `{"error":"internal server error"}`, http.StatusInternalServerError)
			return
		}
		createdTools = append(createdTools, ep.ToolName)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"dry_run":           false,
		"connection_id":     conn.ID,
		"connection_name":   conn.Name,
		"endpoints_created": len(createdTools),
		"tool_names":        createdTools,
	})
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

	// TLS/mTLS may be terminated in-pod or at an upstream proxy/ingress; report
	// both so an ingress-terminated deployment isn't misreported as unencrypted.
	tlsMode := "none"
	switch {
	case p.config.TLSCertPath != "":
		tlsMode = "pod"
	case p.config.TLSTerminatedAtProxy:
		tlsMode = "edge"
	}

	mtlsMode := p.config.MTLSMode
	if p.config.ClientCAPath != "" {
		mtlsMode = "pod"
	}

	// Expose only non-sensitive status booleans. Filesystem paths, client IDs,
	// and provider internals are not disclosed.
	settings := map[string]interface{}{
		"port":                  p.config.Port,
		"vault_provider":        p.config.VaultProvider,
		"jwt_secret_configured": p.config.JWTSecret != "",
		"oidc_configured":       p.config.OIDCIssuer != "",
		"tls_enabled":           p.config.TLSCertPath != "" || p.config.TLSTerminatedAtProxy,
		"tls_mode":              tlsMode,
		"mtls_enabled":          p.config.ClientCAPath != "" || p.config.MTLSMode == "optional" || p.config.MTLSMode == "required",
		"mtls_mode":             mtlsMode,
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

			// Egress guard: refuse to probe internal/private addresses. This
			// admin-triggered health check must not become an internal port
			// scanner (the gateway's own SSRF guard is package-private, so this
			// is a minimal best-effort check on the resolved target).
			if hostIsInternal(c.BaseURL) {
				h.Status = "BLOCKED (internal address)"
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
