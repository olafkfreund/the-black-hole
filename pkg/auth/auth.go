package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

type AuthManager struct {
	jwtSecret    []byte
	gatewayToken string
}

func NewAuthManager(jwtSecret string, gatewayToken string) *AuthManager {
	return &AuthManager{
		jwtSecret:    []byte(jwtSecret),
		gatewayToken: gatewayToken,
	}
}

// jwtAudience scopes issued portal tokens to this gateway's portal API.
const jwtAudience = "mcp-portal"
const jwtIssuer = "mcp-api-gateway"

// GenerateJWT creates a secure portal session token
func (a *AuthManager) GenerateJWT(username, role string) (string, error) {
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    jwtIssuer,
			Audience:  jwt.ClaimStrings{jwtAudience},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(a.jwtSecret)
}

// ValidateJWT verifies the session token and returns claims
func (a *AuthManager) ValidateJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return a.jwtSecret, nil
	},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithAudience(jwtAudience),
		jwt.WithIssuer(jwtIssuer),
	)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid jwt token")
	}

	return claims, nil
}

// VerifyGatewayToken checks if the bearer token for LLM clients is valid
func (a *AuthManager) VerifyGatewayToken(token string) bool {
	if a.gatewayToken == "" {
		return false
	}
	tokenHash := sha256.Sum256([]byte(token))
	gatewayHash := sha256.Sum256([]byte(a.gatewayToken))
	return subtle.ConstantTimeCompare(tokenHash[:], gatewayHash[:]) == 1
}

// bearerToken extracts a bearer token from the Authorization header only.
// Query-parameter tokens are intentionally NOT accepted: they leak into access
// logs, browser history, and Referer headers.
func bearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return ""
}

// authenticate validates the request's bearer JWT and returns its claims.
func (a *AuthManager) authenticate(w http.ResponseWriter, r *http.Request) (*Claims, bool) {
	tokenStr := bearerToken(r)
	if tokenStr == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return nil, false
	}
	claims, err := a.ValidateJWT(tokenStr)
	if err != nil {
		// Do not echo the underlying error to the client (information disclosure).
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return nil, false
	}
	// Inject identity/role into request headers for downstream audit logging.
	r.Header.Set("X-User-Identity", claims.Username)
	r.Header.Set("X-User-Role", claims.Role)
	return claims, true
}

// PortalAuthMiddleware authenticates any valid portal session (any role).
func (a *AuthManager) PortalAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.authenticate(w, r); !ok {
			return
		}
		next.ServeHTTP(w, r)
	}
}

// AdminAuthMiddleware authenticates and additionally requires the admin role,
// enforcing authorization (not just authentication) on privileged endpoints.
func (a *AuthManager) AdminAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := a.authenticate(w, r)
		if !ok {
			return
		}
		if claims.Role != "admin" {
			http.Error(w, `{"error":"forbidden: admin role required"}`, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	}
}

// LoadTLSConfig loads certificates for HTTPS and configures mTLS if required
func LoadTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	if certPath == "" || keyPath == "" {
		return nil, nil // Fallback to plain HTTP if not configured
	}

	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // Force TLS 1.3 for highly regulated env
	}

	if caPath != "" {
		// Set up mTLS (Mutual TLS)
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA cert: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse client CA cert")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsConfig, nil
}
