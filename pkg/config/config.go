package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port             string
	DatabasePath     string
	VaultProvider    string // 'local', 'aws', 'azure', 'gcp'
	VaultLocalPath   string
	JWTSecret        string
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCDefaultRole  string // Role granted to SSO-authenticated users (default 'admin')
	GatewayToken     string // Secure token required by the LLM client
	TLSCertPath      string
	TLSKeyPath       string
	ClientCAPath     string // For mTLS

	// Bootstrap local admin credentials (local login is disabled when password is empty).
	AdminUsername string
	AdminPassword string

	// Public base URL used to build OIDC redirect URIs, e.g. https://gateway.example.com
	PublicBaseURL string

	// Security policy toggles
	SeedDemoData       bool     // Seed demo connections/endpoints (off by default)
	EgressAllowlist    []string // Allowed downstream hostnames (empty = allow any public host)
	EgressAllowPrivate bool     // Permit downstream calls to private/loopback ranges (demo/local only)
	CORSAllowedOrigins []string // Allowed origins for SSE/CORS (empty = none)
	MetricsToken       string   // Bearer token required to scrape /metrics (empty = open)

	// Performance / resilience tuning
	ConfigCacheTTL    time.Duration // TTL for cached connections/endpoints (0 = off)
	SecretCacheTTL    time.Duration // TTL for cached vault lookups (0 = off)
	ResponseCacheTTL  time.Duration // TTL for cached idempotent GET responses (0 = off)
	DBMaxOpenConns    int           // Max open DB connections (Postgres pool)
	DBMaxIdleConns    int           // Max idle DB connections
	DownstreamRetries int           // Bounded retries for idempotent downstream calls
}

// minSecretLen is the minimum acceptable length for security-critical secrets.
const minSecretLen = 32

// LoadConfig reads configuration from the environment and fails closed when
// required security-critical secrets are missing or too weak.
func LoadConfig() (*Config, error) {
	dbURL := getEnv("DATABASE_URL", "")
	if dbURL == "" {
		dbURL = getEnv("DATABASE_PATH", "./mcp-gateway.db")
	}

	cfg := &Config{
		Port:               getEnv("PORT", "8080"),
		DatabasePath:       dbURL,
		VaultProvider:      getEnv("VAULT_PROVIDER", "local"),
		VaultLocalPath:     getEnv("VAULT_LOCAL_PATH", "./secrets.json"),
		JWTSecret:          os.Getenv("JWT_SECRET"),
		OIDCIssuer:         getEnv("OIDC_ISSUER", ""),
		OIDCClientID:       getEnv("OIDC_CLIENT_ID", ""),
		OIDCClientSecret:   os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCDefaultRole:    getEnv("OIDC_DEFAULT_ROLE", "admin"),
		GatewayToken:       os.Getenv("GATEWAY_TOKEN"),
		TLSCertPath:        getEnv("TLS_CERT_PATH", ""),
		TLSKeyPath:         getEnv("TLS_KEY_PATH", ""),
		ClientCAPath:       getEnv("CLIENT_CA_PATH", ""),
		AdminUsername:      getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword:      os.Getenv("ADMIN_PASSWORD"),
		PublicBaseURL:      getEnv("PUBLIC_BASE_URL", ""),
		SeedDemoData:       getBool("SEED_DEMO_DATA", false),
		EgressAllowlist:    splitList(os.Getenv("EGRESS_ALLOWLIST")),
		EgressAllowPrivate: getBool("EGRESS_ALLOW_PRIVATE", false),
		CORSAllowedOrigins: splitList(os.Getenv("CORS_ALLOWED_ORIGINS")),
		MetricsToken:       os.Getenv("METRICS_TOKEN"),
		ConfigCacheTTL:     getDuration("CONFIG_CACHE_TTL", 5*time.Second),
		SecretCacheTTL:     getDuration("SECRET_CACHE_TTL", 30*time.Second),
		ResponseCacheTTL:   getDuration("RESPONSE_CACHE_TTL", 0),
		DBMaxOpenConns:     getInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns:     getInt("DB_MAX_IDLE_CONNS", 10),
		DownstreamRetries:  getInt("DOWNSTREAM_RETRIES", 2),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validate enforces fail-closed security requirements. No usable defaults are
// shipped for secrets — the operator must supply them.
func (c *Config) validate() error {
	if len(c.JWTSecret) < minSecretLen {
		return fmt.Errorf("JWT_SECRET must be set and at least %d bytes (got %d)", minSecretLen, len(c.JWTSecret))
	}
	if len(c.GatewayToken) < minSecretLen {
		return fmt.Errorf("GATEWAY_TOKEN must be set and at least %d bytes (got %d)", minSecretLen, len(c.GatewayToken))
	}
	// Local admin login is allowed only with a sufficiently strong password.
	// Leaving ADMIN_PASSWORD empty disables local login (OIDC-only).
	if c.AdminPassword != "" && len(c.AdminPassword) < 12 {
		return fmt.Errorf("ADMIN_PASSWORD, when set, must be at least 12 characters")
	}
	return nil
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func getBool(key string, defaultVal bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return defaultVal
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func getDuration(key string, defaultVal time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return defaultVal
	}
	return d
}

func getInt(key string, defaultVal int) int {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return defaultVal
	}
	return n
}

func splitList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
