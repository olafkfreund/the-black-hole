package config

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port               string
	DatabasePath       string
	VaultProvider      string // 'local', 'postgres', 'aws', 'azure', 'gcp'
	VaultLocalPath     string
	VaultEncryptionKey string // AES key source for the postgres vault (falls back to JWTSecret)
	JWTSecret          string
	OIDCIssuer         string
	OIDCClientID       string
	OIDCClientSecret   string
	OIDCDefaultRole    string // Role granted to SSO-authenticated users (default 'viewer'; least-privileged)
	GatewayToken       string // Secure token required by the LLM client
	TLSCertPath        string
	TLSKeyPath         string
	ClientCAPath       string // For mTLS

	// TLSTerminatedAtProxy indicates TLS is terminated upstream (e.g. an nginx
	// ingress) rather than by this pod. Set true so operational reporting
	// doesn't misreport an ingress-terminated deployment as unencrypted.
	TLSTerminatedAtProxy bool
	// MTLSMode describes mutual-TLS enforcement, whether enforced in-pod or by
	// an upstream proxy/ingress. One of "off", "optional", "required".
	MTLSMode string

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

	// OAuth protected-resource metadata + wedge feature toggles
	OAuthEnabled              bool     // Advertise OAuth protected-resource metadata (default off)
	OAuthResourceURI          string   // Canonical resource URI for this gateway (required when OAuthEnabled)
	OAuthAuthorizationServers []string // Authorization server issuer URLs (required when OAuthEnabled)
	OAuthScopesSupported      []string // Scopes advertised in protected-resource metadata
	RedactionEnabled          bool     // Redact sensitive fields in logs/audit trail (off by default)
	ToolPinningStrict         bool     // Reject tool-call args that don't match a pinned tool schema (off by default)
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
		VaultEncryptionKey: os.Getenv("VAULT_ENCRYPTION_KEY"),
		JWTSecret:          os.Getenv("JWT_SECRET"),
		OIDCIssuer:         getEnv("OIDC_ISSUER", ""),
		OIDCClientID:       getEnv("OIDC_CLIENT_ID", ""),
		OIDCClientSecret:   os.Getenv("OIDC_CLIENT_SECRET"),
		// Least-privileged default: an unset OIDC_DEFAULT_ROLE must not silently grant
		// every SSO user admin rights. Operators who need admin-by-default must opt in
		// explicitly via the env var (see the warning emitted below when it resolves to "admin").
		OIDCDefaultRole:      getEnv("OIDC_DEFAULT_ROLE", "viewer"),
		GatewayToken:         os.Getenv("GATEWAY_TOKEN"),
		TLSCertPath:          getEnv("TLS_CERT_PATH", ""),
		TLSKeyPath:           getEnv("TLS_KEY_PATH", ""),
		ClientCAPath:         getEnv("CLIENT_CA_PATH", ""),
		TLSTerminatedAtProxy: getBool("TLS_TERMINATED_AT_PROXY", false),
		MTLSMode:             getEnv("MTLS_MODE", "off"),
		AdminUsername:        getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword:        os.Getenv("ADMIN_PASSWORD"),
		PublicBaseURL:        getEnv("PUBLIC_BASE_URL", ""),
		SeedDemoData:         getBool("SEED_DEMO_DATA", false),
		EgressAllowlist:      splitList(os.Getenv("EGRESS_ALLOWLIST")),
		EgressAllowPrivate:   getBool("EGRESS_ALLOW_PRIVATE", false),
		CORSAllowedOrigins:   splitList(os.Getenv("CORS_ALLOWED_ORIGINS")),
		MetricsToken:         os.Getenv("METRICS_TOKEN"),
		ConfigCacheTTL:       getDuration("CONFIG_CACHE_TTL", 5*time.Second),
		SecretCacheTTL:       getDuration("SECRET_CACHE_TTL", 30*time.Second),
		ResponseCacheTTL:     getDuration("RESPONSE_CACHE_TTL", 0),
		// Default kept low deliberately: at HPA max (10 pods) DBMaxOpenConns * replicas
		// must stay under Postgres max_connections. 10 conns/pod * 10 pods = 100, which
		// fits within the fleet's max_connections=200 (see k8s/janus-db.yaml) with headroom
		// for the DBMaxIdleConns below and any out-of-band admin connections.
		DBMaxOpenConns:    getInt("DB_MAX_OPEN_CONNS", 10),
		DBMaxIdleConns:    getInt("DB_MAX_IDLE_CONNS", 10),
		DownstreamRetries: getInt("DOWNSTREAM_RETRIES", 2),

		OAuthEnabled:              getBool("OAUTH_ENABLED", false),
		OAuthResourceURI:          getEnv("OAUTH_RESOURCE_URI", ""),
		OAuthAuthorizationServers: splitList(os.Getenv("OAUTH_AUTHORIZATION_SERVERS")),
		OAuthScopesSupported:      splitList(os.Getenv("OAUTH_SCOPES_SUPPORTED")),
		RedactionEnabled:          getBool("REDACTION_ENABLED", false),
		ToolPinningStrict:         getBool("TOOL_PINNING_STRICT", false),
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.warn()
	return cfg, nil
}

// warn logs non-fatal configuration concerns. Unlike validate(), these do not
// stop startup — they flag choices that are dangerous in production but valid
// for local/demo use.
func (c *Config) warn() {
	if c.OIDCDefaultRole == "admin" {
		log.Printf("WARNING: OIDC_DEFAULT_ROLE is set to 'admin' — every SSO user with no " +
			"explicit role mapping will be granted gateway admin. Set OIDC_DEFAULT_ROLE to a " +
			"least-privileged role (e.g. 'viewer') unless this is intentional.")
	}
	if len(c.EgressAllowlist) == 0 {
		log.Printf("WARNING: EGRESS_ALLOWLIST is empty — downstream calls are unrestricted to " +
			"any public host. A malicious or misconfigured endpoint base_url can exfiltrate " +
			"vault-resolved credentials to an attacker-controlled server. Set EGRESS_ALLOWLIST " +
			"in production to the known downstream hostnames.")
	}
	if !c.RedactionEnabled {
		log.Printf("NOTE: REDACTION_ENABLED is false — sensitive fields are not redacted in " +
			"logs/audit trail. Consider enabling REDACTION_ENABLED in production for data governance.")
	}
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
	// The postgres vault provider hardcodes Postgres-style ($1, $2, ...) placeholders,
	// which fail confusingly (or silently misbehave) against SQLite's `?` placeholders.
	// Fail closed at startup rather than letting the operator hit this at first vault write.
	if c.VaultProvider == "postgres" && !strings.HasPrefix(c.DatabasePath, "postgres://") {
		return fmt.Errorf("VAULT_PROVIDER=postgres requires a Postgres database " +
			"(DATABASE_URL must start with postgres://); got a non-Postgres DatabasePath")
	}
	// Fail closed: advertising OAuth protected-resource metadata without a resource URI
	// or authorization server is worse than not advertising it at all — clients would be
	// pointed at an incomplete or ambiguous configuration.
	if c.OAuthEnabled {
		if c.OAuthResourceURI == "" {
			return fmt.Errorf("OAUTH_ENABLED=true requires OAUTH_RESOURCE_URI to be set")
		}
		if len(c.OAuthAuthorizationServers) == 0 {
			return fmt.Errorf("OAUTH_ENABLED=true requires OAUTH_AUTHORIZATION_SERVERS to be set")
		}
	}
	// "" (zero value) is treated the same as "off" — LoadConfig always defaults
	// MTLS_MODE to "off" before calling validate(), but callers that construct
	// Config directly (e.g. tests) may leave it unset.
	switch c.MTLSMode {
	case "", "off", "optional", "required":
	default:
		return fmt.Errorf("MTLS_MODE must be one of \"off\", \"optional\", \"required\" (got %q)", c.MTLSMode)
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
