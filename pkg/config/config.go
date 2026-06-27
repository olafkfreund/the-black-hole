package config

import (
	"os"
)

type Config struct {
	Port           string
	DatabasePath   string
	VaultProvider  string // 'local', 'aws', 'azure', 'gcp'
	VaultLocalPath string
	JWTSecret      string
	OIDCIssuer     string
	OIDCClientID   string
	OIDCClientSecret string
	GatewayToken   string // Secure token required by the LLM client
	TLSCertPath    string
	TLSKeyPath     string
	ClientCAPath   string // For mTLS
}

func LoadConfig() *Config {
	dbURL := getEnv("DATABASE_URL", "")
	if dbURL == "" {
		dbURL = getEnv("DATABASE_PATH", "./mcp-gateway.db")
	}
	return &Config{
		Port:           getEnv("PORT", "8080"),
		DatabasePath:   dbURL,
		VaultProvider:  getEnv("VAULT_PROVIDER", "local"),
		VaultLocalPath: getEnv("VAULT_LOCAL_PATH", "./secrets.json"),
		JWTSecret:      getEnv("JWT_SECRET", "dev-jwt-secret-key-change-in-production"),
		OIDCIssuer:     getEnv("OIDC_ISSUER", ""),
		OIDCClientID:   getEnv("OIDC_CLIENT_ID", ""),
		OIDCClientSecret: getEnv("OIDC_CLIENT_SECRET", ""),
		GatewayToken:   getEnv("GATEWAY_TOKEN", "secure-mcp-gateway-token-123456"),
		TLSCertPath:    getEnv("TLS_CERT_PATH", ""),
		TLSKeyPath:     getEnv("TLS_KEY_PATH", ""),
		ClientCAPath:   getEnv("CLIENT_CA_PATH", ""),
	}
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
