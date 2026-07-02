package config

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// unsetEnv removes key from the environment for the duration of the test and
// restores its prior value (present-or-absent) on cleanup. t.Setenv cannot
// express "unset", so this fills that gap for tests that need to exercise
// the getEnv/os.Getenv default-fallback paths.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	orig, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("failed to unset %s: %v", key, err)
	}
	t.Cleanup(func() {
		if had {
			os.Setenv(key, orig)
		} else {
			os.Unsetenv(key)
		}
	})
}

// setValidSecrets populates the env vars LoadConfig requires in order to
// pass validate(), so individual tests can focus on the one setting they're
// exercising without tripping the fail-closed secret checks.
func setValidSecrets(t *testing.T) {
	t.Helper()
	t.Setenv("JWT_SECRET", strings.Repeat("a", 32))
	t.Setenv("GATEWAY_TOKEN", strings.Repeat("b", 32))
}

func TestLoadConfig_DatabaseURLPrecedence(t *testing.T) {
	t.Run("DATABASE_URL takes precedence over DATABASE_PATH", func(t *testing.T) {
		setValidSecrets(t)
		t.Setenv("DATABASE_URL", "postgres://user:pass@host/db")
		t.Setenv("DATABASE_PATH", "./should-be-ignored.db")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DatabasePath != "postgres://user:pass@host/db" {
			t.Errorf("expected DATABASE_URL to win, got DatabasePath=%q", cfg.DatabasePath)
		}
	})

	t.Run("falls back to DATABASE_PATH when DATABASE_URL unset", func(t *testing.T) {
		setValidSecrets(t)
		unsetEnv(t, "DATABASE_URL")
		t.Setenv("DATABASE_PATH", "./custom.db")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DatabasePath != "./custom.db" {
			t.Errorf("expected fallback to DATABASE_PATH, got DatabasePath=%q", cfg.DatabasePath)
		}
	})

	t.Run("falls back to DATABASE_PATH default when both unset", func(t *testing.T) {
		setValidSecrets(t)
		unsetEnv(t, "DATABASE_URL")
		unsetEnv(t, "DATABASE_PATH")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DatabasePath != "./mcp-gateway.db" {
			t.Errorf("expected default DatabasePath, got %q", cfg.DatabasePath)
		}
	})
}

func TestLoadConfig_SecretBoundaryLengths(t *testing.T) {
	tests := []struct {
		name        string
		jwtSecret   string
		gatewayTok  string
		adminPass   string
		expectError bool
	}{
		{
			name:        "JWT_SECRET at 31 bytes is rejected",
			jwtSecret:   strings.Repeat("a", 31),
			gatewayTok:  strings.Repeat("b", 32),
			expectError: true,
		},
		{
			name:        "JWT_SECRET at 32 bytes is accepted",
			jwtSecret:   strings.Repeat("a", 32),
			gatewayTok:  strings.Repeat("b", 32),
			expectError: false,
		},
		{
			name:        "GATEWAY_TOKEN at 31 bytes is rejected",
			jwtSecret:   strings.Repeat("a", 32),
			gatewayTok:  strings.Repeat("b", 31),
			expectError: true,
		},
		{
			name:        "GATEWAY_TOKEN at 32 bytes is accepted",
			jwtSecret:   strings.Repeat("a", 32),
			gatewayTok:  strings.Repeat("b", 32),
			expectError: false,
		},
		{
			name:        "ADMIN_PASSWORD at 11 chars is rejected",
			jwtSecret:   strings.Repeat("a", 32),
			gatewayTok:  strings.Repeat("b", 32),
			adminPass:   strings.Repeat("p", 11),
			expectError: true,
		},
		{
			name:        "ADMIN_PASSWORD at 12 chars is accepted",
			jwtSecret:   strings.Repeat("a", 32),
			gatewayTok:  strings.Repeat("b", 32),
			adminPass:   strings.Repeat("p", 12),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("JWT_SECRET", tt.jwtSecret)
			t.Setenv("GATEWAY_TOKEN", tt.gatewayTok)
			if tt.adminPass != "" {
				t.Setenv("ADMIN_PASSWORD", tt.adminPass)
			} else {
				unsetEnv(t, "ADMIN_PASSWORD")
			}

			_, err := LoadConfig()
			if tt.expectError && err == nil {
				t.Fatal("expected LoadConfig to return an error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("expected LoadConfig to succeed, got error: %v", err)
			}
		})
	}
}

func TestLoadConfig_OIDCDefaultRoleDefaultsToViewer(t *testing.T) {
	setValidSecrets(t)
	unsetEnv(t, "OIDC_DEFAULT_ROLE")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.OIDCDefaultRole != "viewer" {
		t.Errorf("expected OIDCDefaultRole to default to %q, got %q", "viewer", cfg.OIDCDefaultRole)
	}
}

func TestLoadConfig_OAuthFailClosed(t *testing.T) {
	tests := []struct {
		name        string
		resourceURI string
		authServers string
		expectError bool
	}{
		{
			name:        "empty resource URI and empty authorization servers",
			resourceURI: "",
			authServers: "",
			expectError: true,
		},
		{
			name:        "resource URI set but authorization servers empty",
			resourceURI: "https://gateway.example.com",
			authServers: "",
			expectError: true,
		},
		{
			name:        "authorization servers set but resource URI empty",
			resourceURI: "",
			authServers: "https://issuer.example.com",
			expectError: true,
		},
		{
			name:        "both set",
			resourceURI: "https://gateway.example.com",
			authServers: "https://issuer.example.com",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidSecrets(t)
			t.Setenv("OAUTH_ENABLED", "true")
			if tt.resourceURI != "" {
				t.Setenv("OAUTH_RESOURCE_URI", tt.resourceURI)
			} else {
				unsetEnv(t, "OAUTH_RESOURCE_URI")
			}
			if tt.authServers != "" {
				t.Setenv("OAUTH_AUTHORIZATION_SERVERS", tt.authServers)
			} else {
				unsetEnv(t, "OAUTH_AUTHORIZATION_SERVERS")
			}

			_, err := LoadConfig()
			if tt.expectError && err == nil {
				t.Fatal("expected LoadConfig to return an error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Fatalf("expected LoadConfig to succeed, got error: %v", err)
			}
		})
	}
}

func TestLoadConfig_NewFlagsParsing(t *testing.T) {
	t.Run("REDACTION_ENABLED and TOOL_PINNING_STRICT parse as bools", func(t *testing.T) {
		setValidSecrets(t)
		t.Setenv("REDACTION_ENABLED", "true")
		t.Setenv("TOOL_PINNING_STRICT", "true")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.RedactionEnabled {
			t.Error("expected RedactionEnabled to be true")
		}
		if !cfg.ToolPinningStrict {
			t.Error("expected ToolPinningStrict to be true")
		}
	})

	t.Run("REDACTION_ENABLED and TOOL_PINNING_STRICT default to false", func(t *testing.T) {
		setValidSecrets(t)
		unsetEnv(t, "REDACTION_ENABLED")
		unsetEnv(t, "TOOL_PINNING_STRICT")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.RedactionEnabled {
			t.Error("expected RedactionEnabled to default to false")
		}
		if cfg.ToolPinningStrict {
			t.Error("expected ToolPinningStrict to default to false")
		}
	})

	t.Run("OAUTH_AUTHORIZATION_SERVERS splits on commas", func(t *testing.T) {
		setValidSecrets(t)
		t.Setenv("OAUTH_AUTHORIZATION_SERVERS", "https://a.example.com,https://b.example.com")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"https://a.example.com", "https://b.example.com"}
		if !slices.Equal(cfg.OAuthAuthorizationServers, want) {
			t.Errorf("expected OAuthAuthorizationServers=%v, got %v", want, cfg.OAuthAuthorizationServers)
		}
	})

	t.Run("OAUTH_SCOPES_SUPPORTED splits and trims on commas", func(t *testing.T) {
		setValidSecrets(t)
		t.Setenv("OAUTH_SCOPES_SUPPORTED", "read, write ,admin")

		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{"read", "write", "admin"}
		if !slices.Equal(cfg.OAuthScopesSupported, want) {
			t.Errorf("expected OAuthScopesSupported=%v, got %v", want, cfg.OAuthScopesSupported)
		}
	})
}
