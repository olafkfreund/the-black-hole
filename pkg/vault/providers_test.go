package vault

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

// providersTestEncKey is a distinct 32+ byte key from local_test.go's
// testEncKey, used here so this file has no hidden coupling to it.
const providersTestEncKey = "providers-test-vault-key-32bytes!!"

// --- InitVault fail-closed (aws/gcp/azure/unknown) -------------------------

// TestInitVault_UnimplementedCloudProvidersFailClosed verifies that asking
// for a cloud provider that has no real backend wired up returns an error
// (wrapping errNotImplemented) rather than a usable VaultProvider or fake
// secrets. This is the crux of the "fail closed, not fake" contract
// documented on InitVault.
func TestInitVault_UnimplementedCloudProvidersFailClosed(t *testing.T) {
	for _, provider := range []string{"aws", "gcp", "azure"} {
		t.Run(provider, func(t *testing.T) {
			v, err := InitVault(provider, "", nil, providersTestEncKey)
			if err == nil {
				t.Fatalf("InitVault(%q): expected error, got nil (and provider %#v)", provider, v)
			}
			if v != nil {
				t.Fatalf("InitVault(%q): expected nil VaultProvider on error, got %#v", provider, v)
			}
			if !errors.Is(err, errNotImplemented) {
				t.Fatalf("InitVault(%q): error = %v, want it to wrap errNotImplemented", provider, err)
			}
		})
	}
}

// TestInitVault_UnknownProviderFailsClosed verifies a bogus/misspelled
// provider name is rejected outright rather than silently falling back to
// some default.
func TestInitVault_UnknownProviderFailsClosed(t *testing.T) {
	bogusNames := []string{"", "Local", "POSTGRES", "vault", "memory", "totally-bogus"}
	for _, name := range bogusNames {
		t.Run(name, func(t *testing.T) {
			v, err := InitVault(name, "", nil, providersTestEncKey)
			if err == nil {
				t.Fatalf("InitVault(%q): expected error, got nil (and provider %#v)", name, v)
			}
			if v != nil {
				t.Fatalf("InitVault(%q): expected nil VaultProvider on error, got %#v", name, v)
			}
		})
	}
}

// TestInitVault_LocalAndPostgresStillWork is a sanity check that the
// fail-closed cases above aren't accidentally masking a broken "local"/
// "postgres" dispatch (e.g. if a future edit swapped the switch cases).
func TestInitVault_LocalAndPostgresStillWork(t *testing.T) {
	t.Run("local", func(t *testing.T) {
		dir := t.TempDir()
		v, err := InitVault("local", dir+"/vault.json", nil, providersTestEncKey)
		if err != nil {
			t.Fatalf("InitVault(local): %v", err)
		}
		if v == nil {
			t.Fatal("InitVault(local): expected non-nil VaultProvider")
		}
		if _, ok := v.(*LocalVault); !ok {
			t.Fatalf("InitVault(local): got %T, want *LocalVault", v)
		}
	})

	t.Run("postgres", func(t *testing.T) {
		db := newSQLiteDB(t)
		v, err := InitVault("postgres", "", db, providersTestEncKey)
		if err != nil {
			t.Fatalf("InitVault(postgres): %v", err)
		}
		if v == nil {
			t.Fatal("InitVault(postgres): expected non-nil VaultProvider")
		}
		if _, ok := v.(*PostgresVault); !ok {
			t.Fatalf("InitVault(postgres): got %T, want *PostgresVault", v)
		}
	})
}

// --- PostgresVault crypto ----------------------------------------------
//
// NewPostgresVault requires a non-nil *sql.DB (it runs a CREATE TABLE IF NOT
// EXISTS during construction), so it cannot be built without a DB handle at
// all. The lightest available backing is an in-memory sqlite3 database: the
// package's SQL uses $1/$2 placeholders and a Postgres-style upsert
// (ON CONFLICT ... DO UPDATE SET col = EXCLUDED.col), both of which sqlite3
// (via mattn/go-sqlite3, which bundles a modern SQLite with UPSERT support)
// understands identically to Postgres. This lets us exercise the exact
// production SQL paths in PostgresVault, not a reimplementation of them,
// while still fully covering the AES-256-GCM seal/open logic under test.

// newSQLiteDB returns an in-memory sqlite3 *sql.DB, closed automatically at
// test cleanup.
func newSQLiteDB(t *testing.T) *sql.DB {
	t.Helper()
	// A unique named in-memory DB (rather than ":memory:") with cache=shared
	// would share state across connections in a pool; a single connection
	// in-memory DB is sufficient and simpler for these tests.
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(sqlite3): %v", err)
	}
	// go-sqlite3's :memory: databases are per-connection; force a single
	// connection so the vault_secrets table isn't lost/recreated across
	// pooled connections.
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestPostgresVault_RoundTrip verifies SetSecret -> GetSecret round trips
// correctly and that the ciphertext stored in the DB never contains the
// plaintext secret.
func TestPostgresVault_RoundTrip(t *testing.T) {
	db := newSQLiteDB(t)
	ctx := context.Background()

	pv, err := NewPostgresVault(db, providersTestEncKey)
	if err != nil {
		t.Fatalf("NewPostgresVault: %v", err)
	}

	if err := pv.SetSecret(ctx, "db-password", "s3cr3t-value"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	var stored string
	if err := db.QueryRowContext(ctx, "SELECT ciphertext FROM vault_secrets WHERE name = $1", "db-password").Scan(&stored); err != nil {
		t.Fatalf("querying stored ciphertext: %v", err)
	}
	if stored == "" {
		t.Fatal("expected non-empty ciphertext column")
	}
	if strings.Contains(stored, "s3cr3t-value") {
		t.Fatal("stored ciphertext contains the plaintext secret value; expected it to be encrypted")
	}

	got, err := pv.GetSecret(ctx, "db-password")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if got != "s3cr3t-value" {
		t.Fatalf("GetSecret = %q, want %q", got, "s3cr3t-value")
	}

	keys, err := pv.ListSecrets(ctx)
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(keys) != 1 || keys[0] != "db-password" {
		t.Fatalf("ListSecrets = %v, want [db-password]", keys)
	}

	// Upsert: setting the same name again should update in place, not
	// duplicate the row.
	if err := pv.SetSecret(ctx, "db-password", "rotated-value"); err != nil {
		t.Fatalf("SetSecret (update): %v", err)
	}
	got2, err := pv.GetSecret(ctx, "db-password")
	if err != nil {
		t.Fatalf("GetSecret (after update): %v", err)
	}
	if got2 != "rotated-value" {
		t.Fatalf("GetSecret (after update) = %q, want %q", got2, "rotated-value")
	}
	keys2, err := pv.ListSecrets(ctx)
	if err != nil {
		t.Fatalf("ListSecrets (after update): %v", err)
	}
	if len(keys2) != 1 {
		t.Fatalf("ListSecrets (after update) = %v, want exactly one key (upsert, not duplicate row)", keys2)
	}

	if err := pv.DeleteSecret(ctx, "db-password"); err != nil {
		t.Fatalf("DeleteSecret: %v", err)
	}
	if _, err := pv.GetSecret(ctx, "db-password"); err == nil {
		t.Fatal("expected error after DeleteSecret, got nil")
	}
}

// TestPostgresVault_GetSecret_NotFound verifies the not-found error path
// (sql.ErrNoRows is translated to a descriptive error, not surfaced raw or
// swallowed into an empty string).
func TestPostgresVault_GetSecret_NotFound(t *testing.T) {
	db := newSQLiteDB(t)
	ctx := context.Background()

	pv, err := NewPostgresVault(db, providersTestEncKey)
	if err != nil {
		t.Fatalf("NewPostgresVault: %v", err)
	}

	_, err = pv.GetSecret(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("expected error for missing secret, got nil")
	}
	if errors.Is(err, sql.ErrNoRows) {
		t.Fatal("expected sql.ErrNoRows to be wrapped in a descriptive error, not surfaced raw")
	}
}

// TestPostgresVault_WrongKeyFailsClosed verifies that decrypting
// ciphertext written under one key with a PostgresVault constructed with a
// different key fails loudly rather than returning garbage plaintext.
func TestPostgresVault_WrongKeyFailsClosed(t *testing.T) {
	db := newSQLiteDB(t)
	ctx := context.Background()

	pv1, err := NewPostgresVault(db, providersTestEncKey)
	if err != nil {
		t.Fatalf("NewPostgresVault: %v", err)
	}
	if err := pv1.SetSecret(ctx, "api-key", "top-secret"); err != nil {
		t.Fatalf("SetSecret: %v", err)
	}

	// Same DB (so the same ciphertext row), different encryption key.
	pv2, err := NewPostgresVault(db, "a-completely-different-key-value")
	if err != nil {
		t.Fatalf("NewPostgresVault (wrong key): %v", err)
	}

	_, err = pv2.GetSecret(ctx, "api-key")
	if err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

// TestPostgresVault_WeakKeyRejected mirrors LocalVault's minimum key length
// enforcement (see TestLocalVault_WeakKeyRejected in local_test.go): both
// providers must apply the same >=16 byte floor on the encryption key so
// that VAULT_ENCRYPTION_KEY (or its JWT_SECRET fallback, resolved by the
// caller before InitVault is invoked) is held to one consistent standard
// regardless of which vault backend is configured.
func TestPostgresVault_WeakKeyRejected(t *testing.T) {
	db := newSQLiteDB(t)

	if _, err := NewPostgresVault(db, "short"); err == nil {
		t.Fatal("expected error for encryption key < 16 bytes, got nil")
	}
}

// TestPostgresVault_NilDBRejected verifies construction fails closed when no
// database handle is supplied, rather than panicking later on first use.
func TestPostgresVault_NilDBRejected(t *testing.T) {
	if _, err := NewPostgresVault(nil, providersTestEncKey); err == nil {
		t.Fatal("expected error for nil *sql.DB, got nil")
	}
}

// TestVaultKeyLengthFloor_ConsistentAcrossProviders asserts LocalVault and
// PostgresVault apply the exact same minimum-key-length rule, so that
// whichever backend an operator picks, the same VAULT_ENCRYPTION_KEY (falling
// back to JWT_SECRET) passes or fails identically. A divergence here would
// mean a key considered "safe" for one provider silently isn't for the
// other.
func TestVaultKeyLengthFloor_ConsistentAcrossProviders(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{"empty", "", true},
		{"15 bytes (below floor)", "012345678901234", true},
		{"exactly 16 bytes (floor)", "0123456789012345", false},
		{"32 bytes (typical)", providersTestEncKey, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			_, localErr := NewLocalVault(dir+"/vault.json", tc.key)

			db := newSQLiteDB(t)
			_, pgErr := NewPostgresVault(db, tc.key)

			if (localErr != nil) != tc.wantErr {
				t.Errorf("NewLocalVault(key len=%d): err = %v, wantErr = %v", len(tc.key), localErr, tc.wantErr)
			}
			if (pgErr != nil) != tc.wantErr {
				t.Errorf("NewPostgresVault(key len=%d): err = %v, wantErr = %v", len(tc.key), pgErr, tc.wantErr)
			}
			if (localErr != nil) != (pgErr != nil) {
				t.Errorf("key length floor diverges between providers for key len=%d: local err=%v, postgres err=%v",
					len(tc.key), localErr, pgErr)
			}
		})
	}
}
