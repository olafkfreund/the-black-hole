// Package storetest provides an in-memory, deterministic fake of
// storage.Store (and a companion fake of vault.VaultProvider) for unit
// tests in pkg/mcp and pkg/portal. It intentionally has no external
// dependencies beyond the standard library and the interfaces it fakes, so
// tests using it never touch a real database or vault backend.
package storetest

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/calitti/mcp-api-gateway/pkg/storage"
)

// MockStore is an in-memory implementation of storage.Store, backed by
// plain maps guarded by a mutex. All read methods return results sorted by
// ID (or the natural key) so tests get deterministic ordering without
// depending on Go's randomized map iteration.
type MockStore struct {
	mu sync.Mutex

	connections map[string]*storage.APIConnection // keyed by ID
	endpoints   map[string]*storage.APIEndpoint   // keyed by ID
	auditLogs   []*storage.AuditLog               // append-only, newest last

	// clientTokens is keyed by the SHA-256 hash of the plaintext token,
	// mirroring how storage.DB stores tokens at rest (see storage.HashToken).
	clientTokens map[string]*storage.ClientToken

	nextAuditID int
}

// NewMockStore returns an empty MockStore ready for use.
func NewMockStore() *MockStore {
	return &MockStore{
		connections:  make(map[string]*storage.APIConnection),
		endpoints:    make(map[string]*storage.APIEndpoint),
		clientTokens: make(map[string]*storage.ClientToken),
	}
}

// compile-time assertion that MockStore satisfies storage.Store.
var _ storage.Store = (*MockStore)(nil)

// --- Seeding helpers -------------------------------------------------------

// SeedConnection inserts (or overwrites) a connection directly, bypassing
// any generated-ID convention — the caller supplies conn.ID. Returns conn
// for convenient chaining in test setup.
func (m *MockStore) SeedConnection(conn *storage.APIConnection) *storage.APIConnection {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *conn
	m.connections[cp.ID] = &cp
	return &cp
}

// SeedEndpoint inserts (or overwrites) an endpoint directly, bypassing the
// hash/version bookkeeping that SaveEndpoint performs. The caller supplies
// ep.ID; DefinitionHash/Version are stored exactly as given (default zero
// values if unset).
func (m *MockStore) SeedEndpoint(ep *storage.APIEndpoint) *storage.APIEndpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *ep
	m.endpoints[cp.ID] = &cp
	return &cp
}

// SeedClientToken registers a client token so that GetClientToken(ctx,
// plaintext) succeeds for it. plaintext is hashed exactly as
// storage.DB.SaveClientToken would; the plaintext itself is never retained.
func (m *MockStore) SeedClientToken(plaintext string, t *storage.ClientToken) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *t
	cp.Token = "" // never store/expose plaintext, matching storage.DB semantics
	m.clientTokens[storage.HashToken(plaintext)] = &cp
}

// SeedAuditLog appends a pre-built audit log entry directly, without going
// through LogAudit's ID/timestamp handling.
func (m *MockStore) SeedAuditLog(l *storage.AuditLog) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *l
	m.auditLogs = append(m.auditLogs, &cp)
}

// --- storage.Store: Connections ---------------------------------------------

func (m *MockStore) GetConnections(ctx context.Context) ([]*storage.APIConnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*storage.APIConnection, 0, len(m.connections))
	for _, c := range m.connections {
		cp := *c
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MockStore) SaveConnection(ctx context.Context, conn *storage.APIConnection) error {
	if conn == nil {
		return fmt.Errorf("storetest: nil connection")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *conn
	m.connections[cp.ID] = &cp
	return nil
}

func (m *MockStore) DeleteConnection(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.connections, id)
	return nil
}

// --- storage.Store: Endpoints / Tools ---------------------------------------

func (m *MockStore) GetEndpoints(ctx context.Context, connID string) ([]*storage.APIEndpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*storage.APIEndpoint, 0)
	for _, e := range m.endpoints {
		if e.ConnectionID == connID {
			cp := *e
			out = append(out, &cp)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MockStore) GetAllEndpoints(ctx context.Context) ([]*storage.APIEndpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*storage.APIEndpoint, 0, len(m.endpoints))
	for _, e := range m.endpoints {
		cp := *e
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MockStore) SaveEndpoint(ctx context.Context, ep *storage.APIEndpoint) error {
	if ep == nil {
		return fmt.Errorf("storetest: nil endpoint")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	// Mirror storage.DB.SaveEndpoint's version bookkeeping (without the
	// content-hash computation, which lives in pkg/toolintegrity and is not
	// this package's concern): a new endpoint starts at version 1; an
	// existing one keeps its version unless the caller has already bumped
	// it (tests that care about version drift can set ep.Version directly).
	if existing, ok := m.endpoints[ep.ID]; ok && ep.Version == 0 {
		ep.Version = existing.Version
	} else if ep.Version == 0 {
		ep.Version = 1
	}

	cp := *ep
	m.endpoints[cp.ID] = &cp
	return nil
}

func (m *MockStore) DeleteEndpoint(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.endpoints, id)
	return nil
}

// --- storage.Store: Audit Logs ----------------------------------------------

func (m *MockStore) LogAudit(ctx context.Context, id, clientIdentity, toolName, status string, durationMS int64, errMsg string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if id == "" {
		m.nextAuditID++
		id = fmt.Sprintf("mock-audit-%d", m.nextAuditID)
	}
	m.auditLogs = append(m.auditLogs, &storage.AuditLog{
		ID:             id,
		ClientIdentity: clientIdentity,
		ToolName:       toolName,
		Status:         status,
		DurationMS:     durationMS,
		ErrorMessage:   errMsg,
	})
	return nil
}

// GetAuditLogs returns logs most-recently-added first, matching storage.DB's
// "ORDER BY timestamp DESC" behavior, capped at 100 entries.
func (m *MockStore) GetAuditLogs(ctx context.Context) ([]*storage.AuditLog, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.auditLogs)
	limit := n
	if limit > 100 {
		limit = 100
	}
	out := make([]*storage.AuditLog, 0, limit)
	for i := 0; i < limit; i++ {
		cp := *m.auditLogs[n-1-i]
		out = append(out, &cp)
	}
	return out, nil
}

// --- storage.Store: Client Tokens -------------------------------------------

func (m *MockStore) GetClientToken(ctx context.Context, token string) (*storage.ClientToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.clientTokens[storage.HashToken(token)]
	if !ok {
		return nil, fmt.Errorf("storetest: client token not found")
	}
	cp := *t
	cp.Token = ""
	return &cp, nil
}

func (m *MockStore) SaveClientToken(ctx context.Context, t *storage.ClientToken) error {
	if t == nil {
		return fmt.Errorf("storetest: nil client token")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *t
	hash := storage.HashToken(cp.Token)
	cp.Token = ""
	m.clientTokens[hash] = &cp
	return nil
}

func (m *MockStore) DeleteClientToken(ctx context.Context, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clientTokens, storage.HashToken(token))
	return nil
}

func (m *MockStore) DeleteClientTokenByName(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for hash, t := range m.clientTokens {
		if t.ClientName == name {
			delete(m.clientTokens, hash)
		}
	}
	return nil
}

func (m *MockStore) GetClientTokens(ctx context.Context) ([]*storage.ClientToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*storage.ClientToken, 0, len(m.clientTokens))
	for _, t := range m.clientTokens {
		cp := *t
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientName < out[j].ClientName })
	return out, nil
}

// --- MockVault: a companion fake of vault.VaultProvider ---------------------
//
// pkg/mcp and pkg/portal both take a vault.VaultProvider alongside
// storage.Store, so tests wiring up either package typically need a secret
// store too. MockVault is a minimal in-memory stand-in kept in this package
// for convenience; it does not implement storage.Store and has no relation
// to it beyond being useful in the same test setup.
type MockVault struct {
	mu      sync.Mutex
	secrets map[string]string
}

// NewMockVault returns an empty MockVault ready for use.
func NewMockVault() *MockVault {
	return &MockVault{secrets: make(map[string]string)}
}

// SeedSecret pre-populates a secret without going through SetSecret. Returns
// the vault for convenient chaining in test setup.
func (v *MockVault) SeedSecret(key, value string) *MockVault {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.secrets[key] = value
	return v
}

func (v *MockVault) GetSecret(ctx context.Context, secretName string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	val, ok := v.secrets[secretName]
	if !ok {
		return "", fmt.Errorf("storetest: secret %q not found", secretName)
	}
	return val, nil
}

func (v *MockVault) SetSecret(ctx context.Context, secretName string, secretValue string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.secrets[secretName] = secretValue
	return nil
}

func (v *MockVault) ListSecrets(ctx context.Context) ([]string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := make([]string, 0, len(v.secrets))
	for k := range v.secrets {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func (v *MockVault) DeleteSecret(ctx context.Context, secretName string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.secrets, secretName)
	return nil
}
