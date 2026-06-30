package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// VaultProvider defines the interface for interacting with various secrets managers
type VaultProvider interface {
	GetSecret(ctx context.Context, secretName string) (string, error)
	SetSecret(ctx context.Context, secretName string, secretValue string) error
	ListSecrets(ctx context.Context) ([]string, error)
	DeleteSecret(ctx context.Context, secretName string) error
}

// LocalVault implements a local file-based vault (ideal for air-gapped/local setups)
type LocalVault struct {
	mu       sync.RWMutex
	filePath string
	secrets  map[string]string
}

func NewLocalVault(filePath string) (*LocalVault, error) {
	lv := &LocalVault{
		filePath: filePath,
		secrets:  make(map[string]string),
	}
	if err := lv.load(); err != nil {
		// If file doesn't exist, create an empty one
		if os.IsNotExist(err) {
			return lv, lv.save()
		}
		return nil, err
	}
	return lv, nil
}

func (l *LocalVault) load() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	file, err := os.Open(l.filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	if len(data) == 0 {
		return nil
	}

	return json.Unmarshal(data, &l.secrets)
}

func (l *LocalVault) saveLocked() error {
	data, err := json.MarshalIndent(l.secrets, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(l.filePath, data, 0600)
}

func (l *LocalVault) save() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.saveLocked()
}

func (l *LocalVault) GetSecret(ctx context.Context, secretName string) (string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	val, ok := l.secrets[secretName]
	if !ok {
		return "", fmt.Errorf("secret %s not found in local vault", secretName)
	}
	return val, nil
}

func (l *LocalVault) SetSecret(ctx context.Context, secretName string, secretValue string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.secrets[secretName] = secretValue
	return l.saveLocked()
}

func (l *LocalVault) ListSecrets(ctx context.Context) ([]string, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	keys := make([]string, 0, len(l.secrets))
	for k := range l.secrets {
		keys = append(keys, k)
	}
	return keys, nil
}

func (l *LocalVault) DeleteSecret(ctx context.Context, secretName string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.secrets, secretName)
	return l.saveLocked()
}

// errNotImplemented is returned by cloud providers that have not yet been wired
// to a real secrets backend. Failing loudly prevents silently injecting bogus
// credentials (which the previous stubs did) into downstream requests.
var errNotImplemented = fmt.Errorf("vault provider not implemented")

// InitVault initializes the vault based on config selection.
//
// Cloud providers (aws/gcp/azure) are not yet implemented. Rather than returning
// fake secret values, InitVault fails closed so the operator must supply a working
// backend or explicitly use the local provider.
func InitVault(provider, localPath string) (VaultProvider, error) {
	switch provider {
	case "local":
		return NewLocalVault(localPath)
	case "aws", "gcp", "azure":
		return nil, fmt.Errorf("%w: %q (use 'local' or implement this provider)", errNotImplemented, provider)
	default:
		return nil, fmt.Errorf("unknown vault provider: %s", provider)
	}
}
