// Package cache provides a minimal, dependency-free, generic TTL cache suitable
// for per-process caching of hot read paths (config topology, secrets, idempotent
// responses). For cross-pod consistency, back these with Redis in phase 2.
package cache

import (
	"sync"
	"time"
)

type entry[V any] struct {
	value   V
	expires time.Time
}

// TTLCache is a concurrency-safe map with per-entry expiry.
type TTLCache[V any] struct {
	mu  sync.RWMutex
	ttl time.Duration
	m   map[string]entry[V]
}

// New returns a cache with the given default TTL. A ttl <= 0 disables caching:
// Get always misses and Set is a no-op, so callers can wire it unconditionally.
func New[V any](ttl time.Duration) *TTLCache[V] {
	return &TTLCache[V]{ttl: ttl, m: make(map[string]entry[V])}
}

// Enabled reports whether the cache stores anything (ttl > 0).
func (c *TTLCache[V]) Enabled() bool { return c != nil && c.ttl > 0 }

// Get returns the value for key if present and unexpired.
func (c *TTLCache[V]) Get(key string) (V, bool) {
	var zero V
	if !c.Enabled() {
		return zero, false
	}
	c.mu.RLock()
	e, ok := c.m[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expires) {
		return zero, false
	}
	return e.value, true
}

// Set stores value under key with the cache's TTL.
func (c *TTLCache[V]) Set(key string, value V) {
	if !c.Enabled() {
		return
	}
	c.mu.Lock()
	c.m[key] = entry[V]{value: value, expires: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}

// Delete removes a single key.
func (c *TTLCache[V]) Delete(key string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	delete(c.m, key)
	c.mu.Unlock()
}

// Purge clears the entire cache (used to invalidate on writes).
func (c *TTLCache[V]) Purge() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.m = make(map[string]entry[V])
	c.mu.Unlock()
}
