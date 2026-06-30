package cache

import (
	"testing"
	"time"
)

func TestTTLCache_HitAndMiss(t *testing.T) {
	c := New[string](time.Minute)
	if _, ok := c.Get("k"); ok {
		t.Fatal("expected miss on empty cache")
	}
	c.Set("k", "v")
	if v, ok := c.Get("k"); !ok || v != "v" {
		t.Fatalf("expected hit 'v', got %q ok=%v", v, ok)
	}
}

func TestTTLCache_Expiry(t *testing.T) {
	c := New[int](20 * time.Millisecond)
	c.Set("n", 42)
	time.Sleep(40 * time.Millisecond)
	if _, ok := c.Get("n"); ok {
		t.Fatal("expected entry to expire")
	}
}

func TestTTLCache_DisabledWhenTTLZero(t *testing.T) {
	c := New[string](0)
	if c.Enabled() {
		t.Fatal("ttl<=0 should disable the cache")
	}
	c.Set("k", "v")
	if _, ok := c.Get("k"); ok {
		t.Fatal("disabled cache must always miss")
	}
}

func TestTTLCache_NilSafe(t *testing.T) {
	var c *TTLCache[string] // nil receiver, as used before EnableX is called
	if _, ok := c.Get("k"); ok {
		t.Fatal("nil cache must miss")
	}
	c.Set("k", "v") // must not panic
	c.Purge()       // must not panic
}

func TestTTLCache_Purge(t *testing.T) {
	c := New[string](time.Minute)
	c.Set("a", "1")
	c.Set("b", "2")
	c.Purge()
	if _, ok := c.Get("a"); ok {
		t.Fatal("expected purge to clear entries")
	}
}
