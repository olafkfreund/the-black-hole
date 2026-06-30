package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

const testSecret = "test-secret-test-secret-test-secret-32"

func TestJWTRoundTrip(t *testing.T) {
	am := NewAuthManager(testSecret, "gw-token")
	tok, err := am.GenerateJWT("alice", "admin")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	claims, err := am.ValidateJWT(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Username != "alice" || claims.Role != "admin" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestValidateJWT_RejectsForeignSecret(t *testing.T) {
	a := NewAuthManager(testSecret, "gw")
	b := NewAuthManager("another-secret-another-secret-32xx", "gw")
	tok, _ := a.GenerateJWT("eve", "admin")
	if _, err := b.ValidateJWT(tok); err == nil {
		t.Fatal("expected token signed with a different secret to be rejected")
	}
}

func TestAdminMiddleware_RejectsNonAdmin(t *testing.T) {
	am := NewAuthManager(testSecret, "gw")
	userTok, _ := am.GenerateJWT("bob", "viewer")

	h := am.AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	req.Header.Set("Authorization", "Bearer "+userTok)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for non-admin, got %d", rec.Code)
	}
}

func TestAdminMiddleware_AllowsAdmin(t *testing.T) {
	am := NewAuthManager(testSecret, "gw")
	adminTok, _ := am.GenerateJWT("root", "admin")

	called := false
	h := am.AdminAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/connections", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusOK || !called {
		t.Fatalf("expected admin to be allowed, got code=%d called=%v", rec.Code, called)
	}
}

func TestAuthMiddleware_RejectsQueryParamToken(t *testing.T) {
	am := NewAuthManager(testSecret, "gw")
	tok, _ := am.GenerateJWT("bob", "admin")

	h := am.PortalAuthMiddleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Token supplied only via query param must NOT authenticate (H1).
	req := httptest.NewRequest(http.MethodGet, "/api/connections?token="+tok, nil)
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when token is only in query param, got %d", rec.Code)
	}
}

func TestBearerToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer  abc ")
	if got := bearerToken(req); got != "abc" {
		t.Fatalf("expected trimmed token 'abc', got %q", got)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Basic xyz")
	if got := bearerToken(req2); got != "" {
		t.Fatalf("expected empty for non-bearer scheme, got %q", got)
	}
}
