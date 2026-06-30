package config

import (
	"strings"
	"testing"
)

func TestValidate_FailsClosedWithoutSecrets(t *testing.T) {
	c := &Config{JWTSecret: "", GatewayToken: ""}
	if err := c.validate(); err == nil {
		t.Fatal("expected validation to fail when JWT_SECRET is unset")
	}
}

func TestValidate_RejectsWeakSecrets(t *testing.T) {
	c := &Config{JWTSecret: "short", GatewayToken: strings.Repeat("x", 40)}
	if err := c.validate(); err == nil {
		t.Fatal("expected validation to reject a too-short JWT_SECRET")
	}
}

func TestValidate_AcceptsStrongSecrets(t *testing.T) {
	c := &Config{
		JWTSecret:    strings.Repeat("a", 32),
		GatewayToken: strings.Repeat("b", 32),
	}
	if err := c.validate(); err != nil {
		t.Fatalf("expected strong secrets to validate, got: %v", err)
	}
}

func TestValidate_RejectsWeakAdminPassword(t *testing.T) {
	c := &Config{
		JWTSecret:     strings.Repeat("a", 32),
		GatewayToken:  strings.Repeat("b", 32),
		AdminPassword: "short",
	}
	if err := c.validate(); err == nil {
		t.Fatal("expected validation to reject a too-short ADMIN_PASSWORD")
	}
}
