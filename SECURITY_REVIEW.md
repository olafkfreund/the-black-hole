# MCP API Gateway — Code, Structure & Security Review

> Reviewer: Claude (automated deep review)
> Date: 2026-06-30
> Scope: Full Go source (`~4,400 LOC`), deployment (Terraform/EKS), CI, Dockerfile
> Branch: `main`

## Executive Summary

The project is a well-organized Go MCP gateway that proxies LLM tool calls to configured
downstream APIs, with a JWT-protected admin portal, a pluggable vault, OpenTelemetry, and
a distroless container. The **engineering structure is good**; the **security posture is not
production-ready**. The dominant theme is *authentication without authorization* and
*insecure-by-default secrets*. Several findings are individually Critical and **compound**:
default secrets + no RBAC + admin-configurable proxy targets = full internal-network SSRF and
downstream-credential exfiltration by any authenticated user.

**Risk rating: HIGH** — do not expose to untrusted networks until the Critical items are fixed.

| Severity | Count |
|----------|-------|
| Critical | 6 |
| High     | 7 |
| Medium   | 9 |
| Low / Quality | 10+ |

---

## CRITICAL findings

### C1. Hardcoded fallback secrets (auth bypass by default)
`pkg/config/config.go:32,36`
```go
JWTSecret:    getEnv("JWT_SECRET", "dev-jwt-secret-key-change-in-production"),
GatewayToken: getEnv("GATEWAY_TOKEN", "secure-mcp-gateway-token-123456"),
```
If the env vars are unset, the gateway runs with **publicly known** secrets. Anyone can:
- forge a valid admin JWT (HS256 signed with the known secret) → full portal access;
- present the known gateway token → `master`/`admin` MCP role with `*` scope.

**Fix:** Remove defaults. Fail closed (`log.Fatal`) if `JWT_SECRET`/`GATEWAY_TOKEN` are empty
or shorter than 32 bytes. Never ship a usable default.

### C2. Hardcoded backdoor admin login
`pkg/portal/api.go:129`
```go
if credentials.Username == "admin" && credentials.Password == "admin-gateway-secret" {
    token, _ := p.authManager.GenerateJWT(credentials.Username, "admin")
```
A static username/password mints an admin JWT. There is no env override and no way to disable it.
Combined with C1, this is a guaranteed remote admin takeover on any default deployment.

**Fix:** Remove. Source the bootstrap credential from a hashed secret (bcrypt/argon2) loaded
from env/vault, or disable local login entirely when OIDC is configured.

### C3. Seeded backdoor client token with wildcard scope
`main.go:404-415`
```go
tok := &storage.ClientToken{ Token: "lch_member_test_token_889", Scopes: "*", Enabled: true }
```
Every fresh database is seeded with a known token granting access to **all** MCP tools.

**Fix:** Never seed live credentials. Generate a random token at first boot, print once, or
require explicit admin creation.

### C4. No authorization (RBAC) on portal admin APIs — privilege escalation
`pkg/auth/auth.go:85` + `pkg/portal/api.go:55-78`

`PortalAuthMiddleware` validates only that the JWT is *valid*; it never checks `claims.Role`.
Every protected route (`/api/connections`, `/api/vault`, `/api/tokens`, `/api/endpoints`,
`/api/settings`) is therefore reachable by **any** authenticated principal — including an
SSO user issued role `"user"` (`api.go:225`). A low-privilege SSO user can create client
tokens, write vault secrets, and register proxy connections.

**Fix:** Add role enforcement in the middleware (or per-handler), e.g. require `role == "admin"`
for all `/api/*` mutating routes. Carry an authorization layer, not just authentication.

### C5. SSRF + downstream credential exfiltration via connection registration
`pkg/gateway/client.go:37-167`, `pkg/portal/api.go:250` (`POST /api/connections`),
`pkg/mcp/server.go:580` (`admin_add_connection`)

An authenticated principal (and, given C1–C4, effectively an unauthenticated one) can register a
connection with an **arbitrary `base_url`** and an `auth_secret_ref` + `bearer` auth type. When the
tool is invoked, the gateway fetches the secret from the vault and sends it in the `Authorization`
header to the attacker-controlled URL → **secret exfiltration**. The same primitive allows SSRF to
internal services and the **cloud metadata endpoint** (`http://169.254.169.254/...`) from inside EKS.

There is no allowlist of destination hosts, no block on private/link-local ranges, and path
parameters are string-substituted into the URL (`client.go:40-45`) allowing path/host manipulation.

**Fix:** Enforce an egress allowlist (scheme `https`, approved hostnames). Resolve and reject
RFC-1918 / link-local / loopback targets. Never attach a secret to a request whose host is not the
secret's bound host. Validate `renderedPath` cannot alter host/scheme.

### C6. Real secrets committed in Terraform
`deployment/secrets.tf:13-16`
```hcl
secret_string = jsonencode({
  jwt-secret    = "dev-jwt-session-secret-change-in-production-12345"
  gateway-token = "dev-mcp-client-auth-token-67890"
})
```
These values are version-controlled and become the *actual* production secret values unless
manually overwritten post-apply. They are now compromised by virtue of being in git history.

**Fix:** Use `random_password` resources or supply via TF_VAR/SOPS; mark `sensitive = true`;
add a `lifecycle { ignore_changes = [secret_string] }` pattern so real values aren't clobbered.
Rotate these tokens.

---

## HIGH findings

### H1. Tokens accepted via URL query parameter
`pkg/auth/auth.go:99-101`, `pkg/mcp/server.go:193`
JWTs and gateway tokens are accepted via `?token=`. Query strings leak into access logs, browser
history, proxy logs, and `Referer` headers. **Fix:** Authorization header only; if a browser flow
needs it, use a short-lived cookie with `HttpOnly`/`Secure`/`SameSite`.

### H2. SSO/OIDC flow is not secure
`pkg/portal/api.go:143-233`
- No `state` parameter → OAuth CSRF / login-CSRF.
- No `nonce`, no PKCE.
- ID-token signature is **not verified** — the code base64-decodes the payload only (`api.go:211`)
  and trusts `preferred_username`/`email`. No `iss`/`aud`/`exp` validation.
- `redirect_uri` is inconsistent: login builds it from the **issuer** host (`api.go:150`), callback
  hardcodes `http://localhost:PORT` (`api.go:171`) — broken outside localhost and non-TLS.
- Final JWT is delivered in a URL fragment `/#token=...` (`api.go:232`) — token in browser history.

**Fix:** Use a vetted OIDC library (e.g. `coreos/go-oidc`), verify signatures and claims, add
state+PKCE, and return the session token via secure cookie.

### H3. Cloud vault providers are non-functional stubs
`pkg/vault/vault.go:114-169`
`AWSVault`/`GCPVault`/`AzureVault` return hardcoded strings (`"aws-secret-stub"`, etc.). Any
deployment with `VAULT_PROVIDER=aws` (the intended EKS mode) will inject the literal string
`"aws-secret-stub"` as the downstream credential — silently broken auth, and a false sense of
secret management. **Fix:** Implement real providers or fail loudly (`return error`) for
unimplemented providers instead of returning fake data.

### H4. No HTTP server timeouts (DoS / Slowloris)
`main.go:110-114` — `http.Server` sets no `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout`, or
`IdleTimeout`. Slowloris and slow-body attacks can exhaust connections. **Fix:** set all four.

### H5. No request body size limits (DoS)
All JSON handlers `json.NewDecoder(r.Body).Decode(...)` with no `http.MaxBytesReader`. A large body
exhausts memory. **Fix:** wrap bodies with `http.MaxBytesReader`.

### H6. No rate limiting / brute-force protection
`grep` confirms no limiter anywhere. `/api/auth/login` (C2 password), gateway-token validation, and
tool calls are all unthrottled. **Fix:** add per-IP/per-principal rate limiting and login backoff.

### H7. `/messages` MCP endpoint trusts session-ID only
`pkg/mcp/server.go:279-304` — `ServeMessages` looks up the session purely by `?sessionId=` (a UUID
in the URL) and re-runs no token check. Anyone who obtains the session ID (it travels in URLs/logs,
see H1) can drive tool calls as that session's identity. **Fix:** bind the session to its auth token
and re-verify on each POST, or require the token on `/messages` too.

---

## MEDIUM findings

- **M1. Wildcard CORS on SSE** — `Access-Control-Allow-Origin: *` (`server.go:235`) with token-based
  auth; combine with H1 and any origin can connect. Scope to known origins.
- **M2. Internal error strings leaked to clients** — handlers echo raw `err` via
  `fmt.Sprintf('{"error":"%v"}', err)` (portal throughout) and JWT errors (`auth.go:110`). Leaks DB
  driver/paths/internals. Return generic messages; log details server-side.
- **M3. `/metrics` is unauthenticated** (`main.go:102`) — exposes operational metrics publicly.
  Bind to an internal port or require auth.
- **M4. `/api/settings` info disclosure** (`api.go:416-426`) — returns database path, vault paths,
  OIDC client ID, cert paths to any authed user. Minimize.
- **M5. Secrets at rest unencrypted (local vault)** — `pkg/vault/vault.go` stores secrets as plain
  JSON (`0600`). Acceptable only for air-gapped/dev; document and/or encrypt.
- **M6. Client tokens stored in plaintext** — `client_tokens.token` is the raw bearer value and the
  PK (`storage/db.go`). A DB read = all tokens. Store a hash; look up by hash.
- **M7. Password compare not constant-time** (`api.go:129`, `==`). Minor timing oracle (mooted by
  removing C2, but note the pattern). `VerifyGatewayToken` correctly uses `subtle` — good.
- **M8. EKS API server publicly accessible** — `cluster_endpoint_public_access = true`
  (`deployment/eks.tf`) with no `public_access_cidrs` restriction. Restrict or disable public access.
- **M9. CI uses long-lived AWS keys** — `deploy.yml` uses `AWS_ACCESS_KEY_ID/SECRET`. Prefer GitHub
  OIDC (`role-to-assume`) for short-lived credentials. `permissions: contents: read` is good.

## LOW / Code-quality findings

- **L1. CI Go version mismatch** — workflows pin `go-version: '1.22'` but `go.mod` declares
  `go 1.26.3` and the Dockerfile uses `golang:1.26`. CI builds/tests on an older toolchain than
  production (and may fail outright). Align them.
- **L2. JWT lifetime 24h, no refresh/revocation** (`auth.go:38`). Add refresh + a revocation list.
- **L3. No `aud`/`sub` on issued JWTs**; only issuer set. Add and validate audience.
- **L4. `seedDatabase` runs unconditionally in `main`** and seeds external connections (Coinbase,
  Treasury) + the backdoor token — demo behavior in the production entrypoint. Gate behind a
  `--seed` flag or `SEED=true`.
- **L5. Body template injection** — `client.go:68-87` does raw string replacement into a JSON body
  template; non-string params are `json.Marshal`'d (good) but the `placeholder` (unquoted) branch can
  still break JSON structure. Build the body via a real encoder.
- **L6. Thin test coverage** — only `pkg/gateway/client_test.go` (127 LOC). No tests for auth, scope
  matching, SQL layer, or the portal handlers — exactly the security-critical paths.
- **L7. `handleOperationalStats` SSRF-ish health check** (`api.go:474`) — `client.Get(c.BaseURL)` to
  admin-configured URLs; bounded by C5's fix.
- **L8. Duplicate scope-parsing logic** in `server.go` (stdio + SSE) — extract a helper.
- **L9. Inconsistent driver portability** — `db.query()` rewrites `?`→`$n` for Postgres but uses
  SQLite-specific `ON CONFLICT ... excluded` and an `ALTER TABLE ADD COLUMN` migration hack
  (`db.go:154`); brittle across drivers. Use a migration tool.
- **L10. `k8s-janus.yaml` referenced by `deploy.yml` via `sed`** with a hardcoded ECR account ID
  `796973489124`; fragile string-replace deploy. Use Kustomize/Helm image overrides.

## What's done well (keep)

- Clean package boundaries (`auth`, `config`, `gateway`, `mcp`, `portal`, `storage`, `telemetry`,
  `vault`) — good separation of concerns; the `VaultProvider` interface is a solid seam.
- **SQL is fully parameterized** — no SQL injection found (`storage/db.go`).
- JWT validation pins the HMAC signing method (`auth.go:57`) — blocks `alg=none`/RS↔HS confusion.
- Gateway-token comparison is constant-time (`auth.go:79-81`).
- TLS 1.3 floor and optional mTLS support (`auth.go:131-149`).
- Hardened **distroless, non-root, static** container image (`Dockerfile`).
- OpenTelemetry tracing + Prometheus metrics, graceful shutdown, audit logging of tool calls.
- IRSA scoped to a single secret ARN in Terraform (`secrets.tf`) — least-privilege intent is right.

---

## Prioritized remediation order

1. **Kill the backdoors & defaults (C1, C2, C3, C6)** — fail-closed config, remove static login,
   stop seeding live tokens, rotate the committed Terraform secrets.
2. **Add authorization (C4)** — role checks on every `/api/*` mutating route.
3. **Lock down egress (C5)** — destination allowlist + private-range blocking + host-bound secrets.
4. **Harden the HTTP edge (H4, H5, H6, H1, H7, M1)** — timeouts, body caps, rate limits,
   header-only tokens, per-message re-auth.
5. **Fix OIDC properly (H2)** and **implement or fail the cloud vaults (H3)**.
6. **Quality/CI (L1, L6)** — align Go versions, add tests for auth/scope/portal.
