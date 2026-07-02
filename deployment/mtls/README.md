# Enabling optional mTLS on the janus ingress

The gateway's nginx ingress already terminates TLS with a real Let's Encrypt cert
(cert-manager, secret `janus-tls`, host `janus.13.134.88.9.nip.io`). This runbook adds
**optional** mutual TLS on top of that: nginx will additionally accept (and forward)
a client certificate if one is presented, without requiring one. Existing token-only
clients (Claude Desktop, Antigravity, GitHub Copilot) are unaffected.

Nothing here is applied automatically. `k8s-janus.yaml` is pipeline-applied on every
push to `main`; the steps below are deliberately kept **out of that file** and must be
run by hand, in order, against the live cluster.

## Prerequisites

- `kubectl` context pointed at the `sarc-aws` EKS cluster, namespace `janus`.
- `openssl` (used by `gen-certs.sh`).

## Steps

### 1. Generate certs

```bash
./deployment/mtls/gen-certs.sh
```

This writes `deployment/mtls/certs/{ca.crt,ca.key,client.crt,client.key}`. These are
demo/self-signed certs for testing the mechanism — `certs/` is gitignored and must
never be committed. For a real client population, replace this with your actual
client CA and issue certs from it instead.

### 2. Create the CA secret (must happen BEFORE the ingress patch)

```bash
kubectl -n janus create secret generic janus-client-ca \
  --from-file=ca.crt=deployment/mtls/certs/ca.crt
```

The ingress patch in step 3 references this secret by name
(`nginx.ingress.kubernetes.io/auth-tls-secret: "janus/janus-client-ca"`). If the
secret doesn't exist yet when the patch is applied, nginx will fail to configure TLS
verification for this Ingress — always create the secret first.

### 3. Apply the ingress mTLS patch

Use a merge patch, **not** `kubectl apply -f`, so only the mTLS annotations are
touched and nothing else on the Ingress (TLS block, routing rules, other
annotations) is disturbed — see the warning in
[`ingress-mtls-patch.yaml`](ingress-mtls-patch.yaml) for why a plain `apply` is unsafe here:

```bash
kubectl -n janus patch ingress mcp-api-gateway \
  --type merge \
  --patch-file deployment/mtls/ingress-mtls-patch.yaml
```

Or the equivalent one-liner with no file:

```bash
kubectl -n janus annotate ingress mcp-api-gateway --overwrite \
  nginx.ingress.kubernetes.io/auth-tls-secret="janus/janus-client-ca" \
  nginx.ingress.kubernetes.io/auth-tls-verify-client="optional" \
  nginx.ingress.kubernetes.io/auth-tls-verify-depth="1" \
  nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream="true"
```

Verify:

```bash
kubectl -n janus get ingress mcp-api-gateway -o yaml | grep auth-tls
```

### 4. Set `MTLS_MODE=optional` on the deployment

```bash
kubectl -n janus set env deployment/mcp-api-gateway MTLS_MODE=optional
```

This just informs the gateway (`pkg/config`) that mTLS is enforced at "optional"
strength upstream, so it reports its security posture accurately in the portal. The
ingress annotation from step 3 is what actually does the TLS verification; the pod
never terminates TLS itself here (`TLS_TERMINATED_AT_PROXY=true`, set in
`k8s-janus.yaml`).

### 5. Test

With a client cert (should succeed and be verified):

```bash
curl --cert deployment/mtls/certs/client.crt \
     --key deployment/mtls/certs/client.key \
     https://janus.13.134.88.9.nip.io/mcp
```

Without a client cert, using only a bearer token as before (should still succeed —
this is the point of "optional"):

```bash
curl -H "Authorization: Bearer <your-token>" \
     https://janus.13.134.88.9.nip.io/mcp
```

Both requests should reach the gateway. The presence/absence of a client cert is
visible to the gateway via the `ssl-client-verify` (`SUCCESS`/`FAILED`/`NONE`) and
`ssl-client-cert` request headers that nginx injects
(`auth-tls-pass-certificate-to-upstream: "true"`).

## How to roll back

Remove the mTLS annotations from the ingress (leaves everything else — TLS, routing,
cookie affinity — untouched):

```bash
kubectl -n janus annotate ingress mcp-api-gateway \
  nginx.ingress.kubernetes.io/auth-tls-secret- \
  nginx.ingress.kubernetes.io/auth-tls-verify-client- \
  nginx.ingress.kubernetes.io/auth-tls-verify-depth- \
  nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream-
```

And revert the deployment env var:

```bash
kubectl -n janus set env deployment/mcp-api-gateway MTLS_MODE=off
```

Optionally delete the CA secret once nothing depends on it:

```bash
kubectl -n janus delete secret janus-client-ca
```

## ⚠️ Warning: do not flip this to "required" carelessly

`nginx.ingress.kubernetes.io/auth-tls-verify-client` has three states:

- `off` — no client cert requested (default, pre-mTLS state)
- `optional` — client cert requested but not required (this runbook's end state)
- `on` / `required` — client cert **mandatory**

Switching to `on`/`required` will **lock out every token-only client** — Claude
Desktop, Antigravity, GitHub Copilot, and any script hitting the gateway with only a
bearer token — until each of them is reconfigured to present a valid client
certificate signed by the `janus-client-ca` CA. Do not make this change without
first confirming every consumer of the gateway has a working client cert, and have
the rollback steps above ready before you do it.
