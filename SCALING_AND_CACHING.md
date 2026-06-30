# Scaling, Caching & Resilience Plan

> Status: phase 1 + phase 2 implemented and live (in-cluster Postgres + HPA 2→10)
> Companion to SECURITY_REVIEW.md

## LIVE STATUS (implemented)

The gateway runs **stateless on in-cluster Postgres** (`janus-db`, mirrors fides-db — no RDS cost),
autoscaled by an **HPA (2→10 on CPU/mem)** with a PodDisruptionBudget. In-process caches (config 5s,
secret 30s, response 10s) are enabled. SSE multi-pod routing uses **nginx cookie affinity**. Verified:
2 replicas across 2 nodes, shared Postgres (3 conns / 6 endpoints seeded), live `tools/list` (9 tools)
and `tools/call` through the affinity cookie. Redis remains the phase-2 lever for a shared response
cache / distributed rate limiter / cross-pod SSE registry — add when measured (see §4/§5).


## 1. Research & review — current state

| Area | Today | Problem for scale |
|------|-------|-------------------|
| Datastore | SQLite file on a `ReadWriteOnce` PVC, `replicas: 2` | **Blocker.** RWO binds to one node; 2 pods on one SQLite file = lock contention/corruption. Cannot scale horizontally. |
| Hot path | Every `tools/call` does `GetAllEndpoints` + `GetConnections` + a vault `GetSecret` | Repeated DB + vault round-trips per request; no caching. |
| SSE sessions | In-memory `map[sessionID]*Session` per pod | `/sse` lands on pod A, `/messages` may hit pod B → "session not found". Breaks behind a plain LB. |
| Rate limiter | In-memory per pod | Effective limit = N × rate; not a true global limit. |
| Downstream calls | Single attempt, default `http.Transport`, 30s timeout | No retries/circuit breaker; no connection pooling tuning; one slow target ties up goroutines. |
| Autoscaling | None (fixed `replicas: 2`) | No HPA/PDB/resource requests; can't scale on load, unsafe during disruptions. |
| Probes | liveness/readiness hit `/` (the SPA) | Not a real health signal; readiness can't gate on DB availability. |

## 2. Target architecture

```
              ┌────────────── Ingress (TLS, sticky by sessionId cookie) ──────────────┐
              │                                                                        │
        ┌─────▼─────┐      ┌───────────┐      ┌───────────┐      HPA (CPU + active_queries)
        │  gw pod 1 │ ...  │  gw pod N │      │  gw pod … │   ◄── scales 2..N on load
        └─────┬─────┘      └─────┬─────┘      └─────┬─────┘
              │  in-proc caches (config/secret/response, short TTL)                    │
              └──────────────┬───────────────┬───────────────┬────────────────────────┘
                             ▼               ▼               ▼
                     Postgres (RDS, system of record)   (optional) Redis:
                     - shared config & tokens             - shared response cache
                     - WAL/replicas for reads             - shared rate limiter
                                                          - SSE session registry
```

Principle: **stateless pods + shared system-of-record (Postgres)**. SQLite stays only for
single-node/dev. In-process caches give per-pod speed; Redis (phase 2) makes caches, the rate
limiter, and SSE sessions consistent across pods.

## 3. Phase 1 — implemented now (in-process, no new infra, backward compatible)

1. **TTL cache package** (`pkg/cache`) — generic, mutex-guarded, no dependencies.
2. **Config/topology cache** in `storage.DB` (opt-in via `CONFIG_CACHE_TTL`, default 5s):
   caches `GetConnections`/`GetAllEndpoints`; **busted on any write** (save/delete). Cuts the two
   hottest queries to ~one per TTL window.
3. **Secret cache** in the gateway client (`SECRET_CACHE_TTL`, default 30s): removes the vault
   round-trip from the per-call hot path.
4. **Optional response cache** for idempotent `GET` tools (`RESPONSE_CACHE_TTL`, default 0 = off):
   caches downstream JSON keyed by method+URL.
5. **DB connection pool tuning** (`SetMaxOpenConns/Idle/ConnMaxLifetime`) — critical for Postgres.
6. **HTTP transport tuning + bounded retries** for idempotent methods (connection pooling,
   `MaxIdleConnsPerHost`, exponential backoff on 5xx/transport errors).
7. **Health endpoints**: `/healthz` (liveness, always-on) and `/readyz` (readiness, pings DB) so
   rollouts and the HPA gate on real readiness.
8. **Kubernetes**: `k8s/` manifests with resource requests/limits, real probes, **HPA** (min 2 /
   max 10 on CPU), **PodDisruptionBudget**, Postgres env (no RWO SQLite), and `sessionAffinity`/
   sticky ingress for the SSE transport.

## 4. Phase 2 — roadmap (needs infra; safe to add incrementally)

- **Postgres/RDS as system of record** — flip `DATABASE_URL`; code already supports it. Add read
  replicas for read-heavy `tools/list`.
- **Redis** for: shared response cache, a distributed rate limiter (correct global limits), and an
  SSE **session registry** so any pod can serve `/messages` (or keep sticky sessions at the ingress).
- **Circuit breaker** per downstream connection (open after consecutive failures; fail fast).
- **JWKS caching** for OIDC signature verification.
- **OpenTelemetry tracing export** to a collector (currently metrics only) for cross-pod latency.

## 5. How scaling stays safe ("scale when needed without breaking anything")

- Caches are **opt-in / short-TTL** and **invalidated on write**, so correctness is preserved;
  worst case is ≤ TTL seconds of staleness for config.
- HPA scales on CPU + readiness; **PodDisruptionBudget** keeps ≥1 pod during node drains.
- `/readyz` gates traffic on DB connectivity, so new pods don't receive traffic before they can serve.
- Graceful shutdown (already present) drains in-flight requests on scale-in.
- Multi-replica requires Postgres (documented); SQLite is guarded to single-node via the manifests.
