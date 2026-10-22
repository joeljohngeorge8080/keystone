# HANDOFF.md — Keystone implementation

> For the next engineer (or model) picking this up. State as of **2026-10-22**, last commit
> `293ad20` plus the uncommitted admin slice 2 described below.
> The design of record is the frozen spec in the Obsidian vault
> (`~/Documents/Obsidian Vault/keystone/docs/05-corrections-round2-R1-R9-FINAL.md`); that
> file's anchor list wins over anything here. `STATUS.md` in this repo is the per-phase
> done / deliberately-not-done ledger and is kept current on every change.

## Status in one paragraph

Every security core the two audit rounds reopened is implemented with a structural mechanism
and a named test. The public plane serves `POST /v1/credentials` end to end: Tier 0 shedding,
OIDC verification with one-time JTIs, Tier 1 limits, the anchor breaker (R7), the OPA
authorization stage with pin-divergence checks, the STS in-flight cap, audit-before-mint, and
single-shot delivery. The admin plane is feature-complete against spec Ch. 40: bearer-token
auth with an env bootstrap, `/readyz`, policy pins with the OPA bundle route, roles and
session-policy templates, revocations, and the read routes (decisions, audit events, audit
verify, issuances). **385 tests pass; `ruff`, `ruff format` and `mypy --strict` are clean.**
Roughly **70% of the 640-hour budget** is spent (estimate, not measured). What remains is the
operator CLI, deployment (compose and Terraform, including the IAM half of the double
allowlist), the GitHub Action, CI bundle signing with the real key, and the dashboard,
metrics and Phase 6 hardening.

## Where things are

| Thing | Location |
|---|---|
| Code repo | `~/Projects/keystone`, GitHub `joeljohngeorge8080/keystone` (private), branch `main` |
| Frozen spec | vault `docs/05-corrections-round2-R1-R9-FINAL.md` (+ `01`, `03` layers) |
| Kickoff decisions | this repo's `CLAUDE.md`; per-phase ledger in `STATUS.md` |
| Daily log | `docs/WORKLOG-2026-09-19.md` (earlier sessions; newer work is recorded in git and STATUS.md) |
| CI | `.github/workflows/ci.yml` (lint, types, full suite with PG/Redis/OPA services), `policy-bundle.yml` (validator gate → build → Cosign) |
| Knowledge graph | `graphify-out/` (uncommitted, local). Query with `graphify query "<question>"` from the repo root |

## How to run it

```bash
cd ~/Projects/keystone
uv sync                                            # Python 3.12, all deps
docker compose -f deploy/compose.test.yml up -d   # PostgreSQL 17 (55432) + Redis 7 (56379)
export KEYSTONE_TEST_DATABASE_URL=postgresql+psycopg://keystone_admin:keystone_test@localhost:55432/keystone_test
export KEYSTONE_TEST_REDIS_URL=redis://localhost:56379/0
export PATH="$HOME/.local/bin:$PATH"               # opa binary (policy + OPA integration tests)
uv run ruff check . && uv run mypy && uv run pytest -q
```

Run the two planes (both read `KEYSTONE_*` settings; unknown keys refuse boot):

```bash
# public plane (internet-facing behind TLS)
uvicorn --factory keystone.api.app:app_from_env --host 0.0.0.0 --port 8080
# admin plane (private interface only; spec A4)
uvicorn --factory keystone.admin.app:admin_app_from_env --host 10.0.0.5 --port 8081
```

Required settings: `KEYSTONE_DATABASE_URL`, `KEYSTONE_REDIS_URL`, `KEYSTONE_AWS_REGION`,
`KEYSTONE_OIDC_AUDIENCE`. Operational secrets (≥32 characters, `SecretStr`, never logged):
`KEYSTONE_ADMIN_BOOTSTRAP_TOKEN` (registered once, while no admin principal exists, 24 h) and
`KEYSTONE_BUNDLE_SERVICE_TOKEN` (the OPA sidecar's bearer for the bundle route).

Useful CLI entry points (the operator CLI is still partial):

```bash
uv run keystone audit verify            # online chain verification
uv run keystone audit export > c.jsonl  # offline bundle; then: keystone audit verify --offline c.jsonl
uv run keystone-policy-verify policies  # R2 structural validator (exit 0 / 1 / 2)
opa test --coverage --threshold 100 policies
```

Integration tests recreate the schema per test (`DROP SCHEMA public CASCADE` + Alembic
upgrade), so they need the throwaway containers above and nothing else.

## Module map (spec Ch. 55: code lives with the layer that owns its data)

```
keystone/api/        app (public routes, composition root), credentials (pipeline, no framework),
                     errors (one exception→HTTP table), http (shared envelope/transport, both planes),
                     ratelimit (Tier 0/1/2, atomic Lua)
keystone/admin/      app (admin composition root, bundle route, /readyz), deps (services + bearer),
                     tokens (hash-stored admin tokens, bootstrap), readiness (/readyz probe),
                     registry_routes (roles, templates, revocations), audit_routes (decisions,
                     events, verify, issuances)
keystone/audit/      events (closed taxonomy + forbidden-key check), canonical (RFC 8785), chain,
                     sink (append under the chain lock), store (reads, paging, decision lookup),
                     verify (pure verifier), aggregation (R4), anchor (Ed25519 + S3 Object Lock +
                     breaker), verification (R7 task)
keystone/identity/   oidc (verifier), jwks (three-tier cache, freshness), replay (SET NX)
keystone/authz/      evaluator (OPA client, decision contract), service (authorization stage),
                     pins (R5/R8 activation, history, OPA config), bundles (build/inspect),
                     policy_verify/ (R2 validator)
keystone/broker/     connectors/{base,aws_sts}, ttl, issuance (state machine, paging), service
                     (T1/mint/T2), reconcile (R6), revocation (F6)
keystone/registry/   models, repo (reads, writes), admin (audited role and template changes)
keystone/db/         ids (UUIDv7), redis (fail-closed guard), partitions, migrations/0001..0003
keystone/workers/    celery_app (two queues), tasks (thin bodies)
keystone/config/     settings (env > defaults; KEYSTONE_TEST_* reserved; SecretStr secrets)
cli/keystone_cli/    `keystone audit verify|export`
policies/            reference bundle keystone.authz -> keystone.grants.* -> keystone.lib (+ opa tests)
```

## Invariants and how they are enforced (grep for the test before changing anything)

| Invariant | Mechanism | Test |
|---|---|---|
| Fail-closed on PG/Redis/OPA/JWKS | `DependencyUnavailable` / `JwksUnavailable` → 503 from every guarded call; no degraded path | `test_redis_controls`, `test_authorization_opa`, `test_oidc_forgery_suite`, `test_credentials_api` (Redis down) |
| External anchor outage stops issuance (R7) | `AnchorBreaker.check` before any decision → 503 `AUDIT_ANCHOR_STORE_UNREACHABLE` | `test_credentials_api` (breaker open / under threshold) |
| Canonical-payload / display integrity (R1) | hash and render from `canonical_payload` bytes; `details` verify-checked | `test_verify`, `test_audit_chain_pg`, `test_admin_registry_audit` (tamper) |
| Positive-assertion-only policy (R2) | `keystone-policy-verify` over `opa parse` AST; required CI stage before signing | `test_policy_verify` (14 negative bundles) |
| Audit-before-mint | decision appended before return; issuance row committed before STS; T2 audit + state in one txn | `test_authorization_opa`, `test_issuance_service_pg`, `test_credentials_api` |
| Uniform pre-auth 401, no oracle | every verifier failure → `TOKEN_INVALID`; precise code goes to the aggregator only | `test_api_http`, `test_credentials_api` |
| No stored credential material | `IssuedCredential` redacted repr; `SecretStr` for operator secrets; secret-key denylist on audit `data`; `jti` hashed | `test_connector_models`, `test_events`, `test_credentials_api`, `test_settings` |
| Admin tokens hash-only, 90-day cap, revocable | SHA-256 lookup; DB CHECK on expiry; revoke and disabled principal checked on every request | `test_admin_plane` (expired, disabled, revoked, bearer shapes) |
| Admin mutations attributed | every admin write chains `admin_principal_id` (tokens, pins, roles, templates, revocations) | `test_admin_plane`, `test_admin_registry_audit` |
| Bundle route accepts only its own bearer | constant-time digest comparison; admin tokens rejected there | `test_admin_plane` (bundle route) |
| Double allowlist (DB half) | `RoleRegistry.require_enabled_role` before any mint; IAM half is AWS `AccessDenied` → 502 | `test_issuance_service_pg`, `test_credentials_api` |
| Revocation ordering (F6) | flagged → apply → read-back → applied; reverse-crash backfill appends; disabled roles stay revocable | `test_revocation_pg`, `test_admin_registry_audit` |
| Pin-activation ordering (R5) | OPA confirms revision before DB pin; timeout leaves pin unchanged | `test_pin_activation_opa`, `test_admin_plane` (live OPA) |
| Monotonic pin (R8) | sequence from bundle manifest metadata only; forced rollback audited | `test_pin_activation_opa`, `test_admin_plane` (stale sequence 409) |
| Tier-0 shedding not IP-keyed (R3) | single global bucket keyed on nothing | `test_redis_controls` |
| Bounded aggregation (R4) | per-bucket key cap + `__overflow__` + HLL | `test_redis_controls` |
| Reconciler atomicity + lag (R6) | one txn per row; `indeterminate` until 20 min window | `test_reconciler_pg` |
| Worker isolation (R7) | dedicated `keystone-anchor` queue | `test_workers` |
| Reconciler append-only (R9) | reconcilers only `INSERT` audit rows; DB trigger blocks UPDATE/DELETE | `test_audit_chain_pg`, `test_schema_pg` |

## Decisions taken during implementation (not in the spec; do not silently reverse)

- **Python CLI**, not Go (spec Ch. 45 wins over the older HANDOFF wording).
- **`audit_events` PK is `(seq, occurred_at)`** because PostgreSQL requires the partition key in every unique constraint.
- **`details` JSONB = the full decoded canonical object**, compared numerically exact.
- **Bundle `revision` = sha256 over policy sources**; CI stamps `bundle_sequence`; the activator never accepts one from a caller.
- **Pin activation = OPA polls a Keystone-served bundle**, verified with OPA's own signing. Pushing policies through OPA's data/policy API was ruled out (bundle-owned paths are read-only).
- **Admin plane is a separate app** on a private listener (spec A4), with its own composition root `keystone.admin.app`.
- **Bootstrap**: `KEYSTONE_ADMIN_BOOTSTRAP_TOKEN` is registered only while no admin principal exists, for 24 h, under the `bootstrap` principal, with the event actor `system:bootstrap`.
- **Bundle route auth**: a dedicated static bearer (`KEYSTONE_BUNDLE_SERVICE_TOKEN`), read by OPA from a file via `opa_config_yaml(bearer_token_path=…)`, so the secret never lands in OPA's config.
- **`/readyz` is unauthenticated** and reports dependency states only (no digests, addresses or messages), so load balancers can probe it. It lives on the admin listener.
- **Revocation of a disabled role is allowed** (Ch. 26 escalates from disabling the grant to invalidating live sessions); only an unknown role is refused.
- **`role_arn` is not patchable** on a registered role; re-pointing an approved grant requires a new, reviewed role.
- **Admin-plane status mapping**: unknown role or template → 404; disabled → 409; the public plane maps the same registry errors to 500 `POLICY_REGISTRY_DIVERGENCE` (Ch. 19).
- **Decision display** renders from the hashed `canonical_payload`, not from `details`, so the API cannot show anything the chain didn't commit to (R1).
- **Breaker on the public plane** checks the anchor store before authorization, so an unanchored window cannot grow while issuance continues (R7).
- **ISSUED rows never marked delivered** are closed as DELIVERED by the reconciler with an `issued_undelivered` event after a 5 min grace.
- **JCS integer domain**: ints above 2^53−1 are refused by `rfc8785`.
- Product-owner defaults accepted: mechanism-3 revocation **OFF**, anchor breaker **600 s**, retention **400 days / monthly partitions**.

## What to do next (in order)

1. **Commit the admin slice 2 work** if it is still uncommitted (see `git status`).
2. **CLI admin commands** (Ch. 45): `roles`, `policy {status,pin,history}`, `decisions {get,tail}`, `revoke role`, `tokens`, `audit {verify,export,tail}`; tables plus `--json`, exit codes 0/1/2, token from env, never argv. They call the admin routes above.
3. **Deploy**: compose (api, admin, worker, anchor worker, opa sidecar with `opa_config_yaml`, PostgreSQL, `noeviction` Redis plus a separate `allkeys-lru` aggregation Redis), Terraform modules (Ch. 64): broker runtime IAM allowlist and target-role trust policy. The IAM half of the double allowlist is still only a contract.
4. **CI**: switch `policy-bundle.yml` to `build_signed_bundle` with the OPA signing key from secrets; exercise the Cosign step (still UNVERIFIED).
5. **GitHub Action** (Ch. 46): `keystone-auth@v1`, masking before any output.
6. **Phase 6**: Ch. 27 failure matrix as one table-driven suite, mutation testing on chain and verifier, k6 budgets (Ch. 61).
7. **Smaller owed items**: OPA capabilities file (Ch. 19), retention pruning (`DROP PARTITION` only behind an anchor), partition pre-creation in production, hostile-matrix generator for grants, dashboard (Ch. 44), metrics (Ch. 51), structured logging (Ch. 49), `/readyz` clock-sync signal.

## Known sharp edges

- **Staged bundle lives in admin-process memory.** After an admin restart OPA's polls get 404 until the next pin. OPA keeps its loaded bundle, but an OPA restart inside that window is a fail-closed outage. Persist the staged bundle or re-stage on boot.
- **Audit partitions are created by the migration only** (14 months from the month it runs). Inserts outside a partition fail closed. Production needs a pre-creation job; the test fixture now creates the pinned month explicitly.
- **Rate-limit overrides don't line up.** The `rate_limit_overrides` table uses scopes `repository|role`, but `Tier1Limiter` asks for `identity|repository`, so overrides never apply for identities. Fix before relying on overrides.
- **`source_ip` is the direct peer address.** No trusted-proxy handling yet; behind a load balancer every request shares one IP in the policy input.
- **Decision lookup has no index** on `details->'data'->>'decision_id'`. It is bounded by the UUIDv7 timestamp so PostgreSQL prunes older partitions; add an index by migration if it gets slow.
- **`/readyz` doesn't probe clock sync** (spec Ch. 31 wants a desync signal).
- SQLAlchemy `text()` treats `:word` and `::cast` inside raw DDL as bind parameters: escape with `\:` or use `CAST(...)`.
- PostgreSQL regex repetition counts are capped at 255 (`{1,512}` is an error).
- `opa build -b <absolute path>` records absolute member names; build from `cwd` with `-b .`.
- `opa test` runs without a loaded bundle, so `loaded_bundle_digest` falls back to `"unloaded"` there.
- The `redis` test container must run with `noeviction`; the aggregation client should point at a separate instance in production.
- Admin tokens default to a 30-day TTL when issued through the API; the cap is 90 days.
