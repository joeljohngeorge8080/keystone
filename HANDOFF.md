# HANDOFF.md — Keystone implementation

> For the next engineer (or model) picking this up. State as of **2026-09-19**, commit `d9ab712`.
> The design of record is the frozen spec in the Obsidian vault
> (`~/Documents/Obsidian Vault/keystone/docs/05-corrections-round2-R1-R9-FINAL.md`); that
> file's anchor list wins over anything here. `STATUS.md` in this repo is the per-phase
> done / deliberately-not-done ledger and is kept current on every commit.

## Status in one paragraph

Every security core the two audit rounds reopened is implemented with a structural
mechanism and a named test: the hash-chained audit log with canonical-payload display
integrity (R1), the structural Rego validator bound to the signing gate (R2), the three-tier
rate limiter and bounded failure aggregation (R3/R4), two-phase policy-pin activation with a
CI-assigned monotonic sequence (R5/R8), the single-transaction, CloudTrail-lag-aware issuance
reconciler (R6), Ed25519 anchoring with snapshot-head verification on an isolated worker whose
breaker trips only on anchor-store unreachability (R7), reconciler-append-only (R9), and
F6-ordered revocation. Around those sit OIDC verification with a three-tier JWKS cache, the
OPA authorization stage, the STS connector, the issuance service and the schema (migrations
0001–0003). **287 tests, `ruff`, `mypy --strict` all pass locally and in GitHub Actions.**
Roughly **60% of the 640-hour budget** is spent. What remains is the user-facing plumbing:
nothing serves `POST /v1/credentials` yet, so the system cannot broker a credential end to end.

## Where things are

| Thing | Location |
|---|---|
| Code repo | `~/Projects/keystone`, GitHub `joeljohngeorge8080/keystone` (private), branch `main` |
| Frozen spec | vault `docs/05-corrections-round2-R1-R9-FINAL.md` (+ `01`, `03` layers) |
| Kickoff decisions | this repo's `CLAUDE.md`; per-phase ledger in `STATUS.md` |
| Daily log | `docs/WORKLOG-2026-09-19.md` |
| CI | `.github/workflows/ci.yml` (lint, types, full suite with PG/Redis/OPA services), `policy-bundle.yml` (validator gate → build → Cosign) |

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

Useful entry points:

```bash
uv run keystone audit verify            # online chain verification (KEYSTONE_DATABASE_URL from env)
uv run keystone audit export > c.jsonl  # offline bundle; then: keystone audit verify --offline c.jsonl
uv run keystone-policy-verify policies  # R2 structural validator (exit 0 / 1 / 2)
opa test --coverage --threshold 100 policies
```

Integration tests recreate the schema per test (`DROP SCHEMA public CASCADE` + Alembic
upgrade), so they need the throwaway containers above and nothing else.

## Module map (spec Ch. 55 layout: code lives with the layer that owns its data)

```
keystone/audit/      events, canonical (RFC 8785), chain, sink, store, verify (pure verifier),
                     aggregation (R4), anchor (Ed25519 + S3 Object Lock + breaker), verification (R7 task)
keystone/identity/   oidc (verifier), jwks (three-tier cache), replay (SET NX)
keystone/api/        ratelimit (Tier 0/1/2)                  <- HTTP routes NOT written yet
keystone/authz/      evaluator (OPA client + decision contract), service (authorization stage),
                     pins (R5/R8 activation), bundles (build/inspect), policy_verify/ (R2 validator)
keystone/broker/     connectors/{base,aws_sts}, ttl, issuance (state machine), service (T1/mint/T2),
                     reconcile (R6), revocation (F6)
keystone/registry/   models, repo (DB half of the double allowlist)
keystone/db/         ids (UUIDv7), redis (fail-closed guard), partitions, migrations/0001..0003
keystone/workers/    celery_app (two queues), tasks (thin bodies)
keystone/config/     settings (env > defaults, unknown keys refuse boot)
cli/keystone_cli/    `keystone audit verify|export`
policies/            reference bundle keystone.authz -> keystone.grants.* -> keystone.lib (+ opa tests)
```

## Invariants and how they are enforced (grep for the test before changing anything)

| Invariant | Mechanism | Test |
|---|---|---|
| Fail-closed on PG/Redis/OPA/JWKS | `DependencyUnavailable` (503) from every guarded call; no degraded path exists | `test_redis_controls`, `test_authorization_opa`, `test_oidc_forgery_suite` |
| Canonical-payload / display integrity (R1) | hash & render from `canonical_payload` bytes; `details` verify-checked with Decimal-exact equality | `test_verify`, `test_audit_chain_pg` |
| Positive-assertion-only policy (R2) | `keystone-policy-verify` over `opa parse` AST, transitive call graph; required CI stage before signing | `test_policy_verify` (14 negative bundles) |
| Audit-before-mint | decision appended before return; issuance row committed before STS; T2 audit+state in one txn | `test_authorization_opa`, `test_issuance_service_pg` |
| No stored credential material | `IssuedCredential` redacted repr; secret-key denylist on audit `data` and `identity_claims`; prefix only | `test_connector_models`, `test_events`, `test_issuance_service_pg` |
| Revocation ordering (F6) | flagged → apply → read-back → applied; reverse-crash backfill appends | `test_revocation_pg` |
| Double allowlist (DB half) | `RoleRegistry.require_enabled_role` before any mint; IAM half is AWS `AccessDenied` → 502 | `test_issuance_service_pg` |
| Tier-0 shedding not IP-keyed (R3) | single global bucket keyed on nothing | `test_redis_controls` |
| Bounded aggregation (R4) | per-bucket key cap + `__overflow__` + HLL | `test_redis_controls` |
| Pin-activation ordering (R5) | OPA confirms revision before DB pin; timeout leaves pin unchanged | `test_pin_activation_opa` |
| Reconciler atomicity + lag (R6) | one txn per row; `indeterminate` until 20 min window | `test_reconciler_pg` |
| Worker isolation + breaker source (R7) | dedicated `keystone-anchor` queue; breaker on store unreachability only | `test_workers`, `test_anchor_verification_pg` |
| Monotonic pin (R8) | sequence from bundle manifest metadata only; forced rollback audited | `test_pin_activation_opa` |
| Reconciler append-only (R9) | reconcilers only `INSERT` audit rows; DB trigger blocks UPDATE/DELETE even for the owner | `test_audit_chain_pg`, `test_schema_pg` |

## Decisions taken during implementation (not in the spec; do not silently reverse)

- **Python CLI**, not Go (spec Ch. 45 wins over the older HANDOFF wording).
- **`audit_events` PK is `(seq, occurred_at)`** because PostgreSQL requires the partition key in every unique constraint.
- **`details` JSONB = the full decoded canonical object**, compared numerically exact (PostgreSQL prints JSONB numerics without exponents).
- **Bundle `revision` = sha256 over policy sources**; `inspect_bundle` recomputes it relative to the manifest roots. CI stamps `bundle_sequence`; the activator never accepts one from a caller.
- **Pin activation = OPA polls a Keystone-served bundle**, verified with OPA's own signing (`opa build --signing-key` + `keys:` in the sidecar config). Pushing policies through OPA's data/policy API was ruled out: bundle-owned paths are read-only.
- **ISSUED rows never marked delivered** are closed as DELIVERED by the reconciler with an `issued_undelivered` event after a 5 min grace, because AMB-3's enum has no other terminal state that means "credential exists".
- **JCS integer domain**: ints above 2^53−1 are refused by `rfc8785`; `seq` is BIGINT but that bound is unreachable in practice.
- Product-owner defaults accepted: mechanism-3 revocation **OFF**, anchor breaker **600 s**, retention **400 days / monthly partitions**.

## What to do next (in order)

1. **`POST /v1/credentials` pipeline** (FastAPI, Ch. 39–43): Tier 0 → verify → Tier 1 → authorize → `StsInflightGuard` → issue → single-shot 201 → `mark_delivered`; error envelope with uniform pre-auth 401; `Cache-Control: no-store`. Every component it needs already exists; this is wiring.
2. **Admin plane**: bearer-token auth (`admin_tokens`, hash-stored, 90-day cap), `/readyz` consulting `active_pin`, `AnchorBreaker.check`, OPA loaded digest; routes for roles, templates, pins (`PinActivator`), revocations, audit read/verify; the bundle-server route that serves `StagedBundleStore` to the OPA sidecar.
3. **CLI admin commands** (Ch. 45) over the admin plane.
4. **Deploy**: compose (api, worker, anchor worker, opa sidecar with `opa_config_yaml`, postgres `noeviction` Redis + separate `allkeys-lru` aggregation Redis), Terraform modules (Ch. 64) — the IAM half of the double allowlist is still only a contract.
5. **CI**: switch `policy-bundle.yml` to `build_signed_bundle` with the OPA signing key from secrets; exercise the Cosign step (still UNVERIFIED).
6. **Phase 6**: Ch. 27 failure matrix as one table-driven suite, mutation testing on chain + verifier, k6 budgets (Ch. 61).
7. Smaller owed items: OPA capabilities file, retention pruning (DROP PARTITION only behind an anchor), hostile-matrix generator for grants, dashboard, GitHub Action, metrics.

## Known sharp edges

- SQLAlchemy `text()` treats `:word` and `::cast` inside raw DDL as bind parameters — escape with `\:` or use `CAST(...)`.
- PostgreSQL regex repetition counts are capped at 255 (`{1,512}` is an error).
- `opa build -b <absolute path>` records absolute member names; build from `cwd` with `-b .`.
- `opa test` runs without a loaded bundle, so `loaded_bundle_digest` falls back to `"unloaded"` there and is mocked via `with data.system.bundles as ...`.
- The `redis` test container from `deploy/compose.test.yml` must run with `noeviction`; the aggregation client should point at a separate instance in production.
