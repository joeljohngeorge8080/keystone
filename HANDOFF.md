# HANDOFF.md — Keystone implementation

> For the next engineer (or model) picking this up. State as of **2026-10-23**: last commit
> `427baac`, plus the uncommitted Phase 5 completion and Phase 6 work described below.
> The design of record is the frozen spec in the Obsidian vault
> (`~/Documents/Obsidian Vault/keystone/docs/05-corrections-round2-R1-R9-FINAL.md`); that
> file's anchor list wins over anything here. `STATUS.md` in this repo is the per-phase
> done / deliberately-not-done ledger and is kept current on every change.

## Status in one paragraph

Every security core the two audit rounds reopened is implemented with a structural mechanism
and a named test, and the system now deploys: a non-root, read-only Docker image, a compose
stack (OPA sidecar sharing a network namespace with both planes, two Celery queues + beat, two
Redis instances, provisioning and OPA-config init steps) smoke-tested live, Terraform modules for
the IAM half of the double allowlist (validated and guardrail-tested offline, never applied),
the operator CLI, and the `keystone-auth` GitHub Action. Phase 6 has the Ch. 27 failure matrix,
mutation testing at 100% on chain + verifier (a CI gate), the hostile policy matrix (R2) and
stage-latency budgets. **505 tests pass (+4 opt-in perf); `ruff`, `ruff format`, `mypy --strict`
and `actionlint` are clean.** Not done: metrics and dashboard (blocked on approving new
dependencies), retention pruning (blocked on a design decision), the load/soak harness, and
anything that needs real AWS or GitHub to run.

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

Deploy the whole stack (Ch. 62/63):

```bash
docker build -t keystone:dev .
cp deploy/.env.example deploy/.env      # fill in; keys go in deploy/secrets/ (both gitignored)
docker compose -f deploy/compose.yml --env-file deploy/.env up -d
```

Operator CLI (talks to the admin plane; token from env or file, never argv):

```bash
export KEYSTONE_ADMIN_URL=https://admin.internal:8081   # plain http only for a loopback tunnel
export KEYSTONE_ADMIN_TOKEN_FILE=~/.keystone-token       # or KEYSTONE_ADMIN_TOKEN
uv run keystone policy status           # exit 1 on no pin / divergence
uv run keystone policy pin bundle.tar.gz
uv run keystone roles list | decisions tail -f | tokens issue --principal alice
uv run keystone replay <decision-id> --bundle b.tar.gz --input input.json
uv run keystone audit verify            # direct to PostgreSQL (KEYSTONE_DATABASE_URL)
uv run keystone audit export > c.jsonl  # offline bundle; then: keystone audit verify --offline c.jsonl
```

Policy and Phase 6 gates:

```bash
uv run keystone-policy-verify policies                                   # R2 structural validator
uv run python -m keystone.authz.policy_verify.hostile policies --seeds tests/policy/hostile_seeds.json
opa test --coverage --threshold 100 policies
uv run python -m tests.mutation.run                                      # >= 95% or exit 1
KEYSTONE_RUN_PERF=1 uv run pytest tests/perf -s                          # Ch. 61 stage budgets
# Terraform (no binary needed locally):
docker run --rm -v $PWD/deploy/terraform:/tf -w /tf/modules/broker-runtime hashicorp/terraform:1.10.5 test
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
keystone/workers/    celery_app (two queues), tasks (thin bodies; JSON logging via setup_logging)
keystone/config/     settings (env > defaults; KEYSTONE_TEST_* reserved; SecretStr secrets)
keystone/telemetry/  clock (adjtimex sync signal), logs (JSON lines, denylist, request/decision ids)
keystone/db/         + provision (deploy init: migrate, partitions, service login role)
keystone/admin/      + opa_config (deploy init: render the OPA sidecar config)
keystone/authz/      + build_bundle (CI entry point), policy_verify/hostile (R2 hostile matrix)
cli/keystone_cli/    main, client (admin HTTP, TLS rule, token sources), output (safe tables),
                     admin (roles/policy/decisions/audit tail/revoke/tokens), replay
action/              keystone-auth composite Action (stdlib Python, 3.10+)
deploy/              compose.yml (+ .env.example), compose.test.yml, terraform/{modules,environments}
tests/mutation/      stdlib AST mutation harness; tests/perf/ stage budgets (opt-in)
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
| Every dependency outage fails closed with Retry-After (Ch. 27) | one error table; PG/Redis/OPA/JWKS/STS/anchor rows | `test_failure_matrix` |
| Verifier catches what it claims to | mutation score gate on chain/verify/canonical | `python -m tests.mutation.run` (CI) |
| Hostile inputs never allowed (R2) | generated absent/wrong-type/fork/org/ref/near-miss matrix per grant seed | `test_hostile_matrix`, policy-bundle CI stage |
| App role creates partitions only via the definer function | migration 0005; no CREATE on schema | `test_schema_pg`, `test_provision_pg` |
| Persisted bundle re-proven before it is served | `restage_active_bundle` re-inspects bytes vs pin | `test_pin_activation_opa` |
| Owner DB URL can never reach a service | provisioning variables are not settings: services refuse to boot | `test_provision_pg` |
| Credentials masked before export (Action) | `::add-mask::` first; heredoc exports with random delimiters | `test_keystone_action` |
| Hostile claim text cannot drive the terminal (CLI) | control/bidi characters escaped in every cell | `test_cli_client`, `test_cli_admin` |

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
- **Staged bundles persist in `policy_bundles`** (append-only, migration 0004), not on disk: the image's rootfs is read-only and the DB is the backed-up, shared store.
- **Compose secrets are env-injected** (Ch. 48 says so); only the two key files are mounted. Compose's env-sourced `secrets:` are copied into containers, which a read-only rootfs refuses.
- **OPA, api and admin share one network namespace** in compose so the Ch. 21 "OPA on localhost" rule holds; admin is published on host loopback only.
- **Overrides apply to the repository bucket only**; `role` rows are not applied (no per-role bucket exists in Ch. 29).
- **`replay` takes the policy input from the operator** and proves it against `input_hash`; the audit record deliberately does not store full inputs.
- **Mutation testing is a stdlib harness**, not `mutmut` (no new dependency); equivalent mutants are listed with a reason in `tests/mutation/run.py`.
- **Terraform target ARNs are built from names** in the root module, avoiding a broker-allowlist <-> trust-policy dependency cycle.

## What to do next (in order)

1. **Commit** the uncommitted Phase 5/6 work (see `git status`; graphify-out/ stays uncommitted).
2. **Decide**: approve `prometheus_client` (metrics, Ch. 51) and a templating library (dashboard,
   Ch. 44), or choose alternatives; then build them.
3. **Decide retention restart semantics** (Ch. 33 says prune only behind an anchor, but every
   verifier starts from genesis or the previous row): e.g. verification resumes from the newest
   anchor at or before the first retained seq, with `prev_hash` taken from that anchor's head.
   Then implement `DROP PARTITION` behind it through a definer function like migration 0005's.
4. **Exercise against real infrastructure**: set the `OPA_BUNDLE_SIGNING_KEY` secret and run the
   bundle workflow (and its Cosign step); `terraform apply` the example root in a sandbox account;
   run `action/` from a real workflow; add the nightly sandbox-AWS job (Ch. 59).
5. **Load/soak harness** (Ch. 61): needs a fake STS + local JWKS issuance path, then k6/Locust.
6. **Smaller owed items**: OPA capabilities file (Ch. 19), decision-lookup index, tracing (Ch. 52),
   image signing + SBOM (Ch. 63), Trivy/pip-audit (Ch. 60), Action release tags + SLSA.

## Known sharp edges

- **Pins made before migration 0004 have no persisted bundle**: the admin plane logs a warning at boot and OPA polls 404 until the next pin.
- **Restarting the `opa` container breaks `api`/`admin` networking** (they live in its namespace); restart all three together.
- **Partition pre-creation depends on beat** running `ensure_partitions` daily (as the service role, via the definer function).
- **Rate-limit `role`-scope override rows are ignored** (see decisions).
- **`KEYSTONE_TRUSTED_PROXIES` must list the load balancers**, or every request behind one shares its address in the policy input.
- **Decision lookup has no index** on `details->'data'->>'decision_id'`. It is bounded by the UUIDv7 timestamp so PostgreSQL prunes older partitions; add an index by migration if it gets slow.
- SQLAlchemy `text()` treats `:word` and `::cast` inside raw DDL as bind parameters: escape with `\:` or use `CAST(...)`.
- PostgreSQL regex repetition counts are capped at 255 (`{1,512}` is an error).
- `opa build -b <absolute path>` records absolute member names; build from `cwd` with `-b .`.
- `opa test` runs without a loaded bundle, so `loaded_bundle_digest` falls back to `"unloaded"` there.
- The `redis` test container must run with `noeviction`; the aggregation client should point at a separate instance in production.
- Admin tokens default to a 30-day TTL when issued through the API; the cap is 90 days.
