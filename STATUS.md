# STATUS.md — implementation progress against HANDOFF phases

Updated 2026-10-23. Spec of record: vault `docs/05-corrections-round2-R1-R9-FINAL.md`.

## Phase 1 — Audit chain (R1) — DONE, VERIFIED
- [x] `audit_events` (month-partitioned, append-only via grants + trigger), `audit_chain_head`
- [x] RFC 8785 canonical bytes as sole hashing/rendering source; `details` verify-checked equal
- [x] Pure verifier with snapshot head (R7-ready); online + offline CLI (`keystone audit verify/export`)
- [x] 71 unit + 16 integration tests; ruff, mypy --strict, CI workflow

### Deliberately NOT done in Phase 1 (owed to later phases)
- [ ] `audit_events.issuance_id` FK → `issuances` (Phase 3, table does not exist yet)
- [ ] `audit_anchors` table, Ed25519 anchor signing, S3 Object Lock mirror, anchor-signature
      verification in `/verify` (Phase 4, R7 `keystone-anchor` worker)
- [ ] Scheduled verification task + issuance breaker on anchor-store unreachability (Phase 4)
- [x] Partition pre-creation: migration 0005 `keystone_ensure_audit_partition` (SECURITY DEFINER,
      bounded window) so the least-privilege worker can create months ahead (it could not before)
- [ ] Retention DROP PARTITION — BLOCKED on a design decision: the spec says "prune only behind an
      anchor" but not how verification restarts after a pruned prefix (see HANDOFF)
- [x] `GET /v1/audit/events`, `/v1/audit/verify`, `/v1/decisions/{id}` HTTP surface (Phase 5)
- [ ] `audit verify --offline` reading `pg_dump` + S3 anchors (Ch. 33) — current offline mode
      reads the JSONL produced by `audit export`; pg_dump input deferred to Phase 4 with anchors
- [x] Mutation testing on chain + verifier (Ch. 57) — Phase 6
- [x] Admin-plane commands `roles`, `policy`, `decisions`, `revoke`, `replay`, `tokens` (Ch. 45)

## Phase 2 — Policy validator `keystone-policy-verify` (R2) — DONE, VERIFIED
- [x] Parses via `opa parse` AST (no second Rego parser); transitive call graph from
      `data.keystone.authz.decision`; dynamic refs (`grants[name].allow`) reach every grant
- [x] Rejects: NOT_OVER_INPUT (direct, transitive, inside functions), PERMISSIVE_DEFAULT,
      PERMISSIVE_ELSE, MASKING_BUILTIN (object.get/union over input), UNGUARDED_ITERATION
      (every/comprehension without count>0), UNGUARDED_CLAIM (input.identity.* without
      is_*/literal-set guard), WITH_OVERRIDE, MISSING_ENTRY, DENY_WITHOUT_REASON (F3)
- [x] Precise `rule (file:row:col): reason` output; exit codes 0/1/2; `--json`
- [x] 14 negative + 2 positive fixture bundles; reference policy with `opa test` at 100% coverage
- [x] `policy-bundle.yml`: fmt/check/test/verify gate → CI-stamped `bundle_sequence` (R8) →
      `opa build` → Cosign keyless sign; signing is unreachable unless the validator passed

### Deliberately NOT done in Phase 2
- [x] Hostile-matrix generator (`keystone.authz.policy_verify.hostile`): absent / wrong-type per
      referenced claim + fork / wrong-org / mutated-ref / near-miss repo; seeds per grant
      (`tests/policy/hostile_seeds.json`, an unseeded grant fails); required CI stage before signing
- [ ] Cosign keyless step is written but UNVERIFIED locally (needs GitHub OIDC)
- [ ] OPA capabilities file disabling non-deterministic builtins (Ch. 19) — Phase 4 with sidecar
- [ ] Validator treats `deny*`-named rules as exempt only when never used as an allow condition;
      negation inside presence guards (`not is_null`) is not special-cased — authors use `is_*`

## Phase 3 — DB schema + AWS STS broker — DONE (core), VERIFIED
- [x] Migration 0002: target_roles, session_policy_templates (inline policy <= 2048), policy_pins
      (one active, CI-assigned bundle_sequence), admin_principals/admin_tokens (90-day cap),
      issuances (state enum, jti_hash + session_name unique, TTL 900-3600), rate_limit_overrides,
      audit_anchors (append-only), audit_events.issuance_id FK; least-privilege grants
- [x] RoleRegistry (DB half of the double allowlist; disabled/unknown role and template refused)
- [x] TTL clamp lattice (Ch. 25): floor/ceiling/policy-cap/registry-max, strict deny mode
- [x] CredentialConnector Protocol + AwsStsConnector: region-pinned, botocore retries OFF,
      Throttling retried once, timeout after send = indeterminate (never blind-retried),
      AccessDenied 502 / MalformedPolicyDocument 500 / unreachable 503, Expiration ~ now+ttl check,
      closed attribution-tag set, redacted repr
- [x] Issuance state machine + repository (AMB-3: denials write no row; idempotent by state)
- [x] IssuanceService: T1 authorize row committed before mint, mint outside any transaction,
      T2 audit + state in one transaction; refusals audited in their own transaction;
      session_name = ks-{repository_id}-{run_id}-{decision_seq} (AMB-4)
- [x] Settings (Ch. 47): env > defaults, unknown KEYSTONE_* keys refuse boot

### Deliberately NOT done in Phase 3
- [x] Revocation mechanisms 2-4 (Ch. 26 / F6 ordering, `keystone revoke role`) — Phase 5
- [x] Policy-pin repository + two-phase activation (R5) and admin-token auth — Phase 4/5
- [x] Startup issuance reconciler (R6) that resolves AUTHORIZED/INDETERMINATE rows — Phase 5
- [x] Terraform modules (Ch. 64) in `deploy/terraform/`: broker-runtime (exact allowlist + Deny
      NotResource), target-role (trust needs `ks-*` session + keystone tags; mechanism-3 flag off),
      anchor-bucket (Object Lock COMPLIANCE 400 d), network; `terraform validate` + 11 mock-provider
      `terraform test` guardrail runs pass. Never applied against a real account (UNVERIFIED in AWS)
- [ ] STS verified against moto + botocore Stubber only; no nightly sandbox-AWS run yet (Ch. 59)
- [x] `POST /v1/credentials` and the OIDC verification stage that produces IdentityContext (Phase 4/5)
- [ ] `updated_at` maintenance is app-side; no DB trigger

## Phase 4 — OPA + rate limiting + worker isolation — DONE (core), VERIFIED
- [x] Replay protection: SET NX PX on sha256(jti), TTL covers exp + skew (Ch. 30, AMB-2, F11)
- [x] Rate limiting R3: Tier 0 global shedding (not IP-keyed), Tier 1 per-identity/per-repo with
      registry overrides, Tier 2 STS in-flight cap; one atomic Lua bucket; Redis down = 503
- [x] Aggregation R4: bounded cardinality + overflow bucket + HyperLogLog estimate, one chained
      row per bucket, at-least-once flush; aggregation client can point at its own Redis
- [x] OIDC verification (Ch. 17/31) + three-tier JWKS cache (Ch. 18) with the forgery suite
- [x] Authorization stage (Ch. 19, F3, F7): OPA sidecar evaluator, strict decision schema,
      explainability, per-request digest vs pin (503 POLICY_PIN_DIVERGENCE), audited before use
- [x] Two-phase pin activation (R5) + CI-assigned monotonic sequence (R8): OPA polls a
      Keystone-served, OPA-signed bundle; pin commits only after OPA confirms; forced rollback
      loudly audited; content-digest revision proven against bundle contents
- [x] Anchoring (Ch. 32/33, A8): Ed25519-signed anchors chained to each other, external
      write-once store written before the DB row commits; S3 Object Lock COMPLIANCE store
- [x] Scheduled verification (F9/R7): snapshot head, closed range, anchor signature + linkage
      checks, pages on divergence; breaker trips only on anchor-store unreachability
- [x] Celery topology (Ch. 9/R7): `keystone-anchor` queue isolated from `keystone-worker`

### Deliberately NOT done in Phase 4
- [ ] OPA capabilities file disabling non-deterministic builtins (Ch. 19)
- [x] Bundle-server endpoint on the admin plane; staged bundle persisted (migration 0004) and
      re-staged on boot, verified live across admin + OPA restarts
- [x] policy-bundle.yml builds via `python -m keystone.authz.build_bundle` (content-digest
      revision — the old git-SHA revision could never be pinned — OPA key from the
      `OPA_BUNDLE_SIGNING_KEY` secret via env). UNVERIFIED on GitHub: needs that secret; Cosign
      keyless step still unexercised
- [x] Redis `noeviction` primary + separate `allkeys-lru` aggregation instance in `deploy/compose.yml`
- [ ] Retention pruning (DROP PARTITION only behind an anchor) and JWKS/aggregation task wiring
      have bodies but no end-to-end worker run
- [ ] S3 conditional put (`IfNoneMatch: *`) is on by default but only moto-tested without it

## Phase 5 — Reconcilers + API/CLI + deploy — DONE except metrics/dashboard (blocked on deps)
- [x] Issuance reconciler (R6): one transaction per row, `indeterminate` until the 20 min
      CloudTrail window passes, `issued_undelivered` when a session is found, never rewrites
- [x] Revocation (Ch. 26, F6): flagged -> IAM deny policy -> read-back confirm -> applied;
      mechanism 3 OFF by default renders the runbook policy; reverse-crash backfill
- [x] `POST /v1/credentials` request pipeline (Tier 0 -> verify -> Tier 1 -> anchor breaker (R7)
      -> authorize -> issue -> single-shot response -> mark delivered) + `/healthz` and the
      Ch. 41 transport/schema layers and Ch. 43 error envelope (uniform pre-auth 401, no-store,
      request_id), in `keystone/api/`; `uvicorn --factory keystone.api.app:app_from_env`
- [x] Admin plane slice 1 (`keystone/admin/`, own listener:
      `uvicorn --factory keystone.admin.app:admin_app_from_env`): hash-stored bearer tokens with
      env bootstrap (KEYSTONE_ADMIN_BOOTSTRAP_TOKEN, registered once when no principal exists,
      24 h), `GET|POST /v1/admin/tokens`, `DELETE /v1/admin/tokens/{id}`; `/readyz` (PG, Redis,
      OPA loaded digest vs pin, anchor breaker, JWKS fresh-or-grace; unauthenticated, states
      only); `GET|POST /v1/policy/pins`, `GET /v1/policy/status`; bundle route for the OPA
      sidecar behind KEYSTONE_BUNDLE_SERVICE_TOKEN (`opa_config_yaml(bearer_token_path=...)`)
- [x] Admin plane slice 2: `GET|POST /v1/roles`, `GET|PATCH /v1/roles/{name}` (role_arn not
      patchable), `GET|POST /v1/roles/{name}/session-policies` (Statement + STS size checked), all
      audited as `admin_role_changed` with the acting principal; `POST /v1/revocations` (any
      registered role, enabled or not, per Ch. 26 escalation; not_before never in the future);
      `GET /v1/decisions/{id}` (decision + outcome events), `GET /v1/audit/events` (keyset,
      event_type filter), `GET /v1/audit/verify` (snapshot head, 100k events per call),
      `GET /v1/issuances` (UUIDv7 keyset, state filter). Events render from `canonical_payload`.
- [x] Fail-closed gaps closed: PostgreSQL loss on the public path was a 500, now 503
      `KEYSTONE_DEPENDENCY_UNAVAILABLE`; every 503 now carries `Retry-After` (Ch. 27)
- [x] Rate-limit overrides wired from `rate_limit_overrides` (repository scope; the table has no
      identity scope); `per_minute = 0` blocks without the old divide-by-zero in Lua
- [x] Trusted-proxy `source_ip` (`KEYSTONE_TRUSTED_PROXIES`, off by default; uvicorn run with
      `--no-proxy-headers`), `/readyz` clock-sync check (kernel adjtimex, Ch. 31), structured JSON
      logging with a field denylist and message-free exception frames (Ch. 49)
- [x] Operator CLI (Ch. 45): `roles`, `policy {status,pin,history}`, `decisions {get,tail}`,
      `audit {verify,export,tail}`, `revoke role`, `replay`, `tokens`; tables + `--json`; 0/1/2;
      token from env/file only; terminal-escape-safe output. `replay` needs the decision's input
      (`--input`, proven against the recorded `input_hash`). Keychain storage not done (needs a dep)
- [x] Docker image (non-root, read-only rootfs, locked venv) + `deploy/compose.yml` (OPA/api/admin
      share a netns; two queues + beat; provision + opa-config init steps); smoke-tested live:
      provision, pin via CLI, OPA reload after admin+OPA restarts, partition task as service role
- [x] GitHub Action `action/` (Ch. 46): mask first, fresh OIDC token per retry, 2/4/8 s on 429/503,
      heredoc exports. UNVERIFIED on a real runner; release tagging/SLSA/Cosign not done
- [ ] Decision lookup has no expression index on `details->'data'->>'decision_id'` (add if slow)
- [ ] Metrics (Ch. 51) — needs `prometheus_client` (new dependency: awaiting approval)
- [ ] Dashboard (Ch. 44) — needs a templating library (new dependency: awaiting approval)
- [ ] Tracing (Ch. 52), image signing/SBOM (Ch. 63), Trivy/pip-audit in CI (Ch. 60)

## Phase 6 — Invariant test suite — DONE except load/soak
- [x] Ch. 27 failure table as one matrix (`tests/integration/test_failure_matrix.py`): OPA, PG,
      Redis, STS, JWKS cold/warm/expired, Celery worker, anchor store; 503 + Retry-After + no mint
- [x] Mutation testing (`python -m tests.mutation.run`, stdlib AST mutator, CI gate >= 95%): 100%
      (71/71) on chain + verifier + canonical after closing 4 test gaps (forged head hash with the
      right seq, non-object canonical payload, container/type comparisons, equal booleans)
- [x] Ch. 61 stage budgets (`KEYSTONE_RUN_PERF=1 pytest tests/perf -s`): p95 verify 0.24 ms,
      OPA 0.73 ms, audit commit 1.38 ms; chain-head ceiling ~630 appends/s at 16 writers (burst
      target needs ~400) — single dev machine, not a CI baseline
- [ ] Poisson 50 rps / burst 200 rps load harness, 24 h soak, p95 regression gate (k6 not installed;
      needs a fake STS + local JWKS issuance path)
- [ ] Nightly sandbox-AWS job (Ch. 59) for trust-policy correctness
