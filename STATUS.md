# STATUS.md — implementation progress against HANDOFF phases

Updated 2026-09-18. Spec of record: vault `docs/05-corrections-round2-R1-R9-FINAL.md`.

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
- [ ] Partition pre-creation beyond the 14 months seeded by migration 0001 and retention
      DROP PARTITION (Phase 4 retention worker) — inserts outside a partition fail closed
- [ ] `GET /v1/audit/events`, `/v1/audit/verify`, `/v1/decisions/{id}` HTTP surface (Phase 5)
- [ ] `audit verify --offline` reading `pg_dump` + S3 anchors (Ch. 33) — current offline mode
      reads the JSONL produced by `audit export`; pg_dump input deferred to Phase 4 with anchors
- [ ] Mutation testing on chain + verifier (Ch. 57) — Phase 6
- [ ] Admin-plane commands `roles`, `policy`, `decisions`, `revoke`, `replay`, `tokens` (Ch. 45)

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
- [ ] Hostile-matrix generator (claim-absent / wrong-type / fork / wrong-org permutations
      auto-generated per referenced claim) — R2 requires it alongside the validator before
      signing; reference policy covers these cases by hand in `authz_test.rego` for now
- [ ] Cosign keyless step is written but UNVERIFIED locally (needs GitHub OIDC)
- [ ] OPA capabilities file disabling non-deterministic builtins (Ch. 19) — Phase 4 with sidecar
- [ ] Validator treats `deny*`-named rules as exempt only when never used as an allow condition;
      negation inside presence guards (`not is_null`) is not special-cased — authors use `is_*`

## Phase 3 — DB schema + AWS STS broker — not started
## Phase 4 — OPA + rate limiting + worker isolation — not started
## Phase 5 — Reconcilers + API/CLI — not started
## Phase 6 — Invariant test suite — not started
