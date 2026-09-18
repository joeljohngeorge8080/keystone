# CLAUDE.md — Keystone implementation repo

The authoritative design lives in the Obsidian vault at
`~/Documents/Obsidian Vault/keystone/` — read its `CLAUDE.md`, `HANDOFF.md`, and
`docs/05-corrections-round2-R1-R9-FINAL.md` (the FROZEN spec + anchor list) before
changing security-relevant code. The invariants listed there are non-negotiable.

Decisions taken at kickoff (2026-09-18), not restated in the spec:
- Python 3.12 service AND Python CLI (spec Ch. 45 wins over HANDOFF's "Go CLI").
- Product-owner defaults accepted: mechanism-3 revocation OFF, anchor-lag breaker at
  spec default, retention 400 days / monthly partitions.
- `audit_events` PK is `(seq, occurred_at)` because PostgreSQL requires the monthly
  partition key inside every unique constraint (Ch. 34 + Ch. 36 reconciled).
- JCS canonicalization via the `rfc8785` package; the verifier never re-canonicalizes,
  it hashes the stored `canonical_payload` bytes only (R1).

Toolchain: `uv sync`, `uv run ruff check .`, `uv run mypy`, `uv run pytest`.
Integration tests need `KEYSTONE_TEST_DATABASE_URL` (see `deploy/compose.test.yml`).
Layout follows spec Ch. 55: code lives with the layer that owns its data.
