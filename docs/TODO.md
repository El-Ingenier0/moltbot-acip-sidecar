# TODO

This file tracks follow-up work for **acip-sidecar**.

Principles:
- Prefer small, reviewable PRs.
- Anything security-relevant should include tests and clear documentation.

## P0 — Security / correctness

- [ ] **Extractor output cap hardening**: add a regression test proving the parent enforces output caps even if the helper writes more than expected.
- [ ] **Sentry JSON parsing ambiguity**: if tolerant parsing is enabled (default), detect/handle multiple JSON candidates (e.g., refuse if more than one valid candidate parses).
- [ ] **HTML parser DoS budgeting**: add explicit normalization CPU/memory budget notes + consider a stricter default cap for `normalize.max_input_chars`.

## P1 — Robustness / ops

- [ ] **Canonicalize host reputation keys**:
  - IPv6 bracket normalization decision (keep brackets vs strip).
  - Add an explicit helper + docs for canonical form.
- [ ] **Reputation store durability sweep**: add a test path for quarantine rename failure (exercise copy/remove fallback).
- [ ] **More deterministic normalization steps**: ensure `normalization_steps` ordering is stable and documented.

## P2 — DX / docs

- [ ] Add `--json-logs` option (and implement JSON log formatter), with docs + examples.

- [ ] Add a short **SECURITY.md** section describing the invariants:
  - fenced content only
  - tools hard caps
  - caller tool authorization
  - extractor sandbox boundary
- [ ] Add a release process note on when to update `CHANGE_LOG.md` (manual vs generated).

## Backlog

- [ ] Optional: add a `CHANGELOG.md` (Keep a curated human-facing version separate from `CHANGE_LOG.md` which is a commit timeline).
- [ ] Optional: structured log events / metrics for:
  - extractor timeouts
  - model call failures (L1/L2)
  - quarantine events
