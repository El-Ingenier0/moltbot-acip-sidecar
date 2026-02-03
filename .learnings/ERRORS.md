# Errors Log

## [ERR-20260128-001] functions.edit exact-match failure

**Logged**: 2026-01-28T14:49:30-06:00
**Priority**: medium
**Status**: pending
**Area**: backend

### Summary
`functions.edit` failed because the target text in `src/main.rs` did not match exactly (whitespace/newlines differed).

### Error
```
⚠️ 📝 Edit: ~/clawd/acip-sidecar/src/main.rs failed: Could not find the exact text in /home/ceverett/clawd/acip-sidecar/src/main.rs. The old text must match exactly including all whitespace and newlines.
```

### Context
- Operation attempted: patching `src/main.rs` via `functions.edit`
- Root cause: `functions.edit` is strict; any formatting change (e.g., `cargo fmt`) or small drift prevents an exact oldText match.

### Suggested Fix
- Prefer one of:
  - `functions.read` the exact current snippet first, then apply `functions.edit` with exact matching text.
  - Generate and apply a unified diff via `git apply` for non-trivial edits.
  - Use smaller, more targeted `oldText` anchors.

### Metadata
- Reproducible: yes
- Related Files: src/main.rs
- Tags: tooling, patching, exact-match

---
