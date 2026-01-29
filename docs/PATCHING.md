# Patching workflow (recommended)

To avoid brittle exact-match edits, prefer unified diffs.

## Generate a patch

- Use `git diff` to produce a patch.
- Or use your coding agent to output a unified diff.

## Apply a patch

```bash
git apply --check /path/to/patch.diff
git apply /path/to/patch.diff
```

If it fails due to context drift:

```bash
git apply --3way /path/to/patch.diff
```

## Why

Exact-match replacements are fragile after formatting changes. Unified diffs are reliable and reviewable.
