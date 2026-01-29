# Release checklist (template)

1) Run checks

```bash
./scripts/check.sh
```

2) Update version (Cargo.toml) if applicable.

3) Update docs (API, install).

4) Tag and push

```bash
git tag -a vX.Y.Z -m "vX.Y.Z"
git push --tags
```

5) (Optional) Build and attach binary artifacts.
