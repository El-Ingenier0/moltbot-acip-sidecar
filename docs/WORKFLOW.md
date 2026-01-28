# Development workflow (SOP)

## Rule: review after each checklist item

When working a TODO list:

1. Implement exactly one checklist item.
2. Run:
   - `cargo fmt`
   - `cargo test`
   - `cargo clippy -- -D warnings`
3. Do a *targeted code review* of **only the files changed by that item**:
   - re-read the diff
   - sanity-check error handling, security boundaries, and API behavior
   - update tests if behavior changed
4. Only then mark the item as complete (checkbox).
5. Commit with a message that names the item.

This keeps changes small and prevents checklist-driven regressions.
