## Summary

**Before.** What was missing or wrong, in a sentence or two.

**Now:**
-

The changelog has an entry (for a change to the profile or the checker).

## Test plan

- [ ] `ruff check .` and `pytest -q` in `checker/` (for checker changes)
- [ ] The checker still sends only GET, HEAD and OPTIONS to endpoints in `SAFE_PATHS` (for checker changes)
- [ ] No addresses, ports, folder names or pictures of your own in this pull request
