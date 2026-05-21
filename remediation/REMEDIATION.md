# Remediation Plan

Generated `2026-05-21T04:21:04+00:00` from audit of `/Users/sudhiseshachala/projects/narratr-website`.

## How to apply

1. **Review** `apply.sh` — these are safe shell commands (mostly `git add`).
2. **Diff** files in `files/` against your originals:
   ```bash
   diff -u /your/original.json files/path/to/original.json
   ```
3. **Manual items** below need your judgment — they cannot be auto-fixed.
4. Run `bash apply.sh` when ready, then copy approved `files/` over the originals.
5. Commit and review the result.

## Summary

- 1 shell commands ready to run
- 1 proposed file replacements
- 0 items needing manual judgment

## Shell commands (in `apply.sh`)

### 🔴 Track skill integration-nextjs-app-router in git
Project-level skills auto-load by directory presence; they should be reviewable.
```bash
git -C "/Users/sudhiseshachala/projects/narratr-website" add ".claude/skills/integration-nextjs-app-router"
```

## Proposed file replacements

### ⚪ Create a versioned CLAUDE.md
Provides Claude with project conventions, reviewable through normal PR process.
- **Proposed:** `files/CLAUDE.md`

Diff against original:
```bash
diff -u "" "files/CLAUDE.md"
```
