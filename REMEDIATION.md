# Remediation Plan

Generated `2026-05-21T04:11:47+00:00` from audit of `/tmp/tmp6qryr4re/fake_project`.

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

- 2 shell commands ready to run
- 8 proposed file replacements
- 6 items needing manual judgment

## Shell commands (in `apply.sh`)

### 🔴 Track skill untracked-skill in git
Project-level skills auto-load by directory presence; they should be reviewable.
```bash
git -C "/tmp/tmp6qryr4re/fake_project" add ".claude/skills/untracked-skill"
```

### 🔴 Track subagent powerful in git
Subagent definitions affect what tools child sessions can call.
```bash
git -C "/tmp/tmp6qryr4re/fake_project" add ".claude/agents/powerful.md"
```

## Proposed file replacements

### 🔴 Redacted CLAUDE.md
Auto-approve language and secret-like tokens commented out. Review each redaction and decide whether to delete or rewrite.
- **Proposed:** `files/CLAUDE.md`
- **Replaces:** `/tmp/tmp6qryr4re/fake_project/CLAUDE.md`

Diff against original:
```bash
diff -u "/tmp/tmp6qryr4re/fake_project/CLAUDE.md" "files/CLAUDE.md"
```

### 🟡 Add logging to PreToolUse hooks in .claude/settings.json
Wraps each PreToolUse command with `tee -a ~/.claude/audit.log` so the activity is recorded.
- **Proposed:** `files/.claude/settings.json`
- **Replaces:** `/tmp/tmp6qryr4re/fake_project/.claude/settings.json`

Diff against original:
```bash
diff -u "/tmp/tmp6qryr4re/fake_project/.claude/settings.json" "files/.claude/settings.json"
```

### 🟡 Pin untracked-skill skill with checksums
SHA-256 of every file in the skill directory. Commit this manifest and verify it in CI to detect drift in skill contents.
- **Proposed:** `files/.claude/skills/untracked-skill/.skill-manifest.json`
- **Replaces:** `/tmp/tmp6qryr4re/fake_project/.claude/skills/untracked-skill/.skill-manifest.json`

Diff against original:
```bash
diff -u "/tmp/tmp6qryr4re/fake_project/.claude/skills/untracked-skill/.skill-manifest.json" "files/.claude/skills/untracked-skill/.skill-manifest.json"
```

### 🟡 Block unsanctioned plugins via managed settings
Deploy this to /Library/Application Support/ClaudeCode/managed-settings.json (macOS) or /etc/claude-code/managed-settings.json (Linux). Users cannot override managed settings.
- **Proposed:** `templates/managed-settings.json`
- **Replaces:** `(deploy at org level)`

Diff against original:
```bash
diff -u "(deploy at org level)" "templates/managed-settings.json"
```

### 🔴 Block shadow MCP servers via managed policy
Lists every shadow (non-sanctioned) MCP host found. Replace with the actual managed-mcp.json schema your IT team uses if different.
- **Proposed:** `templates/managed-mcp.json`
- **Replaces:** `(deploy at org level)`

Diff against original:
```bash
diff -u "(deploy at org level)" "templates/managed-mcp.json"
```

### 🔴 Remove shadow MCP servers from project .mcp.json
Removes ['shady'] from the project config.
- **Proposed:** `files/.mcp.json`
- **Replaces:** `/tmp/tmp6qryr4re/fake_project/.mcp.json`

Diff against original:
```bash
diff -u "/tmp/tmp6qryr4re/fake_project/.mcp.json" "files/.mcp.json"
```

### 🟡 Narrow tools for subagent inheritor
Set least-privilege default allowedTools (Read/Grep/Glob). Add Bash, Write, Edit only if the subagent actually needs them, and scope Bash to specific commands where possible.
- **Proposed:** `files/.claude/agents/inheritor.md`
- **Replaces:** `/tmp/tmp6qryr4re/fake_project/.claude/agents/inheritor.md`

Diff against original:
```bash
diff -u "/tmp/tmp6qryr4re/fake_project/.claude/agents/inheritor.md" "files/.claude/agents/inheritor.md"
```

### 🟡 Narrow tools for subagent powerful
Removed broad tools (Bash, Write, Edit, *). Re-add only the ones this agent demonstrably needs, and scope Bash to specific commands.
- **Proposed:** `files/.claude/agents/powerful.md`
- **Replaces:** `/tmp/tmp6qryr4re/fake_project/.claude/agents/powerful.md`

Diff against original:
```bash
diff -u "/tmp/tmp6qryr4re/fake_project/.claude/agents/powerful.md" "files/.claude/agents/powerful.md"
```

## Manual review required

These are too context-dependent to auto-fix safely.

### 🔴 Move shared content out of CLAUDE.local.md
CLAUDE.local.md is gitignored by design. Review its contents and move anything the team needs into the tracked CLAUDE.md. Keep only per-developer overrides in the .local file.
- **Location:** `/tmp/tmp6qryr4re/fake_project/CLAUDE.local.md`

### 🔴 Review hook: Hook risk: recursive delete (rm -rf)
PostToolUse hook matching 'Edit' contains recursive delete (rm -rf). Evidence: `sudo rm -rf /tmp/junk`. This is too risky to auto-fix — confirm the hook is intentional, then either remove it or sandbox it.
- **Location:** `/tmp/tmp6qryr4re/fake_project/.claude/settings.json`

### 🔴 Review hook: Hook risk: privilege escalation (sudo)
PostToolUse hook matching 'Edit' contains privilege escalation (sudo). Evidence: `sudo rm -rf /tmp/junk`. This is too risky to auto-fix — confirm the hook is intentional, then either remove it or sandbox it.
- **Location:** `/tmp/tmp6qryr4re/fake_project/.claude/settings.json`

### 🟡 Rewrite skill description
Description is too vague — the skill will over-trigger. Add specific trigger conditions (file types, keywords, task verbs) so it only loads when actually relevant.
- **Location:** `/tmp/tmp6qryr4re/fake_project/.claude/skills/untracked-skill/SKILL.md`

### 🔴 Pin version: MCP stdio server: fs
Launches 'npx' '-y @modelcontextprotocol/server-filesystem /tmp' on every session. If the command is npx/uvx/etc the package is fetched on the fly. Evidence: `npx -y @modelcontextprotocol/server-filesystem /tmp`. Replace `npx -y package` with `npx -y package@x.y.z` or install the binary explicitly with an absolute path.
- **Location:** `/tmp/tmp6qryr4re/fake_project/.mcp.json`

### 🟡 Externalize credentials for MCP server
Secrets passed into the MCP process are visible to whatever code that process runs. Replace the inline env value with a reference to your OS keychain or a credential helper. Verify the MCP binary is trusted before granting it access to the credential.
- **Location:** `/tmp/tmp6qryr4re/fake_project/.mcp.json`
