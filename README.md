# Claude Code Security Audit

A single-file Python auditor for the six security surfaces in a Claude Code
installation:

1. **CLAUDE.md** — who reviews changes to the file that programs the agent?
2. **Hooks** — what shell runs on every tool call, and is it logged?
3. **Skills** — what auto-loads into context based on directory presence?
4. **Plugins** — which third-party marketplaces are trusted?
5. **MCP servers** — what outbound endpoints + local binaries are wired in?
6. **Subagents** — child sessions, their tool permissions, audit trail?

## Usage

```bash
# Audit current directory + ~/.claude (Markdown to stdout)
python3 claude_audit.py

# Audit a specific project (positional or --project)
python3 claude_audit.py /path/to/repo
python3 claude_audit.py --project /path/to/repo

# HTML action plan — checkable task list with persistent state
python3 claude_audit.py /path/to/repo --output audit.html
# (or explicitly: --html)

# JSON output for CI / SIEM ingestion
python3 claude_audit.py --json > report.json
python3 claude_audit.py --output report.json    # auto-detected

# Add MCP hosts to your org's sanctioned allow-list
python3 claude_audit.py --sanctioned-mcp mcp.internal.corp --sanctioned-mcp mcp.acme.io
```

Output format is auto-detected from the `--output` extension (`.html`, `.json`,
or anything else → Markdown), or set explicitly with `--html` / `--json`.

Exit code is `1` if any HIGH-severity finding exists — wire into CI.

## The HTML report

Open the file in any browser. Designed as an action plan, not a report:

- **Top of page:** progress counter (`N / total tasks resolved`)
- **Action items** sorted HIGH → MEDIUM → LOW, each as a checkable task with the recommendation surfaced as "Do this →"
- **Filter** by severity (All / High only / Medium+ / Hide done) or by surface (chip row at the top)
- **Checkbox state persists** in localStorage, namespaced by project path + timestamp
- **Detail / evidence / location** collapsed by default — expand per-task as you triage
- Fully offline, no external resources or fonts

## `--comply` — generate the fixes

```bash
python3 claude_audit.py /path/to/project --comply ./remediation
```

Writes a self-contained remediation bundle:

```
remediation/
├── REMEDIATION.md                         # human-readable plan
├── apply.sh                               # safe shell commands (mostly `git add`)
├── files/                                 # proposed file replacements
│   ├── CLAUDE.md                          # with credential / auto-approve lines redacted
│   ├── .claude/settings.json              # PreToolUse hooks wrapped in `tee -a audit.log`
│   ├── .claude/agents/<name>.md           # subagents with allowedTools narrowed
│   ├── .claude/skills/<name>/.skill-manifest.json   # SHA-256 of each file
│   └── .mcp.json                          # shadow servers stripped
└── templates/
    ├── managed-settings.json              # blocks unsanctioned plugins org-wide
    └── managed-mcp.json                   # blocks shadow MCP servers org-wide
```

**Two principles:**
1. **Nothing is modified in place.** Proposed files go to a separate directory you `diff` against the originals.
2. **Risky changes are flagged for manual review**, not auto-fixed. The script will not remove a `sudo` or `rm -rf` hook for you — those go in the "manual review" section of `REMEDIATION.md`.

### Applying

```bash
# 1. Review
less remediation/REMEDIATION.md
bash -n remediation/apply.sh             # syntax check
diff -u .claude/settings.json remediation/files/.claude/settings.json

# 2. Apply
bash remediation/apply.sh                # runs the git adds
cp -r remediation/files/. .              # copies proposed files over originals

# 3. Verify
python3 claude_audit.py . --comply ./remediation-pass2   # see what's left
```

In the smoketest, this drops HIGH findings 9 → 4 and MEDIUM 10 → 7. The remainder are intentionally manual (the `sudo` and `rm -rf` hooks, the `npx`-unpinned MCP, the credential env var) because auto-removing them could break the developer's intentional setup.

## What it checks

| Surface     | Heuristics |
|-------------|------------|
| CLAUDE.md   | git tracking, recent commits, prompt-injection-style language, hard-coded secrets |
| Hooks       | curl/wget, sudo, rm -rf, env mutation, command substitution, package installs, missing logging on PreToolUse |
| Skills      | not in git, short / over-broad description, executable scripts shipped in skill dir |
| Plugins     | marketplace identity, official vs unknown source |
| MCP         | sanctioned vs shadow host, npx/uvx (on-the-fly fetch), secret env vars passed in |
| Subagents   | no allowedTools restriction (inherits parent), broad tools (Bash, Write, Edit, *), not in git |

## Layout

```
claude_audit.py    # the auditor (stdlib only, Python 3.9+)
smoketest.py       # builds a fake install with planted issues, asserts each is caught
generate_sample.py # writes sample_report.md from the fixture
sample_report.md   # what the output looks like
```

## Adapting to your org

The two main knobs:

- `DEFAULT_SANCTIONED_MCP_HOSTS` at the top of `claude_audit.py` — set this to
  your org's approved MCP endpoint list (or pass `--sanctioned-mcp` repeatedly).
- `DANGEROUS_HOOK_PATTERNS` — add patterns specific to your environment
  (custom internal CLIs, secret formats, etc).

## CI integration

```yaml
# .github/workflows/claude-audit.yml
- run: python3 tools/claude_audit.py --project . --json > claude-audit.json
- run: python3 tools/claude_audit.py --project .   # fails build on HIGH
```

## Caveats

- Heuristic, not exhaustive. A clean report means "no obvious red flags," not "secure."
- Static analysis only — it reads config and matches patterns. It does not
  execute hooks, contact MCP servers, or fetch plugin source.
- Sanctioned MCP list defaults to a few well-known providers (Asana, Atlassian,
  GitHub, Linear, Notion, Sentry, Slack, Anthropic). Replace with yours.
