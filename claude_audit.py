#!/usr/bin/env python3
"""
claude_audit.py — Security audit for a Claude Code installation + project.

Walks the standard Claude Code config locations (5-layer hierarchy) and reports
on the six security surfaces:

    1. CLAUDE.md      — who can change Claude's instructions, when did it change
    2. Hooks          — shell commands fired on tool events, env mutations, logging
    3. Skills         — auto-discovered capability bundles, trust + provenance
    4. Plugins        — third-party marketplaces, enabled set, supply chain
    5. MCP servers    — outbound endpoints + local commands, sanctioned/shadow
    6. Subagents      — child sessions, their tool permissions + audit trail

Usage:
    python3 claude_audit.py                       # audit ~/.claude and CWD
    python3 claude_audit.py --project /path/proj  # audit specific project
    python3 claude_audit.py --user ~/.claude      # audit specific user dir
    python3 claude_audit.py --json                # machine-readable output
    python3 claude_audit.py --output report.md    # write to file

Exit codes:
    0  no HIGH severity findings
    1  one or more HIGH severity findings
    2  script error (bad path, parse failure, etc.)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Severity levels
# ---------------------------------------------------------------------------

HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}

# ---------------------------------------------------------------------------
# Risk heuristics
# ---------------------------------------------------------------------------

# Shell patterns that suggest a hook can do dangerous things.
DANGEROUS_HOOK_PATTERNS = [
    (re.compile(r"\bcurl\b|\bwget\b"), "network egress (curl/wget)"),
    (re.compile(r"\brm\s+-rf?\b"), "recursive delete (rm -rf)"),
    (re.compile(r"\bsudo\b"), "privilege escalation (sudo)"),
    (re.compile(r"\beval\b"), "shell eval"),
    (re.compile(r"\bexport\s+\w+="), "environment mutation"),
    (re.compile(r"\$\([^)]*\)|`[^`]*`"), "command substitution"),
    (re.compile(r"\bnpm\s+(install|i)\b|\bpip\s+install\b"), "package install"),
    (re.compile(r"chmod\s+(\+x|[0-7]*[7])"), "permission change"),
    (re.compile(r">\s*/dev/null|2>&1.*&\s*$"), "backgrounded with no logging"),
    (re.compile(r"AWS_|GITHUB_TOKEN|API_KEY|SECRET", re.IGNORECASE), "secret reference"),
]

# Tool permissions that grant broad authority when applied to a subagent.
WIDE_TOOL_PERMISSIONS = {"Bash", "Bash(*)", "*", "Write", "Edit"}

# MCP URLs that are not on a well-known sanctioned list.
# Edit this set to match your org's allow-list, or pass --sanctioned-mcp=file
DEFAULT_SANCTIONED_MCP_HOSTS = {
    "mcp.anthropic.com",
    "mcp.asana.com",
    "mcp.atlassian.com",
    "mcp.github.com",
    "mcp.linear.app",
    "mcp.notion.com",
    "mcp.sentry.dev",
    "mcp.slack.com",
}

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    surface: str          # one of: claude_md, hooks, skills, plugins, mcp, subagents
    severity: str         # HIGH | MEDIUM | LOW | INFO
    title: str
    detail: str
    location: str = ""    # filepath or identifier
    evidence: str = ""    # short quote / value
    recommendation: str = ""


@dataclass
class AuditReport:
    started_at: str
    project_dir: str
    user_dir: str
    findings: list[Finding] = field(default_factory=list)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def by_surface(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {}
        for f in self.findings:
            out.setdefault(f.surface, []).append(f)
        for v in out.values():
            v.sort(key=lambda x: (SEVERITY_ORDER[x.severity], x.title))
        return out

    def counts(self) -> dict[str, int]:
        c = {HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        for f in self.findings:
            c[f.severity] += 1
        return c


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def load_json(path: Path) -> dict[str, Any] | None:
    """Tolerant JSON loader: returns None on missing/invalid file."""
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def parse_yaml_frontmatter(text: str) -> dict[str, Any] | None:
    """
    Minimal YAML frontmatter parser. Handles the subset Claude Code uses:
    top-level scalar keys, simple lists (- item), and quoted strings.
    Avoids the PyYAML dependency.
    """
    m = re.match(r"^---\s*\n(.*?)\n---\s*\n", text, re.DOTALL)
    if not m:
        return None
    body = m.group(1)
    result: dict[str, Any] = {}
    current_key: str | None = None
    for raw in body.splitlines():
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        # list item under current_key
        if line.lstrip().startswith("- ") and current_key:
            item = line.lstrip()[2:].strip().strip('"').strip("'")
            if isinstance(result.get(current_key), list):
                result[current_key].append(item)
            else:
                result[current_key] = [item]
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            if not val:
                # next lines may be a list
                result[key] = []
                current_key = key
            else:
                result[key] = val.strip('"').strip("'")
                current_key = key
    return result


def git_log_for(path: Path, repo_root: Path) -> list[str]:
    """Return last 10 commits touching path. Empty list if not a git repo."""
    if not (repo_root / ".git").exists():
        return []
    try:
        rel = str(path.relative_to(repo_root))
    except ValueError:
        return []
    try:
        out = subprocess.run(
            ["git", "-C", str(repo_root), "log", "--oneline", "-n", "10",
             "--format=%h %an <%ae> %ad %s", "--date=short", "--", rel],
            check=True, capture_output=True, text=True, timeout=10,
        )
        return [line for line in out.stdout.splitlines() if line.strip()]
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return []


def is_gitignored(path: Path, repo_root: Path) -> bool:
    if not (repo_root / ".git").exists():
        return False
    try:
        r = subprocess.run(
            ["git", "-C", str(repo_root), "check-ignore", str(path)],
            capture_output=True, text=True, timeout=5,
        )
        return r.returncode == 0
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def repo_root_of(start: Path) -> Path:
    """Walk up to find .git; fall back to start dir."""
    p = start.resolve()
    for d in (p, *p.parents):
        if (d / ".git").exists():
            return d
    return p


def relpath(p: Path, base: Path) -> str:
    try:
        return str(p.relative_to(base))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# Surface 1: CLAUDE.md
# ---------------------------------------------------------------------------

def audit_claude_md(report: AuditReport, project: Path, user: Path) -> None:
    candidates: list[Path] = []
    # global
    for name in ("CLAUDE.md", "CLAUDE.local.md"):
        p = user / name
        if p.is_file():
            candidates.append(p)
    # project — root + subdirectories
    if project.is_dir():
        for p in project.rglob("CLAUDE.md"):
            # skip node_modules / .git / vendor
            parts = set(p.parts)
            if parts & {"node_modules", ".git", "vendor", "dist", "build"}:
                continue
            candidates.append(p)
        for p in project.rglob("CLAUDE.local.md"):
            parts = set(p.parts)
            if parts & {"node_modules", ".git", "vendor", "dist", "build"}:
                continue
            candidates.append(p)

    if not candidates:
        report.add(Finding(
            surface="claude_md",
            severity=INFO,
            title="No CLAUDE.md found",
            detail="Neither user-level nor project-level CLAUDE.md exists. Claude runs with default instructions only.",
            recommendation="If using Claude Code on this project, create a versioned CLAUDE.md so behaviour is reviewable.",
        ))
        return

    repo = repo_root_of(project)
    for path in candidates:
        size = path.stat().st_size
        report.add(Finding(
            surface="claude_md",
            severity=INFO,
            title=f"CLAUDE.md present ({size} bytes)",
            detail="Instructions injected into every Claude Code session for this scope.",
            location=str(path),
        ))

        # Local / gitignored file = nobody is reviewing it
        if path.name == "CLAUDE.local.md" or is_gitignored(path, repo):
            report.add(Finding(
                surface="claude_md",
                severity=HIGH,
                title="CLAUDE.md is local / gitignored",
                detail="Instructions to the agent are not under version control. Nobody else can review changes.",
                location=str(path),
                recommendation="Move shared instructions into the tracked CLAUDE.md. Reserve .local for per-developer overrides.",
            ))

        # Recent commits — if zero, untracked
        log = git_log_for(path, repo)
        if log:
            report.add(Finding(
                surface="claude_md",
                severity=INFO,
                title="Recent CLAUDE.md history",
                detail=f"Last {len(log)} change(s):\n  " + "\n  ".join(log),
                location=str(path),
            ))
        elif (repo / ".git").exists():
            report.add(Finding(
                surface="claude_md",
                severity=MEDIUM,
                title="CLAUDE.md not tracked in git",
                detail="No git history for this file even though the repo uses git. Changes are invisible to reviewers.",
                location=str(path),
                recommendation="git add the file and require CODEOWNER review on the path.",
            ))

        # Pattern-match dangerous instructions inside the file
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        for pattern, label in [
            (r"(?i)ignore (previous|all) (instructions|rules)", "prompt-injection style instruction"),
            (r"(?i)disable (safety|guardrails)", "guardrail disable language"),
            (r"(?i)never ask (for )?confirmation", "auto-approve instruction"),
            (r"(?i)always run (without|with no) confirmation", "auto-approve instruction"),
            (r"(?i)export\s+\w+=", "env var export in instructions"),
            (r"(?i)(AWS_|GITHUB_TOKEN|API_?KEY|SECRET|PASSWORD)", "secret-like token"),
        ]:
            if re.search(pattern, text):
                snippet = next(
                    (line.strip() for line in text.splitlines() if re.search(pattern, line)),
                    "",
                )
                report.add(Finding(
                    surface="claude_md",
                    severity=HIGH,
                    title=f"Suspicious content: {label}",
                    detail="CLAUDE.md contains language that reduces oversight or leaks credentials.",
                    location=str(path),
                    evidence=snippet[:200],
                    recommendation="Remove or replace with explicit, narrow instructions.",
                ))


# ---------------------------------------------------------------------------
# Settings discovery (shared by hooks, plugins, mcp)
# ---------------------------------------------------------------------------

def discover_settings_files(project: Path, user: Path) -> list[tuple[str, Path]]:
    """
    Return [(scope_label, path), ...] in precedence order: managed > project-local
    > project > user-local > user. Only existing files.
    """
    candidates = [
        ("managed",       Path("/Library/Application Support/ClaudeCode/managed-settings.json")),
        ("managed",       Path("/etc/claude-code/managed-settings.json")),
        ("project-local", project / ".claude" / "settings.local.json"),
        ("project",       project / ".claude" / "settings.json"),
        ("user-local",    user / "settings.local.json"),
        ("user",          user / "settings.json"),
        ("user-global",   user.parent / ".claude.json"),  # ~/.claude.json
    ]
    return [(scope, p) for scope, p in candidates if p.is_file()]


# ---------------------------------------------------------------------------
# Surface 2: Hooks
# ---------------------------------------------------------------------------

def audit_hooks(report: AuditReport, settings_files: list[tuple[str, Path]]) -> None:
    found_any = False
    for scope, path in settings_files:
        data = load_json(path)
        if not data:
            continue
        hooks = data.get("hooks") or {}
        if not hooks:
            continue
        found_any = True

        for event, entries in hooks.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                matcher = entry.get("matcher", "*") if isinstance(entry, dict) else "*"
                hook_list = entry.get("hooks", []) if isinstance(entry, dict) else []
                for h in hook_list:
                    cmd = h.get("command", "") if isinstance(h, dict) else str(h)
                    htype = h.get("type", "command") if isinstance(h, dict) else "command"

                    report.add(Finding(
                        surface="hooks",
                        severity=INFO,
                        title=f"{event} hook ({htype}) in {scope}",
                        detail=f"matcher={matcher!r}",
                        location=str(path),
                        evidence=cmd[:300],
                    ))

                    # Risk heuristics on the command body
                    for pattern, label in DANGEROUS_HOOK_PATTERNS:
                        if pattern.search(cmd):
                            sev = HIGH if label in {
                                "privilege escalation (sudo)",
                                "recursive delete (rm -rf)",
                                "secret reference",
                            } else MEDIUM
                            report.add(Finding(
                                surface="hooks",
                                severity=sev,
                                title=f"Hook risk: {label}",
                                detail=f"{event} hook matching {matcher!r} contains {label}.",
                                location=str(path),
                                evidence=cmd[:300],
                                recommendation="Confirm this is intentional, sandboxed, and logged.",
                            ))

                    # PreToolUse with no logging is the classic 'silent intercept'
                    if event == "PreToolUse" and not re.search(r"tee|>>|log|logger", cmd):
                        report.add(Finding(
                            surface="hooks",
                            severity=MEDIUM,
                            title="PreToolUse hook with no apparent logging",
                            detail="Hooks that block or modify tool calls before they execute should write an audit record.",
                            location=str(path),
                            evidence=cmd[:300],
                            recommendation="Append a line to a logfile (e.g. `| tee -a ~/.claude/audit.log`).",
                        ))

    if not found_any:
        report.add(Finding(
            surface="hooks",
            severity=INFO,
            title="No hooks configured",
            detail="No PreToolUse/PostToolUse/Stop/Notification hooks present in any settings layer.",
        ))


# ---------------------------------------------------------------------------
# Surface 3: Skills
# ---------------------------------------------------------------------------

def audit_skills(report: AuditReport, project: Path, user: Path) -> None:
    skill_roots = [
        ("user", user / "skills"),
        ("project", project / ".claude" / "skills"),
    ]
    repo = repo_root_of(project)
    any_found = False

    for scope, root in skill_roots:
        if not root.is_dir():
            continue
        for skill_md in root.rglob("SKILL.md"):
            any_found = True
            skill_dir = skill_md.parent
            report.add(Finding(
                surface="skills",
                severity=INFO,
                title=f"Skill: {skill_dir.name} ({scope})",
                detail="Auto-discovered when the description matches the task.",
                location=str(skill_md),
            ))

            # Parse frontmatter to inspect description trigger
            try:
                text = skill_md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            fm = parse_yaml_frontmatter(text) or {}
            desc = fm.get("description", "")

            # Greedy descriptions get auto-loaded for almost any prompt
            if isinstance(desc, str) and len(desc) < 30:
                report.add(Finding(
                    surface="skills",
                    severity=MEDIUM,
                    title=f"Skill {skill_dir.name!r} has a very short description",
                    detail="Short descriptions over-trigger and pull untrusted instructions into context broadly.",
                    location=str(skill_md),
                    evidence=desc,
                    recommendation="Make the description specific so the skill only loads when actually relevant.",
                ))

            # If skill directory contains executables, that's notable
            for child in skill_dir.iterdir():
                if child.is_file() and os.access(child, os.X_OK) and child.suffix in {
                    "", ".sh", ".py", ".js", ".rb"
                }:
                    report.add(Finding(
                        surface="skills",
                        severity=MEDIUM,
                        title=f"Skill ships executable: {child.name}",
                        detail="Skills can include scripts Claude is encouraged to run. Verify provenance.",
                        location=str(child),
                        recommendation="Pin the skill bundle to a reviewed commit; checksum the executable.",
                    ))

            # Project skill not in git = nobody reviewed it
            if scope == "project" and (repo / ".git").exists():
                if is_gitignored(skill_md, repo) or not git_log_for(skill_md, repo):
                    report.add(Finding(
                        surface="skills",
                        severity=HIGH,
                        title=f"Project skill {skill_dir.name!r} not in version control",
                        detail="A skill loaded automatically by directory context, with no review trail.",
                        location=str(skill_md),
                        recommendation="git add the skill or move it to user scope with a code review on import.",
                    ))

    if not any_found:
        report.add(Finding(
            surface="skills",
            severity=INFO,
            title="No skills installed",
            detail="No SKILL.md found under user or project skill directories.",
        ))


# ---------------------------------------------------------------------------
# Surface 4: Plugins
# ---------------------------------------------------------------------------

def audit_plugins(report: AuditReport, settings_files: list[tuple[str, Path]]) -> None:
    enabled: dict[str, tuple[str, str]] = {}  # plugin -> (scope, file)
    for scope, path in settings_files:
        data = load_json(path)
        if not data:
            continue
        ep = data.get("enabledPlugins") or {}
        if not isinstance(ep, dict):
            continue
        for plugin, on in ep.items():
            if on:
                enabled[plugin] = (scope, str(path))

    if not enabled:
        report.add(Finding(
            surface="plugins",
            severity=INFO,
            title="No plugins enabled",
            detail="No entries in enabledPlugins across settings layers.",
        ))
        return

    for plugin, (scope, file) in enabled.items():
        # Plugin identifier looks like `name@marketplace`. The marketplace is the
        # supply-chain trust boundary.
        marketplace = plugin.split("@", 1)[1] if "@" in plugin else "(unknown)"
        sev = LOW if marketplace == "claude-plugins-official" else MEDIUM
        report.add(Finding(
            surface="plugins",
            severity=sev,
            title=f"Plugin enabled: {plugin}",
            detail=f"Marketplace: {marketplace}. Scope: {scope}.",
            location=file,
            recommendation=(
                "Confirm the marketplace is on your org's approved list. "
                "Pin to a specific plugin version where possible."
            ),
        ))


# ---------------------------------------------------------------------------
# Surface 5: MCP servers
# ---------------------------------------------------------------------------

def audit_mcp(report: AuditReport, project: Path, user: Path,
              settings_files: list[tuple[str, Path]],
              sanctioned: set[str]) -> None:
    servers: list[tuple[str, str, dict[str, Any], str]] = []  # (scope, name, cfg, source)

    # Project .mcp.json
    p_mcp = project / ".mcp.json"
    data = load_json(p_mcp)
    if data and isinstance(data.get("mcpServers"), dict):
        for name, cfg in data["mcpServers"].items():
            servers.append(("project", name, cfg, str(p_mcp)))

    # ~/.claude.json — has per-project mcpServers nested under projects
    home_json = load_json(user.parent / ".claude.json")
    if home_json:
        for name, cfg in (home_json.get("mcpServers") or {}).items():
            servers.append(("user-global", name, cfg, str(user.parent / ".claude.json")))
        for proj_path, proj_cfg in (home_json.get("projects") or {}).items():
            for name, cfg in (proj_cfg.get("mcpServers") or {}).items():
                servers.append((f"user-global:{proj_path}", name, cfg,
                                str(user.parent / ".claude.json")))

    # Managed MCP
    for mp in (Path("/Library/Application Support/ClaudeCode/managed-mcp.json"),
               Path("/etc/claude-code/managed-mcp.json")):
        d = load_json(mp)
        if d and isinstance(d.get("mcpServers"), dict):
            for name, cfg in d["mcpServers"].items():
                servers.append(("managed", name, cfg, str(mp)))

    if not servers:
        report.add(Finding(
            surface="mcp",
            severity=INFO,
            title="No MCP servers configured",
            detail="No .mcp.json, ~/.claude.json mcpServers, or managed MCP file found.",
        ))
        return

    for scope, name, cfg, src in servers:
        url = cfg.get("url") or cfg.get("httpUrl") or ""
        command = cfg.get("command", "")
        args = " ".join(cfg.get("args", [])) if isinstance(cfg.get("args"), list) else ""
        env = cfg.get("env") or {}

        if url:
            host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
            sanctioned_hit = any(host == h or host.endswith("." + h) for h in sanctioned)
            report.add(Finding(
                surface="mcp",
                severity=LOW if sanctioned_hit else HIGH,
                title=f"MCP HTTP server: {name}",
                detail=f"Outbound endpoint from developer machine. Sanctioned: {sanctioned_hit}.",
                location=src,
                evidence=url,
                recommendation=(
                    "Add to managed-mcp.json with the org allow-list."
                    if not sanctioned_hit else
                    "Confirm the connector is the version your security team reviewed."
                ),
            ))
        elif command:
            # stdio MCP — runs a local binary. npx/uvx pull from public registries.
            sev = HIGH if command in {"npx", "uvx", "bunx", "pnpm"} else MEDIUM
            report.add(Finding(
                surface="mcp",
                severity=sev,
                title=f"MCP stdio server: {name}",
                detail=(
                    f"Launches {command!r} {args!r} on every session. "
                    "If the command is npx/uvx/etc the package is fetched on the fly."
                ),
                location=src,
                evidence=f"{command} {args}".strip(),
                recommendation=(
                    "Pin to a specific version (e.g. npx -y pkg@1.2.3) or install the "
                    "binary explicitly and reference it by absolute path."
                ),
            ))

        # Env var leakage from local shell to remote MCP
        for var, val in (env.items() if isinstance(env, dict) else []):
            if isinstance(val, str) and re.search(r"(KEY|TOKEN|SECRET|PASSWORD)", var, re.I):
                report.add(Finding(
                    surface="mcp",
                    severity=MEDIUM,
                    title=f"MCP {name!r} receives secret env var {var}",
                    detail="Secrets passed into the MCP process are visible to whatever code that process runs.",
                    location=src,
                    recommendation="Confirm the MCP binary is trusted; rotate the credential if not.",
                ))


# ---------------------------------------------------------------------------
# Surface 6: Subagents
# ---------------------------------------------------------------------------

def audit_subagents(report: AuditReport, project: Path, user: Path) -> None:
    roots = [
        ("user", user / "agents"),
        ("project", project / ".claude" / "agents"),
    ]
    repo = repo_root_of(project)
    any_found = False

    for scope, root in roots:
        if not root.is_dir():
            continue
        for agent_md in root.rglob("*.md"):
            any_found = True
            try:
                text = agent_md.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            fm = parse_yaml_frontmatter(text) or {}
            name = fm.get("name", agent_md.stem)
            allowed = fm.get("allowedTools") or fm.get("tools") or []
            if isinstance(allowed, str):
                allowed = [allowed]
            mcp_refs = fm.get("mcpServers") or []
            if isinstance(mcp_refs, str):
                mcp_refs = [mcp_refs]

            report.add(Finding(
                surface="subagents",
                severity=INFO,
                title=f"Subagent: {name} ({scope})",
                detail=f"allowedTools={list(allowed) or 'inherited'}; mcpServers={list(mcp_refs) or 'none'}",
                location=str(agent_md),
            ))

            # No tool restriction = inherits everything from the parent
            if not allowed:
                report.add(Finding(
                    surface="subagents",
                    severity=MEDIUM,
                    title=f"Subagent {name!r} has no allowedTools restriction",
                    detail=(
                        "Subagent runs with the parent's full tool surface. Its actions "
                        "happen in a fresh context window — the parent's audit trail "
                        "may not capture per-step tool calls."
                    ),
                    location=str(agent_md),
                    recommendation="Set an explicit allowedTools list (least privilege).",
                ))
            elif WIDE_TOOL_PERMISSIONS & set(allowed):
                report.add(Finding(
                    surface="subagents",
                    severity=MEDIUM,
                    title=f"Subagent {name!r} has broad tool access",
                    detail=f"allowedTools includes {sorted(WIDE_TOOL_PERMISSIONS & set(allowed))}",
                    location=str(agent_md),
                    recommendation="Narrow Bash to specific commands, drop Write/Edit if read-only.",
                ))

            # Project subagent not in git
            if scope == "project" and (repo / ".git").exists():
                if is_gitignored(agent_md, repo) or not git_log_for(agent_md, repo):
                    report.add(Finding(
                        surface="subagents",
                        severity=HIGH,
                        title=f"Project subagent {name!r} not in version control",
                        detail="Subagent definition can be modified silently with no review.",
                        location=str(agent_md),
                        recommendation="git add the file; require CODEOWNER review on .claude/agents/.",
                    ))

    if not any_found:
        report.add(Finding(
            surface="subagents",
            severity=INFO,
            title="No custom subagents defined",
            detail="No agent files found in user or project agent directories.",
        ))


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

SURFACE_TITLES = {
    "claude_md": "1. CLAUDE.md — Who reviews changes?",
    "hooks":     "2. Hooks — Logged and bounded?",
    "skills":    "3. Skills — Trusted to auto-load?",
    "plugins":   "4. Plugins — Approved supply chain?",
    "mcp":       "5. MCP Servers — Sanctioned or shadow?",
    "subagents": "6. Subagents — Audited or blind spot?",
}

SEVERITY_BADGE = {HIGH: "🔴 HIGH", MEDIUM: "🟡 MEDIUM", LOW: "🟢 LOW", INFO: "⚪ INFO"}


def render_markdown(report: AuditReport) -> str:
    counts = report.counts()
    lines: list[str] = []
    lines.append("# Claude Code Security Audit")
    lines.append("")
    lines.append(f"- Started: `{report.started_at}`")
    lines.append(f"- Project dir: `{report.project_dir}`")
    lines.append(f"- User dir: `{report.user_dir}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Severity | Count |")
    lines.append(f"|----------|-------|")
    for sev in (HIGH, MEDIUM, LOW, INFO):
        lines.append(f"| {SEVERITY_BADGE[sev]} | {counts[sev]} |")
    lines.append("")

    by = report.by_surface()
    for surface_key, title in SURFACE_TITLES.items():
        findings = by.get(surface_key, [])
        lines.append(f"## {title}")
        lines.append("")
        if not findings:
            lines.append("_No findings recorded._")
            lines.append("")
            continue
        for f in findings:
            lines.append(f"### {SEVERITY_BADGE[f.severity]} — {f.title}")
            if f.location:
                lines.append(f"- **Location:** `{f.location}`")
            lines.append(f"- **Detail:** {f.detail}")
            if f.evidence:
                ev = f.evidence.replace("`", "'")
                lines.append(f"- **Evidence:** `{ev}`")
            if f.recommendation:
                lines.append(f"- **Recommendation:** {f.recommendation}")
            lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Remediation — generate corrective files based on findings
# ---------------------------------------------------------------------------

@dataclass
class Remediation:
    """A single corrective action produced from one or more findings."""
    kind: str               # "shell" | "file" | "manual"
    title: str              # short headline for the remediation plan
    detail: str             # explanation
    # For "shell": the command to run (idempotent where possible)
    command: str = ""
    # For "file": where the proposed file goes (relative to remediation dir),
    # and the content to write
    rel_path: str = ""
    content: str = ""
    # The original path on disk this replaces, if applicable
    replaces: str = ""
    # Surface + severity carried through for grouping in the plan
    surface: str = ""
    severity: str = INFO


def _emit_yaml_frontmatter(data: dict) -> str:
    """Re-emit a simple YAML frontmatter block from a parsed dict."""
    lines = ["---"]
    for key, val in data.items():
        if isinstance(val, list):
            lines.append(f"{key}:")
            for item in val:
                lines.append(f"  - {item}")
        elif isinstance(val, str) and ("\n" in val or ":" in val):
            # Quote anything ambiguous
            esc = val.replace('"', '\\"')
            lines.append(f'{key}: "{esc}"')
        else:
            lines.append(f"{key}: {val}")
    lines.append("---")
    return "\n".join(lines) + "\n"


def _split_frontmatter(text: str) -> tuple[dict, str]:
    """Return (frontmatter_dict, body) — empty dict if no frontmatter."""
    fm = parse_yaml_frontmatter(text) or {}
    m = re.match(r"^---\s*\n.*?\n---\s*\n", text, re.DOTALL)
    body = text[m.end():] if m else text
    return fm, body


# Sensible least-privilege default for a subagent with no allowedTools set.
SAFE_DEFAULT_ALLOWED_TOOLS = ["Read", "Grep", "Glob"]


def inspect_project(project: Path) -> dict:
    """
    Walk the project root looking for signals that should appear in CLAUDE.md:
    env files, test/lint commands, CI configs, language hints. Returns a dict
    of lists — each list is "what we found" for a category.
    """
    facts: dict[str, list[str]] = {
        "env_files": [],
        "test_commands": [],
        "lint_commands": [],
        "build_commands": [],
        "languages": [],
        "tooling": [],
        "ci_files": [],
        "secret_paths": [],
        "package_managers": [],
    }

    if not project.is_dir():
        return facts

    # 1. .env* files at root (and one level deep) — everything matching .env*
    #    except .env.example / .env.sample / .env.template, which are intended
    #    to be tracked as scaffolding.
    template_pat = re.compile(r"\.env\.(example|sample|template|dist)$", re.I)
    for path in sorted(project.glob(".env*")):
        if path.is_file() and not template_pat.search(path.name):
            facts["env_files"].append(path.name)
    for sub in sorted(project.glob("*/.env*")):
        # Skip node_modules, vendor, dist, build, .git
        if any(p in sub.parts for p in ("node_modules", "vendor", "dist", "build", ".git", ".next")):
            continue
        if sub.is_file() and not template_pat.search(sub.name):
            try:
                facts["env_files"].append(str(sub.relative_to(project)))
            except ValueError:
                pass

    # 2. Other common secret-bearing files
    for name in ("secrets.json", "secrets.yaml", "secrets.yml", "credentials.json",
                 "service-account.json", "firebase-adminsdk.json"):
        if (project / name).is_file():
            facts["secret_paths"].append(name)

    # 3. Language + test/lint detection
    #    Node / JS / TS
    pkg_json = project / "package.json"
    if pkg_json.is_file():
        facts["languages"].append("JavaScript/TypeScript")
        try:
            pkg = json.loads(pkg_json.read_text(encoding="utf-8"))
            scripts = pkg.get("scripts") or {}
            for key, label in [
                ("test", "test_commands"),
                ("test:unit", "test_commands"),
                ("test:e2e", "test_commands"),
                ("lint", "lint_commands"),
                ("lint:fix", "lint_commands"),
                ("typecheck", "lint_commands"),
                ("build", "build_commands"),
            ]:
                if key in scripts:
                    facts[label].append(f"npm run {key}")
            # Detect which package manager
            for pm_file, pm in [("pnpm-lock.yaml", "pnpm"), ("yarn.lock", "yarn"),
                                 ("bun.lockb", "bun"), ("package-lock.json", "npm")]:
                if (project / pm_file).is_file():
                    facts["package_managers"].append(pm)
                    break
        except (json.JSONDecodeError, OSError):
            pass
        if (project / "tsconfig.json").is_file():
            facts["tooling"].append("TypeScript")

    #    Python
    py_signals = [
        (project / "pyproject.toml", "pyproject.toml"),
        (project / "setup.py", "setup.py"),
        (project / "requirements.txt", "requirements.txt"),
        (project / "Pipfile", "Pipfile"),
    ]
    if any(p.is_file() for p, _ in py_signals):
        facts["languages"].append("Python")
        if (project / "pyproject.toml").is_file():
            try:
                pyp = (project / "pyproject.toml").read_text(encoding="utf-8")
                if "pytest" in pyp:
                    facts["test_commands"].append("pytest")
                if "ruff" in pyp:
                    facts["lint_commands"].append("ruff check .")
                if '"black"' in pyp or "[tool.black]" in pyp:
                    facts["lint_commands"].append("black --check .")
                if "[tool.mypy]" in pyp or 'mypy' in pyp:
                    facts["lint_commands"].append("mypy .")
                if "[tool.poetry" in pyp:
                    facts["package_managers"].append("poetry")
                if "[tool.uv" in pyp or "[project]" in pyp:
                    facts["package_managers"].append("uv (or pip)")
            except OSError:
                pass
        if (project / "tests").is_dir() or (project / "test").is_dir():
            if "pytest" not in facts["test_commands"]:
                facts["test_commands"].append("pytest")

    #    Rust
    if (project / "Cargo.toml").is_file():
        facts["languages"].append("Rust")
        facts["test_commands"].append("cargo test")
        facts["lint_commands"].append("cargo clippy")
        facts["build_commands"].append("cargo build")

    #    Go
    if (project / "go.mod").is_file():
        facts["languages"].append("Go")
        facts["test_commands"].append("go test ./...")
        facts["lint_commands"].append("go vet ./...")
        facts["build_commands"].append("go build ./...")

    #    Ruby
    if (project / "Gemfile").is_file():
        facts["languages"].append("Ruby")
        if (project / ".rspec").is_file() or (project / "spec").is_dir():
            facts["test_commands"].append("bundle exec rspec")
        elif (project / "test").is_dir():
            facts["test_commands"].append("bundle exec rake test")
        if (project / ".rubocop.yml").is_file():
            facts["lint_commands"].append("bundle exec rubocop")

    #    Java/Kotlin
    if (project / "pom.xml").is_file():
        facts["languages"].append("Java (Maven)")
        facts["test_commands"].append("mvn test")
        facts["build_commands"].append("mvn package")
    if (project / "build.gradle").is_file() or (project / "build.gradle.kts").is_file():
        facts["languages"].append("Java/Kotlin (Gradle)")
        facts["test_commands"].append("./gradlew test")
        facts["build_commands"].append("./gradlew build")

    #    Makefile fallback — often the canonical entrypoint
    makefile = project / "Makefile"
    if makefile.is_file():
        try:
            mk = makefile.read_text(encoding="utf-8", errors="replace")
            targets = set(re.findall(r"^([a-zA-Z][a-zA-Z0-9_-]*):", mk, re.M))
            for t, label in [("test", "test_commands"), ("lint", "lint_commands"),
                              ("build", "build_commands")]:
                if t in targets and f"make {t}" not in facts[label]:
                    facts[label].insert(0, f"make {t}")
        except OSError:
            pass

    # 4. Linter / formatter config files (independent of language)
    lint_signals = [
        (".eslintrc.json", "ESLint"),
        (".eslintrc.js", "ESLint"),
        (".eslintrc.cjs", "ESLint"),
        ("eslint.config.js", "ESLint"),
        (".prettierrc", "Prettier"),
        (".prettierrc.json", "Prettier"),
        ("prettier.config.js", "Prettier"),
        (".flake8", "Flake8"),
        (".pylintrc", "Pylint"),
        ("ruff.toml", "Ruff"),
        ("biome.json", "Biome"),
    ]
    for fname, label in lint_signals:
        if (project / fname).is_file() and label not in facts["tooling"]:
            facts["tooling"].append(label)

    # 5. CI configs — call out to never modify without review
    ci_signals = [
        ".github/workflows",
        ".gitlab-ci.yml",
        ".circleci/config.yml",
        "azure-pipelines.yml",
        "Jenkinsfile",
        ".buildkite",
        "bitbucket-pipelines.yml",
    ]
    for ci in ci_signals:
        p = project / ci
        if p.exists():
            facts["ci_files"].append(ci)

    # 6. Pre-commit / git hooks
    if (project / ".pre-commit-config.yaml").is_file():
        facts["tooling"].append("pre-commit")

    # 7. Dockerized
    if (project / "Dockerfile").is_file() or (project / "compose.yaml").is_file() \
            or (project / "docker-compose.yml").is_file():
        facts["tooling"].append("Docker")

    # Dedupe while preserving order
    for k, v in facts.items():
        seen = set()
        deduped = []
        for item in v:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        facts[k] = deduped

    return facts


def build_claude_md(project: Path, facts: dict) -> str:
    """Render a project-aware CLAUDE.md from inspect_project() facts."""
    lines: list[str] = []
    lines.append(f"# {project.name} — project conventions")
    lines.append("")
    lines.append(
        "Instructions for AI coding agents working in this repository. "
        "Keep this file under version control — every change to it is a change "
        "to how the agent behaves."
    )
    lines.append("")

    # Stack section — only emit if we detected something
    if facts["languages"] or facts["tooling"] or facts["package_managers"]:
        lines.append("## Stack")
        lines.append("")
        if facts["languages"]:
            lines.append(f"- **Language:** {', '.join(facts['languages'])}")
        if facts["package_managers"]:
            lines.append(f"- **Package manager:** {', '.join(facts['package_managers'])}")
        if facts["tooling"]:
            lines.append(f"- **Tooling:** {', '.join(facts['tooling'])}")
        lines.append("")

    # Build & test — concrete commands or a clear "fill in" prompt
    lines.append("## Build, test, lint")
    lines.append("")
    if facts["test_commands"]:
        lines.append("**Run tests** before considering any task complete:")
        lines.append("")
        lines.append("```bash")
        for cmd in facts["test_commands"]:
            lines.append(cmd)
        lines.append("```")
        lines.append("")
    else:
        lines.append("- (fill in: how to run the test suite — no test framework detected)")
        lines.append("")
    if facts["lint_commands"]:
        lines.append("**Lint / typecheck** before committing:")
        lines.append("")
        lines.append("```bash")
        for cmd in facts["lint_commands"]:
            lines.append(cmd)
        lines.append("```")
        lines.append("")
    else:
        lines.append("- (fill in: lint / format / typecheck command)")
        lines.append("")
    if facts["build_commands"]:
        lines.append("**Build:**")
        lines.append("")
        lines.append("```bash")
        for cmd in facts["build_commands"]:
            lines.append(cmd)
        lines.append("```")
        lines.append("")

    # Secrets — the key user request
    lines.append("## Secrets — never read, never commit, never echo")
    lines.append("")
    if facts["env_files"] or facts["secret_paths"]:
        lines.append("These files contain credentials. Treat as opaque:")
        lines.append("")
        for f in facts["env_files"] + facts["secret_paths"]:
            lines.append(f"- `{f}`")
        lines.append("")
        lines.append(
            "- Do not `cat`, `head`, `Read`, or otherwise display these files.\n"
            "- Do not include their contents in commits, log lines, or error messages.\n"
            "- When a value from one of these is needed, reference it by env var name "
            "(e.g. `process.env.STRIPE_KEY`) without echoing the value."
        )
    else:
        lines.append(
            "No `.env*` or credential files were detected at the project root. "
            "If any are added later, list them here so the agent knows to avoid them."
        )
    lines.append("")

    # CI — never modify without review
    if facts["ci_files"]:
        lines.append("## CI configuration — do not modify without review")
        lines.append("")
        lines.append("These files control what runs on push and merge:")
        lines.append("")
        for f in facts["ci_files"]:
            lines.append(f"- `{f}`")
        lines.append("")
        lines.append(
            "Treat changes here as a separate PR and tag the relevant CODEOWNERS."
        )
        lines.append("")

    # Universal rules
    lines.append("## Things to never do")
    lines.append("")
    lines.append("- Do not commit secrets, API keys, or credentials.")
    lines.append("- Do not disable failing tests to make CI pass — fix the underlying issue.")
    lines.append("- Do not bypass code review by force-pushing to shared branches.")
    if facts["ci_files"]:
        lines.append("- Do not modify CI configuration without explicit approval.")
    lines.append("- Do not delete files outside the scope of the requested change.")
    lines.append("")

    # A footer that explains the file came from --comply
    lines.append("---")
    lines.append("")
    lines.append(
        f"_Generated by `claude_audit.py --comply` on "
        f"{datetime.now(timezone.utc).date().isoformat()}. "
        "Review every line and fill in `(fill in: ...)` placeholders before committing._"
    )
    return "\n".join(lines) + "\n"


def remediate_claude_md(findings: list[Finding], project: Path) -> list[Remediation]:
    out: list[Remediation] = []
    handled_paths: set[str] = set()

    # First pass: collect all paths that are gitignored-by-design. We must NOT
    # later try to `git add` these.
    gitignored_paths: set[str] = set()
    for f in findings:
        if f.surface == "claude_md" and "local / gitignored" in f.title:
            gitignored_paths.add(f.location)

    for f in findings:
        if f.surface != "claude_md":
            continue

        # "No CLAUDE.md found" → generate a project-aware template
        if f.title.startswith("No CLAUDE.md found"):
            facts = inspect_project(project)
            content = build_claude_md(project, facts)
            # Build a detail string that surfaces what we detected, so the user
            # can see the generation isn't blind.
            detail_bits = []
            if facts["languages"]:
                detail_bits.append(f"detected {', '.join(facts['languages'])}")
            if facts["env_files"]:
                detail_bits.append(f"{len(facts['env_files'])} env file(s) called out")
            if facts["test_commands"]:
                detail_bits.append(f"{len(facts['test_commands'])} test command(s)")
            if facts["ci_files"]:
                detail_bits.append("CI configs flagged")
            detail = (
                "Generated from project inspection: " + "; ".join(detail_bits)
                if detail_bits else
                "No stack signals detected — file contains only universal rules and `(fill in)` placeholders."
            )
            out.append(Remediation(
                kind="file",
                title="Create a versioned CLAUDE.md",
                detail=detail,
                rel_path="files/CLAUDE.md",
                content=content,
                surface=f.surface,
                severity=f.severity,
            ))
            continue

        # gitignored / untracked local file → suggest splitting, can't auto-merge
        if "local / gitignored" in f.title:
            if f.location in handled_paths:
                continue
            handled_paths.add(f.location)
            out.append(Remediation(
                kind="manual",
                title=f"Move shared content out of {Path(f.location).name}",
                detail=(
                    "CLAUDE.local.md is gitignored by design. Review its contents and "
                    "move anything the team needs into the tracked CLAUDE.md. Keep only "
                    "per-developer overrides in the .local file."
                ),
                replaces=f.location,
                surface=f.surface,
                severity=f.severity,
            ))
            continue

        # "not tracked in git" → git add command, UNLESS the file is gitignored
        # by design (e.g. CLAUDE.local.md), in which case the gitignored
        # finding above already gave the right guidance.
        if "not tracked in git" in f.title:
            if f.location in gitignored_paths:
                continue
            rel = str(Path(f.location).relative_to(project)) if Path(f.location).is_relative_to(project) else f.location
            out.append(Remediation(
                kind="shell",
                title=f"Track {Path(f.location).name} in git",
                detail="Brings the file under version control so changes get reviewed.",
                command=f'git -C "{project}" add "{rel}"',
                replaces=f.location,
                surface=f.surface,
                severity=f.severity,
            ))
            continue

        # Suspicious content → produce a redacted CLAUDE.md.proposed
        if f.title.startswith("Suspicious content"):
            src = Path(f.location)
            if str(src) in handled_paths or not src.is_file():
                continue
            handled_paths.add(str(src))
            try:
                original = src.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            patched_lines: list[str] = []
            patched_lines.append(
                "<!-- redacted by claude_audit.py --comply on "
                f"{datetime.now(timezone.utc).date().isoformat()} -->\n"
            )
            for line in original.splitlines():
                bad_label = None
                for label, pat in [
                    ("auto-approve", r"(?i)ignore (previous|all) (instructions|rules)"),
                    ("auto-approve", r"(?i)disable (safety|guardrails)"),
                    ("auto-approve", r"(?i)never ask (for )?confirmation"),
                    ("auto-approve", r"(?i)always run (without|with no) confirmation"),
                    ("credential",   r"(?i)(AWS_|GITHUB_TOKEN|API_?KEY|SECRET|PASSWORD)"),
                ]:
                    if re.search(pat, line):
                        bad_label = label
                        break
                if bad_label:
                    patched_lines.append(
                        f"<!-- REDACTED [{bad_label}] — review git history and "
                        f"decide whether to delete or rewrite -->"
                    )
                else:
                    patched_lines.append(line)
            rel = str(src.relative_to(project)) if src.is_relative_to(project) else src.name
            out.append(Remediation(
                kind="file",
                title=f"Redacted {src.name}",
                detail=(
                    "Auto-approve language and secret-like tokens commented out. "
                    "Review each redaction and decide whether to delete or rewrite."
                ),
                rel_path=f"files/{rel}",
                content="\n".join(patched_lines) + "\n",
                replaces=str(src),
                surface=f.surface,
                severity=f.severity,
            ))

    return out


def remediate_hooks(findings: list[Finding], project: Path, user: Path,
                    settings_files: list[tuple[str, Path]]) -> list[Remediation]:
    """
    Add `| tee -a ~/.claude/audit.log` to PreToolUse hooks lacking logging.
    Flag dangerous patterns (sudo, rm -rf, secret refs) for manual review.
    """
    out: list[Remediation] = []
    files_to_patch: set[Path] = set()

    for f in findings:
        if f.surface != "hooks":
            continue
        if "no apparent logging" in f.title:
            files_to_patch.add(Path(f.location))
        elif f.severity == HIGH:
            out.append(Remediation(
                kind="manual",
                title=f"Review hook: {f.title}",
                detail=(
                    f"{f.detail} Evidence: `{f.evidence}`. "
                    "This is too risky to auto-fix — confirm the hook is "
                    "intentional, then either remove it or sandbox it."
                ),
                replaces=f.location,
                surface=f.surface,
                severity=f.severity,
            ))

    # For each settings file that has PreToolUse hooks needing logging, produce
    # a patched copy with `| tee -a ~/.claude/audit.log` appended.
    for path in files_to_patch:
        data = load_json(path)
        if not data:
            continue
        modified = False
        hooks = data.get("hooks") or {}
        for entry in (hooks.get("PreToolUse") or []):
            for h in (entry.get("hooks", []) if isinstance(entry, dict) else []):
                if isinstance(h, dict) and "command" in h:
                    cmd = h["command"]
                    if not re.search(r"tee|>>|log|logger", cmd):
                        # Wrap so the original command still runs, but its
                        # input/output is also recorded.
                        h["command"] = (
                            f"{cmd} 2>&1 | tee -a "
                            f'"$HOME/.claude/audit.log"'
                        )
                        modified = True
        if not modified:
            continue
        try:
            rel = str(path.relative_to(project)) if path.is_relative_to(project) else f"home/{path.name}"
        except ValueError:
            rel = path.name
        out.append(Remediation(
            kind="file",
            title=f"Add logging to PreToolUse hooks in {rel}",
            detail="Wraps each PreToolUse command with `tee -a ~/.claude/audit.log` so the activity is recorded.",
            rel_path=f"files/{rel}",
            content=json.dumps(data, indent=2) + "\n",
            replaces=str(path),
            surface="hooks",
            severity=MEDIUM,
        ))

    return out


def remediate_skills(findings: list[Finding], project: Path) -> list[Remediation]:
    out: list[Remediation] = []
    seen_dirs: set[str] = set()

    for f in findings:
        if f.surface != "skills":
            continue

        # Untracked skill → git add the directory
        if "not in version control" in f.title:
            skill_dir = str(Path(f.location).parent)
            if skill_dir in seen_dirs:
                continue
            seen_dirs.add(skill_dir)
            try:
                rel = str(Path(skill_dir).relative_to(project))
            except ValueError:
                rel = skill_dir
            out.append(Remediation(
                kind="shell",
                title=f"Track skill {Path(skill_dir).name} in git",
                detail="Project-level skills auto-load by directory presence; they should be reviewable.",
                command=f'git -C "{project}" add "{rel}"',
                replaces=skill_dir,
                surface=f.surface,
                severity=f.severity,
            ))

        # Skill ships executable → generate a manifest with SHA256 of each file
        if "ships executable" in f.title:
            exe = Path(f.location)
            skill_dir = exe.parent
            if str(skill_dir) + "::manifest" in seen_dirs:
                continue
            seen_dirs.add(str(skill_dir) + "::manifest")
            try:
                import hashlib
                checksums = {}
                for child in skill_dir.rglob("*"):
                    if child.is_file() and child.name != ".skill-manifest.json":
                        h = hashlib.sha256(child.read_bytes()).hexdigest()
                        checksums[str(child.relative_to(skill_dir))] = h
                manifest = {
                    "skill": skill_dir.name,
                    "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "sha256": checksums,
                }
                try:
                    rel = str(skill_dir.relative_to(project))
                except ValueError:
                    rel = skill_dir.name
                out.append(Remediation(
                    kind="file",
                    title=f"Pin {skill_dir.name} skill with checksums",
                    detail=(
                        "SHA-256 of every file in the skill directory. Commit this manifest "
                        "and verify it in CI to detect drift in skill contents."
                    ),
                    rel_path=f"files/{rel}/.skill-manifest.json",
                    content=json.dumps(manifest, indent=2) + "\n",
                    replaces=str(skill_dir / ".skill-manifest.json"),
                    surface=f.surface,
                    severity=f.severity,
                ))
            except OSError:
                pass

        # Short description → manual (can't infer intent)
        if "very short description" in f.title:
            out.append(Remediation(
                kind="manual",
                title=f"Rewrite skill description",
                detail=(
                    "Description is too vague — the skill will over-trigger. Add specific "
                    "trigger conditions (file types, keywords, task verbs) so it only loads "
                    "when actually relevant."
                ),
                replaces=f.location,
                surface=f.surface,
                severity=f.severity,
            ))

    return out


def remediate_plugins(findings: list[Finding], project: Path) -> list[Remediation]:
    """
    Generate a managed-settings.json template that turns off unsanctioned
    plugins. The org admin deploys this to /Library/Application Support/
    ClaudeCode/managed-settings.json (macOS) or /etc/claude-code/ (Linux).
    """
    shady = []
    for f in findings:
        if f.surface != "plugins":
            continue
        if f.severity == MEDIUM and "Plugin enabled:" in f.title:
            plugin = f.title.replace("Plugin enabled:", "").strip()
            shady.append(plugin)

    if not shady:
        return []

    managed = {
        "_comment": (
            "Managed settings deployed by IT. Wins over user/project settings. "
            "Disables plugins from unsanctioned marketplaces."
        ),
        "enabledPlugins": {p: False for p in shady},
    }
    return [Remediation(
        kind="file",
        title="Block unsanctioned plugins via managed settings",
        detail=(
            "Deploy this to /Library/Application Support/ClaudeCode/managed-settings.json "
            "(macOS) or /etc/claude-code/managed-settings.json (Linux). Users cannot "
            "override managed settings."
        ),
        rel_path="templates/managed-settings.json",
        content=json.dumps(managed, indent=2) + "\n",
        replaces="(deploy at org level)",
        surface="plugins",
        severity=MEDIUM,
    )]


def remediate_mcp(findings: list[Finding], project: Path) -> list[Remediation]:
    out: list[Remediation] = []
    shadow_servers = []

    for f in findings:
        if f.surface != "mcp":
            continue

        # HTTP MCP not on allow-list → flag for managed-mcp.json
        if "MCP HTTP server" in f.title and f.severity == HIGH:
            name = f.title.replace("MCP HTTP server:", "").strip()
            shadow_servers.append((name, f.evidence))

        # npx/uvx unpinned → manual fix needed (we don't know the right version)
        if "MCP stdio server" in f.title and f.severity == HIGH:
            out.append(Remediation(
                kind="manual",
                title=f"Pin version: {f.title}",
                detail=(
                    f"{f.detail} Evidence: `{f.evidence}`. "
                    "Replace `npx -y package` with `npx -y package@x.y.z` or install "
                    "the binary explicitly with an absolute path."
                ),
                replaces=f.location,
                surface=f.surface,
                severity=f.severity,
            ))

        # Secret env var passed to MCP → flag, suggest credential helper
        if "receives secret env var" in f.title:
            out.append(Remediation(
                kind="manual",
                title=f"Externalize credentials for MCP server",
                detail=(
                    f"{f.detail} Replace the inline env value with a reference to your "
                    "OS keychain or a credential helper. Verify the MCP binary is trusted "
                    "before granting it access to the credential."
                ),
                replaces=f.location,
                surface=f.surface,
                severity=f.severity,
            ))

    # Emit a managed-mcp.json template that blocks shadow servers
    if shadow_servers:
        managed = {
            "_comment": (
                "Managed MCP policy. Deploy to /Library/Application Support/ClaudeCode/"
                "managed-mcp.json (macOS) or /etc/claude-code/managed-mcp.json (Linux). "
                "Wins over project .mcp.json and user-global mcpServers."
            ),
            "disallowedServers": [name for name, _ in shadow_servers],
        }
        out.append(Remediation(
            kind="file",
            title="Block shadow MCP servers via managed policy",
            detail=(
                "Lists every shadow (non-sanctioned) MCP host found. Replace with the "
                "actual managed-mcp.json schema your IT team uses if different."
            ),
            rel_path="templates/managed-mcp.json",
            content=json.dumps(managed, indent=2) + "\n",
            replaces="(deploy at org level)",
            surface="mcp",
            severity=HIGH,
        ))

        # Also produce a cleaned project .mcp.json with the shadow servers
        # stripped, so the project-local config is conformant on its own.
        proj_mcp_path = project / ".mcp.json"
        proj_mcp = load_json(proj_mcp_path)
        if proj_mcp and isinstance(proj_mcp.get("mcpServers"), dict):
            shadow_names = {name for name, _ in shadow_servers}
            cleaned = {
                k: v for k, v in proj_mcp["mcpServers"].items()
                if k not in shadow_names
            }
            new_mcp = dict(proj_mcp)
            new_mcp["mcpServers"] = cleaned
            new_mcp["_comment"] = (
                f"Cleaned by claude_audit.py --comply. Removed shadow servers: "
                f"{sorted(shadow_names)}"
            )
            out.append(Remediation(
                kind="file",
                title="Remove shadow MCP servers from project .mcp.json",
                detail=f"Removes {sorted(shadow_names)} from the project config.",
                rel_path="files/.mcp.json",
                content=json.dumps(new_mcp, indent=2) + "\n",
                replaces=str(proj_mcp_path),
                surface="mcp",
                severity=HIGH,
            ))

    return out


def remediate_subagents(findings: list[Finding], project: Path) -> list[Remediation]:
    """
    For subagents with no allowedTools: produce a .md.proposed with a
    least-privilege default. For broad-access subagents: produce a narrowed
    version with the dangerous tools commented out.
    """
    out: list[Remediation] = []
    seen: set[str] = set()

    for f in findings:
        if f.surface != "subagents":
            continue
        path = Path(f.location)
        if not path.is_file() or str(path) in seen:
            if "not in version control" in f.title:
                # Track-in-git is separate — handle below
                pass
            else:
                continue

        if "not in version control" in f.title:
            try:
                rel = str(path.relative_to(project))
            except ValueError:
                rel = str(path)
            out.append(Remediation(
                kind="shell",
                title=f"Track subagent {path.stem} in git",
                detail="Subagent definitions affect what tools child sessions can call.",
                command=f'git -C "{project}" add "{rel}"',
                replaces=str(path),
                surface=f.surface,
                severity=f.severity,
            ))
            continue

        if "has no allowedTools restriction" in f.title or "has broad tool access" in f.title:
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            seen.add(str(path))
            fm, body = _split_frontmatter(text)

            if "has no allowedTools restriction" in f.title:
                fm["allowedTools"] = SAFE_DEFAULT_ALLOWED_TOOLS
                why = (
                    "Set least-privilege default allowedTools (Read/Grep/Glob). "
                    "Add Bash, Write, Edit only if the subagent actually needs them, "
                    "and scope Bash to specific commands where possible."
                )
            else:
                allowed = fm.get("allowedTools") or fm.get("tools") or []
                if isinstance(allowed, str):
                    allowed = [allowed]
                narrowed = [t for t in allowed if t not in WIDE_TOOL_PERMISSIONS]
                if not narrowed:
                    narrowed = list(SAFE_DEFAULT_ALLOWED_TOOLS)
                fm["allowedTools"] = narrowed
                why = (
                    "Removed broad tools (Bash, Write, Edit, *). Re-add only the ones "
                    "this agent demonstrably needs, and scope Bash to specific commands."
                )

            new_text = _emit_yaml_frontmatter(fm) + body
            try:
                rel = str(path.relative_to(project))
            except ValueError:
                rel = path.name
            out.append(Remediation(
                kind="file",
                title=f"Narrow tools for subagent {path.stem}",
                detail=why,
                rel_path=f"files/{rel}",
                content=new_text,
                replaces=str(path),
                surface=f.surface,
                severity=f.severity,
            ))

    return out


def compute_remediations(report: AuditReport, project: Path, user: Path,
                          settings_files: list[tuple[str, Path]]) -> list[Remediation]:
    """Dispatch findings to per-surface remediation builders."""
    findings = report.findings
    out: list[Remediation] = []
    out += remediate_claude_md(findings, project)
    out += remediate_hooks(findings, project, user, settings_files)
    out += remediate_skills(findings, project)
    out += remediate_plugins(findings, project)
    out += remediate_mcp(findings, project)
    out += remediate_subagents(findings, project)
    return out


def write_remediation_bundle(remediations: list[Remediation],
                              out_dir: Path,
                              report: AuditReport) -> None:
    """Write the full remediation directory: README, apply.sh, files/, templates/."""
    out_dir.mkdir(parents=True, exist_ok=True)

    # Group by kind
    shell_remediations = [r for r in remediations if r.kind == "shell"]
    file_remediations = [r for r in remediations if r.kind == "file"]
    manual_remediations = [r for r in remediations if r.kind == "manual"]

    # 1) Proposed files
    for r in file_remediations:
        dest = out_dir / r.rel_path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(r.content, encoding="utf-8")

    # 2) Shell script
    script_lines = [
        "#!/usr/bin/env bash",
        "# Auto-generated by claude_audit.py --comply",
        f"# {report.started_at}",
        f"# Project: {report.project_dir}",
        "#",
        "# Review every line before running. Each command is idempotent.",
        "",
        "set -e",
        "",
    ]
    for r in shell_remediations:
        script_lines.append(f'# [{r.severity}] {r.title}')
        script_lines.append(f'# {r.detail}')
        script_lines.append(r.command)
        script_lines.append("")
    script_lines.append('echo "Done. Run `git status` to review what changed."')
    script_path = out_dir / "apply.sh"
    script_path.write_text("\n".join(script_lines) + "\n", encoding="utf-8")
    script_path.chmod(0o755)

    # 3) Human-readable README
    sev_emoji = {HIGH: "🔴", MEDIUM: "🟡", LOW: "🟢", INFO: "⚪"}
    md = ["# Remediation Plan", "",
          f"Generated `{report.started_at}` from audit of `{report.project_dir}`.", "",
          "## How to apply",
          "",
          "1. **Review** `apply.sh` — these are safe shell commands (mostly `git add`).",
          "2. **Diff** files in `files/` against your originals:",
          "   ```bash",
          "   diff -u /your/original.json files/path/to/original.json",
          "   ```",
          "3. **Manual items** below need your judgment — they cannot be auto-fixed.",
          "4. Run `bash apply.sh` when ready, then copy approved `files/` over the originals.",
          "5. Commit and review the result.",
          "",
          f"## Summary",
          "",
          f"- {len(shell_remediations)} shell commands ready to run",
          f"- {len(file_remediations)} proposed file replacements",
          f"- {len(manual_remediations)} items needing manual judgment",
          ""]

    if shell_remediations:
        md += ["## Shell commands (in `apply.sh`)", ""]
        for r in shell_remediations:
            md.append(f"### {sev_emoji[r.severity]} {r.title}")
            md.append(f"{r.detail}")
            md.append(f"```bash\n{r.command}\n```")
            md.append("")

    if file_remediations:
        md += ["## Proposed file replacements", ""]
        for r in file_remediations:
            md.append(f"### {sev_emoji[r.severity]} {r.title}")
            md.append(f"{r.detail}")
            md.append(f"- **Proposed:** `{r.rel_path}`")
            if r.replaces:
                md.append(f"- **Replaces:** `{r.replaces}`")
            md.append("")
            md.append("Diff against original:")
            md.append(f"```bash\ndiff -u \"{r.replaces}\" \"{r.rel_path}\"\n```")
            md.append("")

    if manual_remediations:
        md += ["## Manual review required", "",
               "These are too context-dependent to auto-fix safely.", ""]
        for r in manual_remediations:
            md.append(f"### {sev_emoji[r.severity]} {r.title}")
            md.append(f"{r.detail}")
            if r.replaces:
                md.append(f"- **Location:** `{r.replaces}`")
            md.append("")

    (out_dir / "REMEDIATION.md").write_text("\n".join(md), encoding="utf-8")


def render_html(report: AuditReport) -> str:
    """Self-contained HTML action plan with persistent checkbox state."""
    counts = report.counts()
    by = report.by_surface()

    # Build an ordered action list: HIGH first, then MEDIUM, then LOW.
    # INFO is informational and goes in a separate collapsed section.
    actionable: list[Finding] = []
    informational: list[Finding] = []
    for f in report.findings:
        if f.severity in (HIGH, MEDIUM, LOW):
            actionable.append(f)
        else:
            informational.append(f)
    actionable.sort(key=lambda x: (SEVERITY_ORDER[x.severity], x.surface, x.title))

    surface_titles = {
        "claude_md": "CLAUDE.md",
        "hooks":     "Hooks",
        "skills":    "Skills",
        "plugins":   "Plugins",
        "mcp":       "MCP Servers",
        "subagents": "Subagents",
    }

    # Storage key — namespaced by project + start time so different audits don't collide.
    storage_key = f"claude-audit::{report.project_dir}::{report.started_at}"

    def esc(s: str) -> str:
        return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                 .replace('"', "&quot;"))

    def action_card(idx: int, f: Finding) -> str:
        sev_class = f.severity.lower()
        action = esc(f.recommendation) if f.recommendation else esc(f.detail)
        # If recommendation is short, use it as the headline; otherwise use the finding title
        headline = esc(f.title)
        loc = esc(f.location) if f.location else ""
        ev = esc(f.evidence) if f.evidence else ""
        detail = esc(f.detail)
        surface_label = surface_titles.get(f.surface, f.surface)

        evidence_block = f'<div class="ev"><span class="ev-label">Evidence</span><code>{ev}</code></div>' if ev else ""
        location_block = f'<div class="loc"><span class="ev-label">Location</span><code>{loc}</code></div>' if loc else ""

        return f"""
<li class="task task-{sev_class}" data-severity="{f.severity}" data-surface="{f.surface}">
  <label class="task-head">
    <input type="checkbox" data-task="{idx}" />
    <span class="sev sev-{sev_class}">{f.severity}</span>
    <span class="surface">{esc(surface_label)}</span>
    <span class="headline">{headline}</span>
  </label>
  <div class="task-body">
    <p class="action"><span class="do">Do this →</span> {action}</p>
    <details>
      <summary>Why</summary>
      <p class="detail">{detail}</p>
      {location_block}
      {evidence_block}
    </details>
  </div>
</li>"""

    action_items_html = "\n".join(action_card(i, f) for i, f in enumerate(actionable))

    info_items_html = "\n".join(
        f"""<li class="info-row" data-surface="{f.surface}">
            <span class="surface">{esc(surface_titles.get(f.surface, f.surface))}</span>
            <span class="info-title">{esc(f.title)}</span>
            <span class="info-detail">{esc(f.detail)}</span>
        </li>"""
        for f in informational
    )

    # Per-surface action counts for the chip row
    per_surface_counts: dict[str, dict[str, int]] = {}
    for f in actionable:
        per_surface_counts.setdefault(f.surface, {HIGH: 0, MEDIUM: 0, LOW: 0})[f.severity] += 1

    surface_chips = "\n".join(
        f"""<button class="chip" data-filter-surface="{key}">
            <span class="chip-label">{esc(label)}</span>
            <span class="chip-counts">
              <span class="chip-h">{per_surface_counts.get(key, {}).get(HIGH, 0)}</span>
              <span class="chip-m">{per_surface_counts.get(key, {}).get(MEDIUM, 0)}</span>
              <span class="chip-l">{per_surface_counts.get(key, {}).get(LOW, 0)}</span>
            </span>
        </button>"""
        for key, label in surface_titles.items()
    )

    actionable_count = len(actionable)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Claude Code Audit — {esc(report.project_dir)}</title>
<style>
  :root {{
    --bg: #0d0e10;
    --panel: #15171b;
    --panel-2: #1c1f25;
    --border: #2a2e36;
    --text: #e8e6e1;
    --text-dim: #8a8f99;
    --text-faint: #5a5f68;
    --high: #ff5d4d;
    --high-bg: rgba(255, 93, 77, 0.08);
    --medium: #f0b429;
    --medium-bg: rgba(240, 180, 41, 0.08);
    --low: #6fcf97;
    --low-bg: rgba(111, 207, 151, 0.06);
    --info: #6a8caf;
    --accent: #e8e6e1;
    --mono: 'JetBrains Mono', 'Fira Code', 'SF Mono', Menlo, Consolas, monospace;
    --serif: 'Iowan Old Style', 'Palatino Linotype', Palatino, 'Hoefler Text', Georgia, serif;
  }}
  * {{ box-sizing: border-box; }}
  html, body {{ margin: 0; padding: 0; background: var(--bg); color: var(--text); }}
  body {{
    font-family: var(--mono);
    font-size: 14px;
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
    padding-bottom: 4rem;
  }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 3rem 2rem; }}

  /* Header */
  .head {{
    display: grid;
    grid-template-columns: 1fr auto;
    gap: 2rem;
    padding-bottom: 2rem;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
  }}
  .head h1 {{
    font-family: var(--serif);
    font-weight: 400;
    font-size: 2.6rem;
    margin: 0 0 0.5rem;
    letter-spacing: -0.02em;
    font-style: italic;
  }}
  .head .sub {{ color: var(--text-dim); font-size: 0.85rem; }}
  .head .sub code {{ color: var(--text); }}
  .head .progress-box {{
    text-align: right;
    border-left: 1px solid var(--border);
    padding-left: 2rem;
  }}
  .head .progress-num {{
    font-family: var(--serif);
    font-size: 3.2rem;
    line-height: 1;
    color: var(--text);
  }}
  .head .progress-num .of {{ color: var(--text-faint); font-size: 1.5rem; }}
  .head .progress-label {{
    color: var(--text-dim);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin-top: 0.4rem;
  }}

  /* Summary counts row */
  .summary {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 0;
    border: 1px solid var(--border);
    margin-bottom: 2.5rem;
  }}
  .summary > div {{
    padding: 1.2rem 1.5rem;
    border-right: 1px solid var(--border);
  }}
  .summary > div:last-child {{ border-right: 0; }}
  .summary .n {{ font-family: var(--serif); font-size: 2.2rem; line-height: 1; }}
  .summary .l {{
    font-size: 0.7rem; text-transform: uppercase;
    letter-spacing: 0.15em; color: var(--text-dim); margin-top: 0.4rem;
  }}
  .summary .high .n {{ color: var(--high); }}
  .summary .medium .n {{ color: var(--medium); }}
  .summary .low .n {{ color: var(--low); }}
  .summary .info .n {{ color: var(--info); }}

  /* Surface chips */
  .chip-row {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin-bottom: 2rem;
  }}
  .chip {{
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text);
    padding: 0.5rem 0.9rem;
    cursor: pointer;
    font-family: var(--mono);
    font-size: 0.78rem;
    display: inline-flex;
    align-items: center;
    gap: 0.7rem;
    transition: border-color 0.15s, background 0.15s;
  }}
  .chip:hover {{ border-color: var(--text-dim); }}
  .chip.active {{ background: var(--panel-2); border-color: var(--text); }}
  .chip-counts {{ display: inline-flex; gap: 0.3rem; font-variant-numeric: tabular-nums; }}
  .chip-h {{ color: var(--high); }}
  .chip-m {{ color: var(--medium); }}
  .chip-l {{ color: var(--low); }}

  /* Section heads */
  h2 {{
    font-family: var(--serif);
    font-weight: 400;
    font-size: 1.4rem;
    font-style: italic;
    margin: 2.5rem 0 1rem;
    color: var(--text);
  }}
  h2 .h2-count {{
    font-family: var(--mono);
    font-size: 0.75rem;
    color: var(--text-dim);
    margin-left: 0.7rem;
    font-style: normal;
    letter-spacing: 0.1em;
  }}

  /* Task list */
  .tasks {{ list-style: none; padding: 0; margin: 0; }}
  .task {{
    border: 1px solid var(--border);
    border-left-width: 3px;
    background: var(--panel);
    margin-bottom: 0.5rem;
    transition: border-color 0.15s, opacity 0.2s;
  }}
  .task-high {{ border-left-color: var(--high); }}
  .task-medium {{ border-left-color: var(--medium); }}
  .task-low {{ border-left-color: var(--low); }}
  .task.done {{ opacity: 0.4; }}
  .task.done .headline {{ text-decoration: line-through; text-decoration-color: var(--text-faint); }}
  .task.hide {{ display: none; }}

  .task-head {{
    display: grid;
    grid-template-columns: auto auto auto 1fr;
    gap: 1rem;
    align-items: baseline;
    padding: 0.9rem 1.2rem;
    cursor: pointer;
    user-select: none;
  }}
  .task-head input[type=checkbox] {{
    appearance: none;
    width: 1.05rem;
    height: 1.05rem;
    border: 1px solid var(--text-dim);
    background: transparent;
    cursor: pointer;
    position: relative;
    top: 2px;
    margin: 0;
  }}
  .task-head input[type=checkbox]:checked {{
    background: var(--text);
    border-color: var(--text);
  }}
  .task-head input[type=checkbox]:checked::after {{
    content: "✓";
    position: absolute;
    color: var(--bg);
    font-size: 0.85rem;
    top: -3px;
    left: 1.5px;
  }}
  .sev {{
    font-size: 0.65rem;
    letter-spacing: 0.15em;
    padding: 0.15rem 0.45rem;
    border: 1px solid currentColor;
  }}
  .sev-high {{ color: var(--high); }}
  .sev-medium {{ color: var(--medium); }}
  .sev-low {{ color: var(--low); }}
  .surface {{
    color: var(--text-dim);
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.12em;
  }}
  .headline {{ color: var(--text); }}

  .task-body {{
    padding: 0 1.2rem 1rem 3.3rem;
    border-top: 1px dashed var(--border);
    margin-top: -1px;
  }}
  .action {{
    margin: 0.9rem 0 0.8rem;
    color: var(--text);
    font-size: 0.92rem;
    line-height: 1.6;
  }}
  .action .do {{
    color: var(--text-faint);
    font-size: 0.68rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-right: 0.6rem;
  }}
  details {{ margin-top: 0.5rem; color: var(--text-dim); }}
  summary {{
    cursor: pointer;
    font-size: 0.75rem;
    color: var(--text-faint);
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 0.3rem 0;
    list-style: none;
  }}
  summary::before {{ content: "+ "; }}
  details[open] summary::before {{ content: "− "; }}
  .detail {{ font-size: 0.85rem; line-height: 1.55; margin: 0.5rem 0; }}
  .ev, .loc {{ margin: 0.4rem 0; font-size: 0.78rem; }}
  .ev-label {{
    display: inline-block;
    color: var(--text-faint);
    font-size: 0.65rem;
    text-transform: uppercase;
    letter-spacing: 0.15em;
    margin-right: 0.6rem;
    min-width: 4.5rem;
  }}
  code {{
    background: var(--panel-2);
    padding: 0.15rem 0.45rem;
    border: 1px solid var(--border);
    color: var(--text);
    font-size: 0.8rem;
    word-break: break-all;
  }}

  /* Informational list */
  .info-list {{ list-style: none; padding: 0; margin: 0; }}
  .info-row {{
    display: grid;
    grid-template-columns: 130px 1fr;
    gap: 1rem;
    padding: 0.7rem 0;
    border-bottom: 1px solid var(--border);
    font-size: 0.85rem;
  }}
  .info-row .info-detail {{ display: block; color: var(--text-dim); font-size: 0.78rem; margin-top: 0.2rem; }}
  .info-row .info-title {{ color: var(--text); }}

  /* Toolbar */
  .toolbar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
    gap: 1rem;
  }}
  .toolbar .left {{ display: flex; gap: 0.5rem; align-items: center; }}
  .toolbar button.tb {{
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-dim);
    font-family: var(--mono);
    font-size: 0.72rem;
    padding: 0.4rem 0.7rem;
    cursor: pointer;
    letter-spacing: 0.1em;
    text-transform: uppercase;
  }}
  .toolbar button.tb:hover {{ color: var(--text); border-color: var(--text-dim); }}
  .toolbar button.tb.active {{ color: var(--text); border-color: var(--text); }}

  footer {{
    margin-top: 4rem;
    padding-top: 2rem;
    border-top: 1px solid var(--border);
    color: var(--text-faint);
    font-size: 0.75rem;
    text-align: center;
  }}
  footer a {{ color: var(--text-dim); }}

  @media (max-width: 700px) {{
    .head {{ grid-template-columns: 1fr; }}
    .head .progress-box {{ border-left: 0; padding-left: 0; text-align: left; }}
    .summary {{ grid-template-columns: repeat(2, 1fr); }}
    .summary > div:nth-child(2) {{ border-right: 0; }}
    .task-head {{ grid-template-columns: auto 1fr; row-gap: 0.4rem; }}
    .task-head .sev, .task-head .surface {{ grid-column: 2; }}
    .task-body {{ padding-left: 1.2rem; }}
  }}
</style>
</head>
<body>
<div class="wrap">

  <header class="head">
    <div>
      <h1>Claude Code Audit</h1>
      <div class="sub">
        <div><code>{esc(report.project_dir)}</code></div>
        <div style="margin-top:0.3rem; color:var(--text-faint);">Generated {esc(report.started_at)}</div>
      </div>
    </div>
    <div class="progress-box">
      <div class="progress-num"><span id="done-count">0</span><span class="of"> / {actionable_count}</span></div>
      <div class="progress-label">tasks resolved</div>
    </div>
  </header>

  <div class="summary">
    <div class="high"><div class="n">{counts[HIGH]}</div><div class="l">High</div></div>
    <div class="medium"><div class="n">{counts[MEDIUM]}</div><div class="l">Medium</div></div>
    <div class="low"><div class="n">{counts[LOW]}</div><div class="l">Low</div></div>
    <div class="info"><div class="n">{counts[INFO]}</div><div class="l">Info</div></div>
  </div>

  <div class="chip-row" id="surface-filter">
    {surface_chips}
  </div>

  <div class="toolbar">
    <div class="left">
      <button class="tb active" data-filter-sev="all">All</button>
      <button class="tb" data-filter-sev="HIGH">High only</button>
      <button class="tb" data-filter-sev="MEDIUM">Medium+</button>
      <button class="tb" data-filter-sev="hide-done">Hide done</button>
    </div>
    <div>
      <button class="tb" id="reset-state">Reset checkmarks</button>
    </div>
  </div>

  <ul class="tasks" id="tasks">
    {action_items_html}
  </ul>

  <h2>Informational <span class="h2-count">{len(informational)} ITEMS</span></h2>
  <ul class="info-list">
    {info_items_html}
  </ul>

  <footer>
    Static HTML — open in any browser. Checkmarks save to your browser's localStorage.
  </footer>
</div>

<script>
(function() {{
  const KEY = {json.dumps(storage_key)};
  const tasks = document.querySelectorAll('.task');
  const doneCount = document.getElementById('done-count');

  // Load saved state
  let state = {{}};
  try {{ state = JSON.parse(localStorage.getItem(KEY) || '{{}}'); }} catch (e) {{ state = {{}}; }}

  function updateProgress() {{
    const total = tasks.length;
    const done = document.querySelectorAll('.task.done').length;
    doneCount.textContent = done;
  }}

  function applyState(li) {{
    const cb = li.querySelector('input[type=checkbox]');
    const id = cb.dataset.task;
    if (state[id]) {{
      cb.checked = true;
      li.classList.add('done');
    }}
  }}

  tasks.forEach(li => {{
    applyState(li);
    const cb = li.querySelector('input[type=checkbox]');
    cb.addEventListener('change', () => {{
      const id = cb.dataset.task;
      if (cb.checked) {{
        state[id] = true;
        li.classList.add('done');
      }} else {{
        delete state[id];
        li.classList.remove('done');
      }}
      localStorage.setItem(KEY, JSON.stringify(state));
      updateProgress();
      applyHideDone();
    }});
  }});
  updateProgress();

  // Severity filter
  let sevFilter = 'all';
  let hideDone = false;
  let surfaceFilter = null;

  function refresh() {{
    tasks.forEach(li => {{
      const sev = li.dataset.severity;
      const surface = li.dataset.surface;
      const isDone = li.classList.contains('done');
      let show = true;
      if (sevFilter === 'HIGH' && sev !== 'HIGH') show = false;
      if (sevFilter === 'MEDIUM' && sev === 'LOW') show = false;
      if (hideDone && isDone) show = false;
      if (surfaceFilter && surface !== surfaceFilter) show = false;
      li.classList.toggle('hide', !show);
    }});
  }}

  function applyHideDone() {{ if (hideDone) refresh(); }}

  document.querySelectorAll('[data-filter-sev]').forEach(btn => {{
    btn.addEventListener('click', () => {{
      const v = btn.dataset.filterSev;
      if (v === 'hide-done') {{
        hideDone = !hideDone;
        btn.classList.toggle('active', hideDone);
      }} else {{
        sevFilter = v;
        document.querySelectorAll('[data-filter-sev]').forEach(b => {{
          if (b.dataset.filterSev !== 'hide-done') b.classList.remove('active');
        }});
        btn.classList.add('active');
      }}
      refresh();
    }});
  }});

  document.querySelectorAll('[data-filter-surface]').forEach(chip => {{
    chip.addEventListener('click', () => {{
      const v = chip.dataset.filterSurface;
      if (surfaceFilter === v) {{
        surfaceFilter = null;
        chip.classList.remove('active');
      }} else {{
        surfaceFilter = v;
        document.querySelectorAll('[data-filter-surface]').forEach(c => c.classList.remove('active'));
        chip.classList.add('active');
      }}
      refresh();
    }});
  }});

  document.getElementById('reset-state').addEventListener('click', () => {{
    if (!confirm('Clear all checkmarks?')) return;
    state = {{}};
    localStorage.removeItem(KEY);
    tasks.forEach(li => {{
      li.classList.remove('done');
      li.querySelector('input[type=checkbox]').checked = false;
    }});
    updateProgress();
  }});
}})();
</script>
</body>
</html>"""


def render_json(report: AuditReport) -> str:
    payload = {
        "started_at": report.started_at,
        "project_dir": report.project_dir,
        "user_dir": report.user_dir,
        "counts": report.counts(),
        "findings": [asdict(f) for f in report.findings],
    }
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("project_pos", nargs="?", default=None, metavar="PROJECT",
                        help="Project directory to audit (positional shorthand for --project)")
    parser.add_argument("--project", default=None,
                        help="Project directory to audit (default: cwd)")
    parser.add_argument("--user", default=str(Path.home() / ".claude"),
                        help="User-level Claude dir (default: ~/.claude)")
    parser.add_argument("--output", "-o", help="Write report to this file instead of stdout")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown")
    fmt.add_argument("--html", action="store_true", help="Emit HTML action plan (best with --output)")
    parser.add_argument("--sanctioned-mcp", action="append", default=[],
                        help="Add a sanctioned MCP host (repeatable)")
    parser.add_argument("--comply", metavar="DIR", default=None,
                        help="Generate a remediation bundle (proposed files + apply.sh) at DIR")
    args = parser.parse_args(argv)

    # Resolve project: positional > --project > cwd
    project_arg = args.project_pos or args.project or os.getcwd()
    project = Path(project_arg).expanduser().resolve()
    user = Path(args.user).expanduser().resolve()

    if not project.is_dir():
        print(f"error: project dir does not exist: {project}", file=sys.stderr)
        return 2

    sanctioned = set(DEFAULT_SANCTIONED_MCP_HOSTS) | set(args.sanctioned_mcp)

    report = AuditReport(
        started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        project_dir=str(project),
        user_dir=str(user),
    )

    settings_files = discover_settings_files(project, user)

    audit_claude_md(report, project, user)
    audit_hooks(report, settings_files)
    audit_skills(report, project, user)
    audit_plugins(report, settings_files)
    audit_mcp(report, project, user, settings_files, sanctioned)
    audit_subagents(report, project, user)

    # Pick renderer: explicit flag > extension auto-detect > markdown default
    out_path = Path(args.output) if args.output else None
    want_html = args.html or (out_path is not None and out_path.suffix.lower() in {".html", ".htm"})
    want_json = args.json or (out_path is not None and out_path.suffix.lower() == ".json")

    if want_html:
        output = render_html(report)
    elif want_json:
        output = render_json(report)
    else:
        output = render_markdown(report)

    if out_path:
        out_path.write_text(output, encoding="utf-8")
    else:
        print(output)

    # If --comply was passed, also emit a remediation bundle.
    if args.comply:
        comply_dir = Path(args.comply).expanduser().resolve()
        remediations = compute_remediations(report, project, user, settings_files)
        write_remediation_bundle(remediations, comply_dir, report)
        # Visible to stderr so it shows up even when stdout is redirected to a file.
        print(f"\nRemediation bundle written to: {comply_dir}", file=sys.stderr)
        print(f"  - {sum(1 for r in remediations if r.kind == 'shell')} shell commands "
              f"in apply.sh", file=sys.stderr)
        print(f"  - {sum(1 for r in remediations if r.kind == 'file')} proposed files "
              f"in files/ and templates/", file=sys.stderr)
        print(f"  - {sum(1 for r in remediations if r.kind == 'manual')} manual review items "
              f"in REMEDIATION.md", file=sys.stderr)

    return 1 if report.counts()[HIGH] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())