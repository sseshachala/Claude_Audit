#!/usr/bin/env python3
"""
smoketest_comply.py — Validates the --comply remediation bundle.

End-to-end test:
  1. Build the fake project (re-using setup_fixture from smoketest.py)
  2. Run claude_audit.py --comply
  3. Assert the remediation directory structure is correct
  4. Apply the remediations (run apply.sh, copy proposed files over originals)
  5. Re-run the audit and assert that fixed findings have disappeared
"""
from __future__ import annotations
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from smoketest import setup_fixture  # type: ignore

HERE = Path(__file__).parent
AUDIT = HERE / "claude_audit.py"


def run_audit_json(project: Path, user: Path, *extra: str) -> dict:
    r = subprocess.run(
        [sys.executable, str(AUDIT), str(project),
         "--user", str(user), "--json", *extra],
        capture_output=True, text=True,
    )
    if r.returncode not in (0, 1):
        print("STDOUT:", r.stdout)
        print("STDERR:", r.stderr)
        raise SystemExit(2)
    return json.loads(r.stdout)


def apply_proposed_files(remediation_dir: Path, project: Path) -> int:
    """Copy files/ contents over the originals in the project. Returns count."""
    files_dir = remediation_dir / "files"
    if not files_dir.is_dir():
        return 0
    count = 0
    for proposed in files_dir.rglob("*"):
        if not proposed.is_file():
            continue
        rel = proposed.relative_to(files_dir)
        target = project / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(proposed, target)
        count += 1
    return count


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        project, user = setup_fixture(root)
        comply_dir = root / "remediation"

        # ---- Phase 1: Initial audit + generate remediation ----
        before = run_audit_json(project, user, "--comply", str(comply_dir))
        before_counts = before["counts"]
        print(f"Before: HIGH={before_counts['HIGH']} MEDIUM={before_counts['MEDIUM']} "
              f"LOW={before_counts['LOW']} INFO={before_counts['INFO']}")

        # ---- Phase 2: Validate remediation directory structure ----
        assert comply_dir.is_dir(), "remediation dir not created"
        assert (comply_dir / "REMEDIATION.md").is_file(), "REMEDIATION.md missing"
        assert (comply_dir / "apply.sh").is_file(), "apply.sh missing"
        apply_sh = (comply_dir / "apply.sh").read_text()
        assert apply_sh.startswith("#!/usr/bin/env bash"), "apply.sh missing shebang"
        assert "set -e" in apply_sh
        # Should contain git add commands for untracked things
        assert "git -C" in apply_sh and "add" in apply_sh, "no git add commands"

        # Should have proposed files for content fixes
        files_dir = comply_dir / "files"
        assert files_dir.is_dir(), "files/ dir missing"
        proposed_files = list(files_dir.rglob("*"))
        proposed_file_count = sum(1 for p in proposed_files if p.is_file())
        assert proposed_file_count >= 3, f"expected ≥3 proposed files, got {proposed_file_count}"

        # Should have managed templates for shadow plugins/MCP
        templates_dir = comply_dir / "templates"
        assert templates_dir.is_dir(), "templates/ dir missing"
        assert (templates_dir / "managed-settings.json").is_file(), \
            "managed-settings.json template missing"
        assert (templates_dir / "managed-mcp.json").is_file(), \
            "managed-mcp.json template missing"

        # Managed settings should disable shady-tool
        ms = json.loads((templates_dir / "managed-settings.json").read_text())
        assert "shady-tool@some-random-marketplace" in ms.get("enabledPlugins", {})
        assert ms["enabledPlugins"]["shady-tool@some-random-marketplace"] is False

        # Managed MCP should disallow shady server
        mm = json.loads((templates_dir / "managed-mcp.json").read_text())
        assert "shady" in mm.get("disallowedServers", []), \
            f"shady not in disallowedServers: {mm}"

        # Verify proposed CLAUDE.md has redactions
        proposed_claudemd = files_dir / "CLAUDE.md"
        assert proposed_claudemd.is_file(), "CLAUDE.md.proposed missing"
        claudemd_content = proposed_claudemd.read_text()
        assert "REDACTED" in claudemd_content, "CLAUDE.md not redacted"
        assert "AWS_ACCESS_KEY" not in claudemd_content or \
               "REDACTED" in [line for line in claudemd_content.splitlines()
                               if "AWS_ACCESS_KEY" in line][0]

        # Verify proposed settings.json has logging added
        proposed_settings = files_dir / ".claude" / "settings.json"
        assert proposed_settings.is_file(), "settings.json.proposed missing"
        settings = json.loads(proposed_settings.read_text())
        pre_hooks = settings["hooks"]["PreToolUse"]
        assert any("tee" in h["command"] and "audit.log" in h["command"]
                    for entry in pre_hooks for h in entry["hooks"]), \
            "logging not added to PreToolUse"

        # Verify subagent .md files were narrowed
        proposed_powerful = files_dir / ".claude" / "agents" / "powerful.md"
        proposed_inheritor = files_dir / ".claude" / "agents" / "inheritor.md"
        assert proposed_powerful.is_file()
        assert proposed_inheritor.is_file()
        powerful_text = proposed_powerful.read_text()
        inheritor_text = proposed_inheritor.read_text()
        # Powerful: Bash/Write/Edit should be gone
        assert "Bash" not in powerful_text.split("---")[1], \
            f"powerful still has Bash:\n{powerful_text}"
        # Inheritor: should now have an allowedTools list with safe defaults
        assert "allowedTools" in inheritor_text
        assert "Read" in inheritor_text and "Grep" in inheritor_text

        print("✓ Remediation bundle structure valid")
        print(f"  apply.sh has {apply_sh.count('git -C')} git commands")
        print(f"  files/ has {proposed_file_count} proposed replacements")
        print(f"  templates/ has managed-settings.json + managed-mcp.json")

        # ---- Phase 3: Apply the remediations ----
        # Run apply.sh (only does git adds — won't break anything)
        r = subprocess.run(["bash", str(comply_dir / "apply.sh")],
                            capture_output=True, text=True, cwd=str(project))
        assert r.returncode == 0, f"apply.sh failed: {r.stderr}"

        # Copy proposed files over originals
        applied = apply_proposed_files(comply_dir, project)
        # Stage the copied files too, then commit everything so the audit's
        # git-log-based "tracked" check sees them.
        subprocess.run(["git", "add", "-A"], cwd=str(project),
                       capture_output=True, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "apply remediation"],
                       cwd=str(project), capture_output=True, check=True)
        print(f"✓ Applied: {applied} files copied, apply.sh ran cleanly, committed")

        # ---- Phase 4: Re-audit and verify findings dropped ----
        after = run_audit_json(project, user)
        after_counts = after["counts"]
        print(f"After:  HIGH={after_counts['HIGH']} MEDIUM={after_counts['MEDIUM']} "
              f"LOW={after_counts['LOW']} INFO={after_counts['INFO']}")

        # We expect a meaningful drop in HIGH and MEDIUM (not necessarily zero,
        # because manual items remain — sudo rm -rf hook, npx MCP, secret env).
        assert after_counts["HIGH"] < before_counts["HIGH"], \
            f"HIGH didn't drop: {before_counts['HIGH']} → {after_counts['HIGH']}"
        assert after_counts["MEDIUM"] <= before_counts["MEDIUM"], \
            f"MEDIUM grew: {before_counts['MEDIUM']} → {after_counts['MEDIUM']}"

        drop_high = before_counts["HIGH"] - after_counts["HIGH"]
        drop_med = before_counts["MEDIUM"] - after_counts["MEDIUM"]
        print(f"✓ Findings dropped after remediation: HIGH -{drop_high}, MEDIUM -{drop_med}")

        # Specific findings that should be GONE after fixing:
        after_titles = [f["title"] for f in after["findings"]]

        should_be_gone = [
            "Suspicious content: auto-approve",  # redacted in CLAUDE.md
            "Suspicious content: secret-like",   # redacted in CLAUDE.md
            "has no allowedTools restriction",   # inheritor now has Read/Grep/Glob
            "has broad tool access",             # powerful had Bash/Write/Edit stripped
            "PreToolUse hook with no apparent logging",  # tee added
        ]
        for needle in should_be_gone:
            still_present = [t for t in after_titles if needle in t]
            assert not still_present, \
                f"still found '{needle}' after remediation: {still_present}"

        # Specific findings that should STILL be present (manual review items):
        should_remain = [
            "privilege escalation (sudo)",        # didn't auto-remove the rm -rf hook
        ]
        for needle in should_remain:
            still_present = [t for t in after_titles if needle in t]
            assert still_present, \
                f"expected to still see '{needle}' (manual item), but it's gone"

        print("✓ Targeted findings correctly disappeared / remained")

        # ---- Phase 5: Sanity check the REMEDIATION.md ----
        rmmd = (comply_dir / "REMEDIATION.md").read_text()
        for needed in ["# Remediation Plan", "## How to apply", "## Summary",
                        "diff -u"]:
            assert needed in rmmd, f"REMEDIATION.md missing section: {needed}"

        # ---- Copy sample bundle to outputs for delivery ----
        out_root = Path("/mnt/user-data/outputs")
        out_root.mkdir(parents=True, exist_ok=True)
        dest = out_root / "sample_remediation"
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(comply_dir, dest)
        print(f"✓ Sample remediation bundle: {dest}")

    print("\nPASS — comply mode works end-to-end")
    return 0


if __name__ == "__main__":
    sys.exit(main())
