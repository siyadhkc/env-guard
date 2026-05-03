# env_guard/scanner.py

import os
from pathlib import Path
from typing import Generator

from env_guard.rules import RULES, SKIP_DIRS, SKIP_EXTENSIONS
from env_guard.custom_rules import load_custom_rules


# Each finding is a plain dict — no classes needed at this scale
# {
#   "file":     str  — relative path to the file
#   "line":     int  — line number (1-indexed)
#   "rule":     str  — rule name
#   "severity": str  — HIGH / MEDIUM / LOW
#   "content":  str  — the actual line that matched (stripped)
# }


def _is_skippable_dir(path: Path) -> bool:
    """Return True if this directory should be completely ignored."""
    return path.name in SKIP_DIRS


def _is_skippable_file(path: Path) -> bool:
    """Return True if this file should be skipped based on extension."""
    return path.suffix.lower() in SKIP_EXTENSIONS


def _load_ignore_patterns(base_path: Path) -> list[str]:
    """
    Read .envguardignore from the scanned directory root.
    One glob pattern per line. Lines starting with # are comments.
    Returns a list of pattern strings.
    """
    ignore_file = base_path / ".envguardignore"
    if not ignore_file.exists():
        return []

    patterns = []
    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _is_ignored(path: Path, base_path: Path, ignore_patterns: list[str]) -> bool:
    """
    Check if a file matches any pattern in .envguardignore.
    """
    if not ignore_patterns:
        return False

    from fnmatch import fnmatch
    relative = str(path.relative_to(base_path)).replace("\\", "/")

    for pattern in ignore_patterns:
        # Strip trailing slash from directory patterns like "tests/"
        clean_pattern = pattern.rstrip("/")

        # Exact match against relative path
        if relative == clean_pattern:
            return True

        # Directory prefix match — "tests/" should only ignore files INSIDE tests/
        if pattern.endswith("/"):
            if relative.startswith(clean_pattern + "/"):
                return True

        # Glob match against full relative path
        if fnmatch(relative, pattern):
            return True

        # Glob match against filename only (for patterns like "*.log")
        if "/" not in pattern and fnmatch(path.name, pattern):
            return True

    return False


def _walk_files(base_path: Path, ignore_patterns: list[str]) -> Generator[Path, None, None]:
    """
    Walk the directory tree and yield every file we should scan.
    Skips ignored dirs, skippable extensions, and .envguardignore patterns.
    """
    for root, dirs, files in os.walk(base_path):
        root_path = Path(root)

        # Prune skip dirs IN PLACE — this stops os.walk from descending into them
        # This is the correct way. Beginners often filter after the fact,
        # which means os.walk still descends into node_modules (slow).
        dirs[:] = [
            d for d in dirs
            if not _is_skippable_dir(root_path / d)
        ]

        for filename in files:
            file_path = root_path / filename

            if _is_skippable_file(file_path):
                continue

            if _is_ignored(file_path, base_path, ignore_patterns):
                continue

            yield file_path


def _scan_file(file_path: Path, base_path: Path, rules: list[dict] = None) -> list[dict]:
    if rules is None:
        from env_guard.rules import RULES
        rules = RULES
    """
    Scan a single file against all rules.
    Returns a list of finding dicts.
    """
    findings = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except (PermissionError, OSError):
        # Can't read the file — skip silently
        return findings

    lines = content.splitlines()

    for line_number, line in enumerate(lines, start=1):
        for rule in rules:
            if rule["pattern"].search(line):
                findings.append({
                    "file": str(file_path.relative_to(base_path)).replace("\\", "/"),
                    "line": line_number,
                    "rule": rule["name"],
                    "severity": rule["severity"],
                    "content": line.strip()[:120],  # cap at 120 chars — tokens/keys can be long
                })

    return findings

def scan(path: str) -> dict:
    """
    Main entry point. Scans the given path recursively.
    """
    base_path = Path(path).resolve()

    if not base_path.exists():
        raise FileNotFoundError(f"Path does not exist: {path}")

    # Load custom rules and merge with built-in rules
    # Custom rules are appended — they run after built-in rules
    custom = load_custom_rules(str(base_path if base_path.is_dir() else base_path.parent))
    all_rules = RULES + custom

    if base_path.is_file():
        ignore_patterns = _load_ignore_patterns(base_path.parent)
        findings = _scan_file(base_path, base_path.parent, all_rules)
        return {
            "findings": findings,
            "scanned": 1,
            "skipped": 0,
            "errors": [],
            "custom_rules_loaded": len(custom),
        }

    ignore_patterns = _load_ignore_patterns(base_path)

    all_findings = []
    scanned = 0

    for file_path in _walk_files(base_path, ignore_patterns):
        findings = _scan_file(file_path, base_path, all_rules)
        all_findings.extend(findings)
        scanned += 1

    return {
        "findings": all_findings,
        "scanned": scanned,
        "skipped": 0,
        "errors": [],
        "custom_rules_loaded": len(custom),
    }
