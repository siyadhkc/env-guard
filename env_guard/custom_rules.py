# env_guard/custom_rules.py
#
# Loads user-defined rules from rules.yml.
# Checks two locations in order:
#   1. Home directory  (~/.env-guard/rules.yml)  — global rules
#   2. Project root    (./rules.yml)             — per-project rules
#
# Rules from both locations are merged.
# Project rules take priority — if same name exists in both,
# project rule wins.

import re
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Valid severity values
VALID_SEVERITIES = {"HIGH", "MEDIUM", "LOW"}


def _load_yaml_file(path: Path) -> list[dict]:
    """
    Load and parse a single rules.yml file.
    Returns a list of raw rule dicts from the file.
    Handles missing file, bad YAML, and invalid rules gracefully.
    """
    if not path.exists():
        return []

    try:
        import yaml
    except ImportError:
        logger.warning("pyyaml not installed. Custom rules disabled. Run: pip install pyyaml")
        return []

    try:
        content = path.read_text(encoding="utf-8")
        data = yaml.safe_load(content)
    except Exception as e:
        logger.warning(f"Failed to parse {path}: {e}")
        return []

    if not isinstance(data, dict):
        logger.warning(f"{path}: expected a YAML dict at top level, got {type(data)}")
        return []

    rules = data.get("rules", [])

    if not isinstance(rules, list):
        logger.warning(f"{path}: 'rules' key must be a list")
        return []

    return rules


def _validate_and_compile(raw: dict, source: Path) -> dict | None:
    """
    Validate a single raw rule dict and compile its regex.
    Returns a compiled rule dict or None if invalid.
    """
    # Required fields
    name = raw.get("name", "").strip()
    pattern = raw.get("pattern", "").strip()
    severity = raw.get("severity", "MEDIUM").strip().upper()

    if not name:
        logger.warning(f"{source}: rule missing 'name' field, skipping")
        return None

    if not pattern:
        logger.warning(f"{source}: rule '{name}' missing 'pattern' field, skipping")
        return None

    if severity not in VALID_SEVERITIES:
        logger.warning(f"{source}: rule '{name}' has invalid severity '{severity}', defaulting to MEDIUM")
        severity = "MEDIUM"

    # Compile the regex — catch bad patterns so they don't crash the scanner
    try:
        compiled = re.compile(pattern)
    except re.error as e:
        logger.warning(f"{source}: rule '{name}' has invalid regex: {e}, skipping")
        return None

    return {
        "name": name,
        "pattern": compiled,
        "severity": severity,
        "source": str(source),   # track where this rule came from
        "custom": True,          # flag so reporter can show [custom] label
    }


def load_custom_rules(project_path: str = ".") -> list[dict]:
    """
    Main entry point. Load custom rules from:
      1. ~/.env-guard/rules.yml  (global)
      2. <project_path>/rules.yml (per-project)

    Project rules override global rules with the same name.
    Returns a list of compiled rule dicts ready for the scanner.
    """
    home_rules_path    = Path.home() / ".env-guard" / "rules.yml"
    project_rules_path = Path(project_path).resolve() / "rules.yml"

    # Load both files
    global_raw  = _load_yaml_file(home_rules_path)
    project_raw = _load_yaml_file(project_rules_path)

    # Compile all rules — track by name for deduplication
    compiled: dict[str, dict] = {}

    # Global rules first (lower priority)
    for raw in global_raw:
        rule = _validate_and_compile(raw, home_rules_path)
        if rule:
            compiled[rule["name"]] = rule

    # Project rules second (higher priority — overwrites global if same name)
    for raw in project_raw:
        rule = _validate_and_compile(raw, project_rules_path)
        if rule:
            compiled[rule["name"]] = rule

    return list(compiled.values())