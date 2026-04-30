 # Git pre-commit hook installer# env_guard/hooks.py

import os
import stat
from pathlib import Path

# This is the script that gets written into .git/hooks/pre-commit
# When you run "git commit", git executes this file automatically
# If it exits with code 1, the commit is blocked
HOOK_SCRIPT = """#!/bin/sh
# env-guard pre-commit hook
# Installed by: env-guard install-hook

echo "env-guard: scanning for secrets..."

env-guard scan . --no-fail=false
EXIT_CODE=$?

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "env-guard: commit blocked. Remove secrets before committing."
    echo "env-guard: to skip this check (NOT recommended): git commit --no-verify"
    exit 1
fi

exit 0
"""


def _get_hooks_dir(repo_path: str) -> Path:
    """
    Find the .git/hooks directory for the given repo path.
    Raises an error if the path is not a git repository.
    """
    git_dir = Path(repo_path).resolve() / ".git"

    if not git_dir.exists():
        raise FileNotFoundError(
            f"No .git directory found at {repo_path}. "
            f"Make sure you're inside a git repository."
        )

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    return hooks_dir


def install_hook(repo_path: str = ".") -> None:
    """
    Write the pre-commit hook script into .git/hooks/pre-commit
    and make it executable.
    """
    hooks_dir = _get_hooks_dir(repo_path)
    hook_file = hooks_dir / "pre-commit"

    # If a pre-commit hook already exists, back it up
    # Beginner mistake: overwriting existing hooks silently
    # destroys other tools like prettier, eslint hooks the user had
    if hook_file.exists():
        backup = hooks_dir / "pre-commit.bak"
        hook_file.rename(backup)
        print(f"  Existing hook backed up to {backup}")

    hook_file.write_text(HOOK_SCRIPT, encoding="utf-8")

    # Make the file executable — required on Linux/macOS
    # On Windows this is ignored but we do it anyway for cross-platform compatibility
    current = stat.S_IMODE(os.stat(hook_file).st_mode)
    os.chmod(hook_file, current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def uninstall_hook(repo_path: str = ".") -> None:
    """
    Remove the env-guard pre-commit hook.
    Restores backup if one exists.
    """
    hooks_dir = _get_hooks_dir(repo_path)
    hook_file = hooks_dir / "pre-commit"
    backup    = hooks_dir / "pre-commit.bak"

    if not hook_file.exists():
        raise FileNotFoundError("No pre-commit hook found. Nothing to remove.")

    hook_file.unlink()

    # Restore backup if it exists
    if backup.exists():
        backup.rename(hook_file)
        print("  Previous hook restored from backup.")