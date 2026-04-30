 # Entry point — argument parsing# env_guard/cli.py

import sys
import click

from env_guard.scanner import scan
from env_guard.reporter import print_findings, print_json
from env_guard.hooks import install_hook, uninstall_hook


@click.group()
@click.version_option(version="0.1.0", prog_name="env-guard")
def main():
    """
    env-guard — scan your codebase for exposed secrets before committing.
    """
    pass


@main.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format: text (default) or json"
)
@click.option(
    "--severity",
    type=click.Choice(["HIGH", "MEDIUM", "LOW"]),
    default=None,
    help="Only show findings at this severity level or above"
)
@click.option(
    "--fail/--no-fail",
    default=True,
    help="Exit with code 1 if secrets found (default: true, useful for CI)"
)
def scan_cmd(path, output_format, severity, fail):
    """
    Scan PATH for exposed secrets and API keys.

    PATH defaults to current directory if not specified.

    Examples:\n
        env-guard scan .\n
        env-guard scan /path/to/project\n
        env-guard scan . --format json\n
        env-guard scan . --severity HIGH\n
        env-guard scan . --no-fail
    """
    try:
        result = scan(path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)

    # Filter by severity if requested
    if severity:
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        min_level = order[severity]
        result["findings"] = [
            f for f in result["findings"]
            if order[f["severity"]] >= min_level
        ]

    if output_format == "json":
        print_json(result)
    else:
        print_findings(result, path)

    # Exit code 1 if secrets found — this is what blocks git commits in CI
    if fail and result["findings"]:
        sys.exit(1)


@main.command("install-hook")
@click.option(
    "--path", "repo_path",
    default=".",
    type=click.Path(exists=True),
    help="Path to the git repo (default: current directory)"
)
def install_hook_cmd(repo_path):
    """
    Install env-guard as a git pre-commit hook.

    After installing, env-guard will automatically scan your code
    before every git commit and block the commit if secrets are found.

    Example:\n
        env-guard install-hook\n
        env-guard install-hook --path /path/to/repo
    """
    try:
        install_hook(repo_path)
        click.echo("✔ Pre-commit hook installed successfully.")
        click.echo("  env-guard will now scan before every commit.")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)


@main.command("uninstall-hook")
@click.option(
    "--path", "repo_path",
    default=".",
    type=click.Path(exists=True),
    help="Path to the git repo (default: current directory)"
)
def uninstall_hook_cmd(repo_path):
    """
    Remove the env-guard pre-commit hook from a git repo.
    """
    try:
        uninstall_hook(repo_path)
        click.echo("✔ Pre-commit hook removed.")
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(2)