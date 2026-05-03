# env_guard/reporter.py

import json
from colorama import init, Fore, Style

# Initialize colorama — required on Windows to make colors work
# autoreset=True means after every print the color resets automatically
# so we don't have to manually write Style.RESET_ALL after every line
init(autoreset=True)

# Severity → color mapping
SEVERITY_COLOR = {
    "HIGH":   Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW":    Fore.CYAN,
}

SEVERITY_ICON = {
    "HIGH":   "✖",
    "MEDIUM": "⚠",
    "LOW":    "ℹ",
}


def _severity_label(severity: str) -> str:
    color = SEVERITY_COLOR.get(severity, Fore.WHITE)
    icon  = SEVERITY_ICON.get(severity, "•")
    return f"{color}{icon} {severity}{Style.RESET_ALL}"


def print_findings(result: dict, path: str) -> None:
    """
    Print a human-readable colored report to the terminal.
    result is the dict returned by scanner.scan()
    """
    findings = result["findings"]
    scanned  = result["scanned"]

    # ── Header ────────────────────────────────────────────────────────────
    print(f"\n{Style.BRIGHT}env-guard scan report{Style.RESET_ALL}")
    print(f"Path    : {Fore.WHITE}{path}{Style.RESET_ALL}")
    print(f"Scanned : {scanned} files")
    print(f"Found   : {len(findings)} potential secret(s)\n")

    if not findings:
        print(f"{Fore.GREEN}✔ No secrets detected. You're good to go.{Style.RESET_ALL}\n")
        return

    # ── Group findings by severity ────────────────────────────────────────
    high   = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]
    low    = [f for f in findings if f["severity"] == "LOW"]

    for group in [high, medium, low]:
        if not group:
            continue
        for finding in group:
            severity_str = _severity_label(finding["severity"])
            custom_label = f"  {Fore.MAGENTA}[custom]{Style.RESET_ALL}" if finding.get('custom') else ""
            print(f"  {severity_str}  {Style.BRIGHT}{finding['rule']}{Style.RESET_ALL}{custom_label}")
            print(f"  {Fore.WHITE}File : {finding['file']}:{finding['line']}{Style.RESET_ALL}")
            print(f"  {Fore.WHITE}Code : {Style.DIM}{finding['content']}{Style.RESET_ALL}")
            print()

    # ── Summary bar ───────────────────────────────────────────────────────
    print("─" * 50)
    if high:
        print(f"  {Fore.RED}{Style.BRIGHT}{len(high)} HIGH{Style.RESET_ALL}", end="   ")
    if medium:
        print(f"  {Fore.YELLOW}{Style.BRIGHT}{len(medium)} MEDIUM{Style.RESET_ALL}", end="   ")
    if low:
        print(f"  {Fore.CYAN}{Style.BRIGHT}{len(low)} LOW{Style.RESET_ALL}", end="")
    print("\n" + "─" * 50)
    print(f"\n{Fore.RED}Scan failed — secrets detected. Do not commit.{Style.RESET_ALL}\n")


def print_json(result: dict) -> None:
    """
    Print findings as raw JSON — useful for CI pipelines and scripting.
    """
    print(json.dumps(result, indent=2))