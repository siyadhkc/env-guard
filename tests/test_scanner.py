# tests/test_scanner.py
#
# Tests the scanner's file walking and detection behavior.
# We create temporary files and directories using pytest's
# built-in `tmp_path` fixture — no cleanup needed, pytest handles it.

import pytest
from pathlib import Path
from env_guard.scanner import scan, _is_ignored, _load_ignore_patterns


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_project(tmp_path):
    """
    Creates a fake project directory structure for testing.
    tmp_path is a pytest built-in that gives a fresh temp dir per test.
    """
    # A file with a real secret
    secret_file = tmp_path / "config.py"
    secret_file.write_text('STRIPE_KEY = "sk_live_fakekey1234567890abcdefXY"')

    # A clean file with no secrets
    clean_file = tmp_path / "views.py"
    clean_file.write_text('def index(request):\n    return "hello"')

    # A .env file with secrets
    env_file = tmp_path / ".env"
    env_file.write_text('DATABASE_URL=postgresql://user:pass@localhost/db\nDEBUG=True')

    return tmp_path


@pytest.fixture
def project_with_ignore(tmp_path):
    """Fake project with a .envguardignore file."""
    secret_file = tmp_path / "secret.py"
    secret_file.write_text('STRIPE_KEY = "sk_live_fakekey1234567890abcdefXY"')

    ignore_file = tmp_path / ".envguardignore"
    ignore_file.write_text("secret.py\n")

    return tmp_path


# ── Basic scan tests ──────────────────────────────────────────────────────────

def test_scan_detects_stripe_key(fake_project):
    result = scan(str(fake_project))
    rules_found = [f["rule"] for f in result["findings"]]
    assert "Stripe Live Secret Key" in rules_found


def test_scan_detects_postgres_url(fake_project):
    result = scan(str(fake_project))
    rules_found = [f["rule"] for f in result["findings"]]
    assert "PostgreSQL Connection String" in rules_found


def test_scan_returns_correct_file(fake_project):
    result = scan(str(fake_project))
    files_found = [f["file"] for f in result["findings"]]
    assert any("config.py" in f for f in files_found)


def test_scan_returns_line_number(fake_project):
    result = scan(str(fake_project))
    stripe = [f for f in result["findings"] if f["rule"] == "Stripe Live Secret Key"]
    assert stripe[0]["line"] == 1


def test_scan_scanned_count(fake_project):
    result = scan(str(fake_project))
    # We created 3 files — all should be scanned
    assert result["scanned"] == 3


def test_clean_file_produces_no_findings(tmp_path):
    clean = tmp_path / "clean.py"
    clean.write_text('def hello():\n    return "world"')
    result = scan(str(tmp_path))
    assert len(result["findings"]) == 0


# ── Ignore pattern tests ──────────────────────────────────────────────────────

def test_ignored_file_not_scanned(project_with_ignore):
    result = scan(str(project_with_ignore))
    # secret.py is in .envguardignore — should produce zero findings
    assert len(result["findings"]) == 0


def test_load_ignore_patterns(tmp_path):
    ignore_file = tmp_path / ".envguardignore"
    ignore_file.write_text("# comment\n*.log\ntests/\n\n")
    patterns = _load_ignore_patterns(tmp_path)
    assert "*.log" in patterns
    assert "tests/" in patterns
    # Comments and empty lines should not be included
    assert "# comment" not in patterns


def test_is_ignored_filename_glob(tmp_path):
    patterns = ["*.log"]
    log_file = tmp_path / "app.log"
    py_file  = tmp_path / "app.py"
    assert _is_ignored(log_file, tmp_path, patterns) is True
    assert _is_ignored(py_file,  tmp_path, patterns) is False


def test_is_ignored_directory_pattern(tmp_path):
    patterns = ["tests/"]
    sub = tmp_path / "tests"
    sub.mkdir()
    file_in_tests = sub / "test_something.py"
    file_in_tests.touch()
    file_outside = tmp_path / "main.py"
    file_outside.touch()
    assert _is_ignored(file_in_tests, tmp_path, patterns) is True
    assert _is_ignored(file_outside,  tmp_path, patterns) is False


# ── Single file scan ──────────────────────────────────────────────────────────

def test_scan_single_file(tmp_path):
    f = tmp_path / "secrets.py"
    f.write_text('API_KEY = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"')
    result = scan(str(f))
    assert result["scanned"] == 1
    assert len(result["findings"]) >= 1


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_scan_nonexistent_path():
    with pytest.raises(FileNotFoundError):
        scan("/this/path/does/not/exist")


def test_scan_skips_pycache(tmp_path):
    # Create a __pycache__ dir with a fake secret inside
    cache = tmp_path / "__pycache__"
    cache.mkdir()
    cache_file = cache / "module.pyc"
    cache_file.write_text('sk_live_fakekey1234567890abcdefXY')

    result = scan(str(tmp_path))
    files = [f["file"] for f in result["findings"]]
    # Nothing from __pycache__ should appear
    assert not any("__pycache__" in f for f in files)


def test_empty_directory(tmp_path):
    result = scan(str(tmp_path))
    assert result["scanned"] == 0
    assert result["findings"] == []

def test_custom_rules_loaded(tmp_path):
    # Create a rules.yml in the temp project
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text("""
rules:
  - name: "Custom Test Rule"
    pattern: "CUSTOM_SECRET_[A-Z0-9]{8}"
    severity: HIGH
""")
    # Create a file that matches the custom rule
    secret_file = tmp_path / "config.py"
    secret_file.write_text('token = "CUSTOM_SECRET_ABCD1234"')

    result = scan(str(tmp_path))
    rules_found = [f["rule"] for f in result["findings"]]
    assert "Custom Test Rule" in rules_found
    assert result["custom_rules_loaded"] == 1


def test_invalid_custom_rule_skipped(tmp_path):
    # Bad regex should not crash the scanner
    rules_file = tmp_path / "rules.yml"
    rules_file.write_text("""
rules:
  - name: "Bad Rule"
    pattern: "[invalid(regex"
    severity: HIGH
""")
    clean = tmp_path / "clean.py"
    clean.write_text('x = 1')

    # Should not raise
    result = scan(str(tmp_path))
    assert result["custom_rules_loaded"] == 0