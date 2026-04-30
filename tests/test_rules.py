# tests/test_rules.py
#
# Tests every major rule with:
#   - A real-looking positive sample  (must match)
#   - A negative sample               (must NOT match)
#
# Why both? A regex that matches everything is useless.
# We need to confirm it's specific, not just that it fires.

import pytest
from env_guard.rules import RULES

# Build a lookup so tests can find rules by name
RULES_BY_NAME = {r["name"]: r for r in RULES}


def match(rule_name: str, text: str) -> bool:
    """Helper — returns True if the rule matches the text."""
    rule = RULES_BY_NAME[rule_name]
    return bool(rule["pattern"].search(text))


# ── AWS ───────────────────────────────────────────────────────────────────────

def test_aws_access_key_positive():
    assert match("AWS Access Key ID", "AKIAIOSFODNN7EXAMPLE1234") is True

def test_aws_access_key_negative():
    # Too short — only 10 chars after AKIA
    assert match("AWS Access Key ID", "AKIA1234567890") is False

def test_aws_secret_key_positive():
    assert match("AWS Secret Access Key", 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"') is True

def test_aws_secret_key_negative():
    assert match("AWS Secret Access Key", 'aws_region = "us-east-1"') is False


# ── Google ────────────────────────────────────────────────────────────────────

def test_google_api_key_positive():
    assert match("Google API Key", "AIzaSyD-9tSrke72I6e67c8urT8YBc_tVFAexample") is True

def test_google_api_key_negative():
    # Doesn't start with AIza
    assert match("Google API Key", "BIzaSyD-9tSrke72I6e67c8urT8YBc_tVFAexample") is False


# ── GitHub ────────────────────────────────────────────────────────────────────

def test_github_pat_positive():
    assert match("GitHub Personal Access Token (classic)", "ghp_16C7e42F292c6912E7710c838347Ae178B4a") is True

def test_github_pat_negative():
    # Wrong prefix
    assert match("GitHub Personal Access Token (classic)", "ghx_16C7e42F292c6912E7710c838347Ae178B4a") is False

def test_github_oauth_positive():
    assert match("GitHub OAuth Token", "gho_16C7e42F292c6912E7710c838347Ae178B4a") is True

def test_github_app_token_positive():
    assert match("GitHub App Token", "ghu_16C7e42F292c6912E7710c838347Ae178B4a") is True


# ── Stripe ────────────────────────────────────────────────────────────────────

def test_stripe_live_key_positive():
    assert match("Stripe Live Secret Key", "sk_live_fakekey1234567890abcdefXY") is True

def test_stripe_live_key_negative():
    # Test key should match test rule, not live rule
    assert match("Stripe Live Secret Key", "sk_test_fakekey1234567890abcdefXY") is False

def test_stripe_test_key_positive():
    assert match("Stripe Test Secret Key", "sk_test_fakekey1234567890abcdefXY") is True


# ── Slack ─────────────────────────────────────────────────────────────────────

def test_slack_bot_token_positive():
    assert match("Slack Bot Token", "xoxb-17653650-123456789012-dvUSjZwl2Zv7KoOTobMgvxT") is True

def test_slack_bot_token_negative():
    assert match("Slack Bot Token", "xoxp-17653650-123456789012-dvUSjZwl2Zv7KoOTobMgvxT") is False

def test_slack_webhook_positive():
    assert match(
        "Slack Webhook URL",
        "https://hooks.slack.com/services/T1234ABCD/B1234ABCD/1234abcdefghijklmnopqrst"
    ) is True


# ── OpenAI ────────────────────────────────────────────────────────────────────

def test_openai_key_positive():
    assert match("OpenAI API Key", "sk-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX") is True

def test_openai_key_negative():
    # Too short
    assert match("OpenAI API Key", "sk-abc123") is False


# ── Anthropic ─────────────────────────────────────────────────────────────────

def test_anthropic_key_positive():
    assert match("Anthropic API Key", "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCD") is True

def test_anthropic_key_negative():
    assert match("Anthropic API Key", "sk-ant-short") is False


# ── Database URLs ─────────────────────────────────────────────────────────────

def test_postgres_positive():
    assert match("PostgreSQL Connection String", "postgresql://admin:password123@db.example.com:5432/mydb") is True

def test_postgres_negative():
    # No password
    assert match("PostgreSQL Connection String", "postgresql://localhost/mydb") is False

def test_mongodb_positive():
    assert match("MongoDB Connection String", "mongodb+srv://user:pass123@cluster.mongodb.net/mydb") is True

def test_mysql_positive():
    assert match("MySQL Connection String", "mysql://root:secret@localhost:3306/myapp") is True

def test_redis_positive():
    assert match("Redis Connection String", "redis://:mypassword@redis.example.com:6379") is True


# ── Private Keys ──────────────────────────────────────────────────────────────

def test_rsa_private_key_positive():
    assert match("RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----") is True

def test_rsa_private_key_negative():
    # Public key should not match
    assert match("RSA Private Key", "-----BEGIN RSA PUBLIC KEY-----") is False

def test_openssh_private_key_positive():
    assert match("OpenSSH Private Key", "-----BEGIN OPENSSH PRIVATE KEY-----") is True


# ── Django ────────────────────────────────────────────────────────────────────

def test_django_secret_key_positive():
    assert match("Django SECRET_KEY", "SECRET_KEY = 'django-insecure-abc123xyz456def789ghi012jkl345mno'") is True

def test_django_secret_key_negative():
    # Too short value
    assert match("Django SECRET_KEY", "SECRET_KEY = 'short'") is False


# ── Generic patterns ──────────────────────────────────────────────────────────

def test_generic_api_key_positive():
    assert match("Generic API Key assignment", 'api_key = "abcdefghijklmnopqrstuvwxyz123456"') is True

def test_generic_api_key_negative():
    # No quotes around value — not an assignment
    assert match("Generic API Key assignment", "api_key docs mention") is False

def test_generic_password_positive():
    assert match("Generic Password assignment", 'password = "mysecretpass"') is True

def test_generic_password_negative():
    assert match("Generic Password assignment", 'password = ""') is False

def test_bearer_token_positive():
    assert match("Bearer Token in code", "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") is True

def test_bearer_token_negative():
    assert match("Bearer Token in code", "Bearer short") is False


# ── Misc ──────────────────────────────────────────────────────────────────────

def test_sendgrid_positive():
    assert match("SendGrid API Key", "SG.abcdefghijklmnopqrstuvwx.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRS") is True

def test_npm_token_positive():
    assert match("NPM Auth Token", "npm_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ") is True

def test_razorpay_positive():
    assert match("Razorpay Key", "rzp_live_abcdefghijklmn") is True

def test_razorpay_test_positive():
    assert match("Razorpay Key", "rzp_test_abcdefghijklmn") is True

def test_basic_auth_url_positive():
    assert match("Basic Auth in URL", "https://admin:password@example.com/api") is True

def test_ftp_credentials_positive():
    assert match("FTP Credentials", "ftp://user:pass@ftp.example.com") is True