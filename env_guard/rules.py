# env_guard/rules.py
# Each rule is a dict with:
#   name    — human readable label shown in the report
#   pattern — regex that matches the secret
#   severity — "HIGH", "MEDIUM", "LOW"

import re

RULES = [
    # ── AWS ───────────────────────────────────────────────────────────────
    {
        "name": "AWS Access Key ID",
        "pattern": re.compile(r'AKIA[0-9A-Z]{16}'),
        "severity": "HIGH",
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": re.compile(r'(?i)aws_secret_access_key\s*=\s*["\']?[A-Za-z0-9/+=]{40}["\']?'),
        "severity": "HIGH",
    },
    {
        "name": "AWS Session Token",
        "pattern": re.compile(r'(?i)aws_session_token\s*=\s*["\']?[A-Za-z0-9/+=]{100,}["\']?'),
        "severity": "HIGH",
    },

    # ── Google ────────────────────────────────────────────────────────────
    {
        "name": "Google API Key",
        "pattern": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "severity": "HIGH",
    },
    {
        "name": "Google OAuth Client Secret",
        "pattern": re.compile(r'(?i)client_secret\s*=\s*["\']?[A-Za-z0-9\-_]{24}["\']?'),
        "severity": "HIGH",
    },
    {
        "name": "Google Service Account Key",
        "pattern": re.compile(r'"type"\s*:\s*"service_account"'),
        "severity": "HIGH",
    },

    # ── GitHub ────────────────────────────────────────────────────────────
    {
        "name": "GitHub Personal Access Token (classic)",
        "pattern": re.compile(r'ghp_[A-Za-z0-9]{36}'),
        "severity": "HIGH",
    },
    {
        "name": "GitHub OAuth Token",
        "pattern": re.compile(r'gho_[A-Za-z0-9]{36}'),
        "severity": "HIGH",
    },
    {
        "name": "GitHub App Token",
        "pattern": re.compile(r'(ghu|ghs)_[A-Za-z0-9]{36}'),
        "severity": "HIGH",
    },
    {
        "name": "GitHub Refresh Token",
        "pattern": re.compile(r'ghr_[A-Za-z0-9]{36}'),
        "severity": "HIGH",
    },

    # ── Stripe ────────────────────────────────────────────────────────────
    {
        "name": "Stripe Live Secret Key",
        "pattern": re.compile(r'sk_live_[0-9A-Za-z]{24,}'),
        "severity": "HIGH",
    },
    {
        "name": "Stripe Test Secret Key",
        "pattern": re.compile(r'sk_test_[0-9A-Za-z]{24,}'),
        "severity": "MEDIUM",
    },
    {
        "name": "Stripe Publishable Key",
        "pattern": re.compile(r'pk_(live|test)_[0-9A-Za-z]{24,}'),
        "severity": "MEDIUM",
    },

    # ── Slack ─────────────────────────────────────────────────────────────
    {
        "name": "Slack Bot Token",
       "pattern": re.compile(r'xoxb-[0-9]{8,13}-[0-9]{8,13}-[A-Za-z0-9]{16,}'),
        "severity": "HIGH",
    },
    {
        "name": "Slack User Token",
        "pattern": re.compile(r'xoxp-[0-9]{8,13}-[0-9]{8,13}-[A-Za-z0-9]{16,}'),
        "severity": "HIGH",
    },
    {
        "name": "Slack Webhook URL",
        "pattern": re.compile(r'https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}'),
        "severity": "HIGH",
    },

    # ── OpenAI ────────────────────────────────────────────────────────────
    {
        "name": "OpenAI API Key",
        "pattern": re.compile(r'sk-[A-Za-z0-9]{48}'),
        "severity": "HIGH",
    },

    # ── Anthropic ─────────────────────────────────────────────────────────
    {
        "name": "Anthropic API Key",
        "pattern": re.compile(r'sk-ant-[A-Za-z0-9\-_]{40,}'),
        "severity": "HIGH",
    },

    # ── Twilio ────────────────────────────────────────────────────────────
    {
        "name": "Twilio Account SID",
        "pattern": re.compile(r'AC[a-z0-9]{32}'),
        "severity": "HIGH",
    },
    {
        "name": "Twilio Auth Token",
        "pattern": re.compile(r'(?i)twilio.*auth.*token\s*=\s*["\']?[a-z0-9]{32}["\']?'),
        "severity": "HIGH",
    },

    # ── SendGrid ──────────────────────────────────────────────────────────
    {
        "name": "SendGrid API Key",
        "pattern": re.compile(r'SG\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}'),
        "severity": "HIGH",
    },

    # ── Firebase ──────────────────────────────────────────────────────────
    {
        "name": "Firebase API Key",
        "pattern": re.compile(r'(?i)firebase.*["\']AIza[0-9A-Za-z\-_]{35}["\']'),
        "severity": "HIGH",
    },

    # ── Database URLs ─────────────────────────────────────────────────────
    {
        "name": "PostgreSQL Connection String",
        "pattern": re.compile(r'postgres(?:ql)?://[^:]+:[^@]+@[^\s\'"]+'),
        "severity": "HIGH",
    },
    {
        "name": "MySQL Connection String",
        "pattern": re.compile(r'mysql://[^:]+:[^@]+@[^\s\'"]+'),
        "severity": "HIGH",
    },
    {
        "name": "MongoDB Connection String",
        "pattern": re.compile(r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\'"]+'),
        "severity": "HIGH",
    },
    {
        "name": "Redis Connection String",
        "pattern": re.compile(r'redis://:[^@]+@[^\s\'"]+'),
        "severity": "HIGH",
    },

    # ── Private Keys ──────────────────────────────────────────────────────
    {
        "name": "RSA Private Key",
        "pattern": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
        "severity": "HIGH",
    },
    {
        "name": "EC Private Key",
        "pattern": re.compile(r'-----BEGIN EC PRIVATE KEY-----'),
        "severity": "HIGH",
    },
    {
        "name": "PGP Private Key",
        "pattern": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        "severity": "HIGH",
    },
    {
        "name": "Generic Private Key",
        "pattern": re.compile(r'-----BEGIN PRIVATE KEY-----'),
        "severity": "HIGH",
    },
    {
        "name": "OpenSSH Private Key",
        "pattern": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----'),
        "severity": "HIGH",
    },

    # ── Django specific ───────────────────────────────────────────────────
    {
        "name": "Django SECRET_KEY",
        "pattern": re.compile(r'SECRET_KEY\s*=\s*["\'][^"\']{20,}["\']'),
        "severity": "HIGH",
    },

    # ── Generic high-entropy patterns ─────────────────────────────────────
    {
        "name": "Generic API Key assignment",
        "pattern": re.compile(r'(?i)(api_key|apikey|api-key)\s*=\s*["\'][A-Za-z0-9\-_]{20,}["\']'),
        "severity": "MEDIUM",
    },
    {
        "name": "Generic Secret assignment",
        "pattern": re.compile(r'(?i)(secret|secret_key)\s*=\s*["\'][^"\']{8,}["\']'),
        "severity": "MEDIUM",
    },
    {
        "name": "Generic Password assignment",
        "pattern": re.compile(r'(?i)(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']'),
        "severity": "MEDIUM",
    },
    {
        "name": "Generic Token assignment",
        "pattern": re.compile(r'(?i)(token|auth_token|access_token)\s*=\s*["\'][A-Za-z0-9\-_\.]{20,}["\']'),
        "severity": "MEDIUM",
    },
    {
        "name": "Bearer Token in code",
        "pattern": re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}'),
        "severity": "MEDIUM",
    },

    # ── .env file patterns ────────────────────────────────────────────────
    {
        "name": "Dotenv secret value",
        "pattern": re.compile(r'(?i)^(SECRET|API_KEY|TOKEN|PASSWORD|PASS|PWD|AUTH_TOKEN|CREDENTIAL)[A-Z_]*=[^\s].+', re.MULTILINE),
        "severity": "LOW",
    },

    # ── Misc ──────────────────────────────────────────────────────────────
    {
        "name": "SSH Password in URL",
        "pattern": re.compile(r'ssh://[^:]+:[^@]+@'),
        "severity": "HIGH",
    },
    {
        "name": "FTP Credentials",
        "pattern": re.compile(r'ftp://[^:]+:[^@]+@'),
        "severity": "HIGH",
    },
    {
        "name": "Basic Auth in URL",
        "pattern": re.compile(r'https?://[^:]+:[^@]+@[a-zA-Z0-9\-\.]+'),
        "severity": "HIGH",
    },
    {
        "name": "Mailgun API Key",
        "pattern": re.compile(r'key-[0-9a-zA-Z]{32}'),
        "severity": "HIGH",
    },
    {
        "name": "Heroku API Key",
        "pattern": re.compile(r'(?i)heroku.*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
        "severity": "HIGH",
    },
    {
        "name": "Netlify Personal Access Token",
        "pattern": re.compile(r'(?i)netlify.*[a-zA-Z0-9\-_]{40,}'),
        "severity": "MEDIUM",
    },
    {
        "name": "NPM Auth Token",
        "pattern": re.compile(r'(?i)npm_[A-Za-z0-9]{36}'),
        "severity": "HIGH",
    },
    {
        "name": "PyPI API Token",
        "pattern": re.compile(r'pypi-[A-Za-z0-9\-_]{40,}'),
        "severity": "HIGH",
    },
    {
        "name": "Vault Token",
        "pattern": re.compile(r'(?i)s\.[a-z0-9]{24}'),
        "severity": "HIGH",
    },
    {
        "name": "Cloudinary URL",
        "pattern": re.compile(r'cloudinary://[0-9]+:[A-Za-z0-9\-_]+@[a-z]+'),
        "severity": "HIGH",
    },
    {
        "name": "Razorpay Key",
        "pattern": re.compile(r'rzp_(live|test)_[A-Za-z0-9]{14}'),
        "severity": "HIGH",
    },
    {
        "name": "Jira / Atlassian Token",
        "pattern": re.compile(r'(?i)atlassian.*[A-Za-z0-9]{24}'),
        "severity": "MEDIUM",
    },
]

# File extensions we will completely skip (binary, compiled, media)
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".mp4", ".mp3", ".wav", ".avi", ".mov",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".pyc", ".pyo", ".pyd",
    ".pdf", ".docx", ".xlsx",
    ".lock",       # package-lock.json, poetry.lock — too noisy
}

# Directories we always skip
SKIP_DIRS = {
    ".git", ".hg", ".svn",
    "node_modules", "__pycache__",
    ".venv", "venv", "env",
    ".tox", ".mypy_cache", ".pytest_cache",
    "dist", "build", ".eggs",
    "migrations","tests","test_rules","test_scanner",  # Django migrations — not secrets
}