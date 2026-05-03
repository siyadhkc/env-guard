# env-guard 🔐

> Catch secrets on your machine — before they ever reach GitHub.

```bash
$ env-guard scan .

env-guard scan report
Path    : .
Scanned : 42 files
Found   : 1 potential secret(s)

  ✖ HIGH  Stripe Live Secret Key
  File : config/settings.py:12
  Code : STRIPE_KEY = "sk_live_abc123..."

──────────────────────────────────────────────────
  1 HIGH
──────────────────────────────────────────────────

Scan failed — secrets detected. Do not commit.
```

---

## GitHub already scans for secrets. So why env-guard?

GitHub has a feature called [Secret Scanning](https://docs.github.com/en/code-security/secret-scanning). It's good. But it has one fundamental problem:

**It runs after you push.**

By the time GitHub catches your exposed API key, it has already left your machine, traveled over the internet, and landed on GitHub's servers. If your repo is public — even for 30 seconds — automated bots scrape it instantly. GitHub will alert you, but the key is already compromised. You have to rotate it, audit usage, and hope nothing was abused.

env-guard is different. It runs **on your machine, before the commit**, as a git pre-commit hook. The secret never leaves your laptop.

```
Without env-guard:
  code → commit → push → GitHub scans → alert → key already exposed ❌

With env-guard:
  code → commit blocked → fix locally → push clean code ✅
```

Think of GitHub Secret Scanning as your last line of defense. env-guard is your first.

---

## Who is this for

- Developers who work with API keys, database URLs, or credentials locally
- Teams that want to enforce secret hygiene without relying on GitHub's post-push detection
- Anyone who has ever accidentally committed a `.env` file and had a bad day

---

## Install

```bash
pip install env-guard
```

Requires Python 3.8+

---

## Quickstart

```bash
# Scan your current project
env-guard scan .

# Install as a pre-commit hook (runs automatically on every git commit)
env-guard install-hook
```

That's it. After `install-hook`, you never have to think about it again. Every commit is scanned automatically.

---

## Usage

### Scan a directory

```bash
env-guard scan .
env-guard scan /path/to/project
```

### Only show HIGH severity findings

```bash
env-guard scan . --severity HIGH
```

### JSON output (for scripts and CI pipelines)

```bash
env-guard scan . --format json
```

### Scan without blocking (reporting mode)

```bash
env-guard scan . --no-fail
```

---

## Git pre-commit hook

```bash
# Install — run this once inside your project repo
env-guard install-hook

# Remove
env-guard uninstall-hook
```

After installing, every `git commit` triggers a scan automatically:

```
env-guard: scanning for secrets...
env-guard: commit blocked. Remove secrets before committing.
env-guard: to skip this check (NOT recommended): git commit --no-verify
```

The commit is fully blocked until the secret is removed. No secret reaches git history.

---

## Ignore false positives

Create `.envguardignore` in your project root:

```
# Ignore specific files
tests/fixtures/sample.env

# Ignore by extension
*.log

# Ignore entire directories
docs/
```

Same concept as `.gitignore` — one pattern per line.

---

## What env-guard detects

| Category | Examples |
|---|---|
| AWS | Access Key ID, Secret Access Key, Session Token |
| Google | API Key, OAuth Client Secret, Service Account |
| GitHub | Personal Access Token, OAuth Token, App Token |
| Stripe | Live and Test Secret Keys, Publishable Keys |
| Slack | Bot Token, User Token, Webhook URL |
| OpenAI | API Key |
| Anthropic | API Key |
| Twilio | Account SID, Auth Token |
| SendGrid | API Key |
| Database | PostgreSQL, MySQL, MongoDB, Redis connection strings |
| Private Keys | RSA, EC, PGP, OpenSSH |
| Django | SECRET_KEY |
| Generic | Passwords, tokens, API key assignments |
| And more | Razorpay, NPM, PyPI, Heroku, Netlify, Cloudinary |

54 detection rules total. More added with every release.

---

## CI/CD integration

env-guard also works in CI pipelines as a second checkpoint — useful for PRs from external contributors who may not have the hook installed locally.

### GitHub Actions

Create `.github/workflows/secret-scan.yml` in your repo:

```yaml
name: Secret Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - run: pip install env-scan-cli
      - run: env-guard scan .
```

---

## env-guard vs GitHub Secret Scanning

| | env-guard | GitHub Secret Scanning |
|---|---|---|
| When it runs | Before commit, on your machine | After push, on GitHub's servers |
| Blocks the secret | Yes — commit is blocked | No — secret is already pushed |
| Works offline | Yes | No |
| Custom ignore rules | Yes, via `.envguardignore` | Limited |
| Free | Yes | Yes (public repos) |
| Requires GitHub | No | Yes |

Use both. They solve different parts of the problem.

---

## Development

```bash
git clone https://github.com/siyadhkc/env-guard.git
cd env-guard
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT
