# secret-triage

[![Built with Claude Code](https://img.shields.io/badge/Built%20with-Claude%20Code-blue?logo=anthropic&logoColor=white)](https://claude.ai/code)


**Find leaked secrets in your codebase with confidence scoring and actionable remediation.** Not just pattern matching -- entropy analysis, context awareness, and per-secret remediation steps.

```bash
secret-triage scan .
```

Catches AWS keys, Stripe secrets, JWTs, private keys, database URLs, and 50+ other patterns. Scores each finding by confidence so you fix real leaks first.

---

## Demo

```
$ secret-triage scan ./my-project

  secret-triage scan results

  5 secrets found  |  CRITICAL: 2  HIGH: 2  MEDIUM: 1  LOW: 0

  # | Severity | Confidence | Type                 | File              | Line | Match (redacted)
  1 | CRITICAL | [#####] 95%| AWS Access Key ID    | config/deploy.py  | 23   | AKIA****EXAMPLE
  2 | CRITICAL | [####-] 87%| PostgreSQL URL        | .env              | 5    | post****@prod-db
  3 | HIGH     | [###--] 72%| GitHub PAT            | scripts/sync.sh   | 11   | ghp_****aBcDeF
  4 | HIGH     | [###--] 68%| Stripe Secret Key     | src/billing.js    | 45   | sk_l****_8xKq
  5 | MEDIUM   | [##---] 51%| Generic API Key       | src/config.ts     | 12   | api-****-key-v2

  Remediation Steps:

  AWS Access Key ID (CRITICAL)
    1. Go to AWS IAM Console
    2. Deactivate the compromised key immediately
    3. Create a new access key pair
    ...
```

---

## Quickstart

```bash
# Install
pip install secret-triage

# Or from source
git clone https://github.com/yourname/secret-triage.git
cd secret-triage
pip install -e .

# Scan current directory
secret-triage scan .

# Scan with git history
secret-triage scan . --history

# Output as SARIF (for CI integration)
secret-triage scan . --format sarif -o results.sarif

# Output as markdown
secret-triage scan . --format markdown -o report.md
```

---

## Features

- **50+ secret patterns** -- AWS, GCP, GitHub, Stripe, OpenAI, Slack, database URLs, private keys, JWTs, and more
- **Confidence scoring** -- each finding scored 0-100% using entropy analysis, context clues, and pattern validation
- **Smart context** -- reduces false positives by detecting test files, comments, placeholders, and env var references
- **Git history scanning** -- finds secrets that were committed and later removed (they're still in the history)
- **Actionable remediation** -- per-secret-type step-by-step fix instructions with dashboard links
- **Multiple output formats** -- rich terminal table, SARIF (for CI/CD), markdown report, JSON
- **CI-friendly** -- exits with code 2 for critical, 1 for high, 0 for clean
- **Respects .gitignore** -- won't waste time scanning node_modules or build artifacts

---

## Confidence Scoring

Each finding is scored based on multiple signals:

| Signal | Impact | Example |
|--------|--------|---------|
| Shannon entropy | High entropy = more likely real | `AKIA3JFHSK8D9FHSK3KD` vs `test_key_placeholder` |
| File path | Test/example files reduce score | `tests/mock_config.py` = lower confidence |
| Placeholder patterns | Known fakes reduce score | `CHANGE_ME`, `<your-key>`, `sk_test_` |
| Comment context | In a comment = slightly lower | `# api_key = sk-abc123` |
| Pattern validation | Structural checks boost score | AWS key format: exactly `AKIA` + 16 alphanumeric |
| Localhost in DB URL | Local dev URLs = lower risk | `postgres://user:pass@localhost/db` |

---

## Architecture

```
File System ──> [Scanner] ──> Pattern Match ──> [Scorer] ──> Confidence
                                                               |
Git History ──> [Git Scanner] ──> Pattern Match ──> [Scorer] ──|
                                                               v
                                                         [Reporter]
                                                        /    |     \
                                                Terminal  SARIF   Markdown
```

---

## CLI Reference

```
secret-triage scan [PATH] [OPTIONS]
  --history               Also scan git commit history
  --min-confidence FLOAT  Minimum confidence threshold (default: 0.5)
  --format FORMAT         Output: terminal, sarif, markdown, json
  -o, --output FILE       Write report to file
  --exclude PATTERN       Exclude file patterns (repeatable)
  --no-git-ignore         Don't respect .gitignore
  -v, --verbose           Verbose scanning output

secret-triage report
  --last                  Show last scan results
```

### Exit Codes

- `0` -- no high/critical findings
- `1` -- high severity findings detected
- `2` -- critical severity findings detected

---

## License

MIT License. See [LICENSE](./LICENSE).
