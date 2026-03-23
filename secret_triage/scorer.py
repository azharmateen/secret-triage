"""
Confidence scoring for secret findings.
Combines entropy analysis, context analysis, and pattern-specific validation.
"""

import math
import re
from .patterns import SecretPattern


# File paths that typically contain intentionally fake secrets
LOW_RISK_PATHS = {
    "test", "tests", "spec", "specs", "__tests__", "__mocks__",
    "fixtures", "mocks", "stubs", "examples", "example", "samples",
    "demo", "docs", "documentation", "README",
}

# Common placeholder values that are not real secrets
PLACEHOLDER_PATTERNS = [
    re.compile(r'^[xX]+$'),                    # xxxx
    re.compile(r'^your[-_]'),                   # your-api-key
    re.compile(r'^<.*>$'),                      # <your-key-here>
    re.compile(r'^\$\{'),                       # ${VAR}
    re.compile(r'^%\('),                        # %(var)s
    re.compile(r'^CHANGE[-_]?ME', re.I),        # CHANGEME
    re.compile(r'^REPLACE[-_]?ME', re.I),       # REPLACEME
    re.compile(r'^INSERT[-_]', re.I),           # INSERT_HERE
    re.compile(r'^TODO', re.I),                 # TODO
    re.compile(r'^sk[-_]test[-_]', re.I),       # sk_test_...
    re.compile(r'^pk[-_]test[-_]', re.I),       # pk_test_...
    re.compile(r'^example', re.I),              # example...
    re.compile(r'^dummy', re.I),                # dummy...
    re.compile(r'^fake', re.I),                 # fake...
    re.compile(r'^sample', re.I),               # sample...
    re.compile(r'^placeholder', re.I),          # placeholder...
    re.compile(r'^0{8,}'),                      # 00000000...
    re.compile(r'^1{8,}'),                      # 11111111...
    re.compile(r'^a{8,}$', re.I),               # aaaaaaaa...
]

# Context patterns that suggest the value is not a real secret
SAFE_CONTEXT_PATTERNS = [
    re.compile(r'#\s*example', re.I),
    re.compile(r'#\s*TODO', re.I),
    re.compile(r'#\s*placeholder', re.I),
    re.compile(r'//\s*example', re.I),
    re.compile(r'//\s*TODO', re.I),
    re.compile(r'process\.env\.'),  # Environment variable reference
    re.compile(r'os\.environ'),     # Python env reference
    re.compile(r'os\.getenv'),      # Python env reference
    re.compile(r'\.env\.example'),
    re.compile(r'\.env\.sample'),
]


def calculate_confidence(
    matched_text: str,
    line: str,
    file_path: str,
    pattern: SecretPattern,
) -> float:
    """
    Calculate confidence score (0.0-1.0) that a finding is a real secret.

    Factors:
    - Entropy of the matched text
    - Whether it's in a test/example file
    - Whether it looks like a placeholder
    - Pattern-specific validation
    - Context clues in the surrounding line
    """
    score = 0.7  # Start with a moderate base

    # --- Entropy Analysis ---
    entropy = _shannon_entropy(matched_text)

    if pattern.entropy_threshold > 0:
        if entropy < pattern.entropy_threshold:
            score -= 0.3
        elif entropy > 4.5:
            score += 0.1

    # --- Path Analysis ---
    path_parts = set(file_path.replace("\\", "/").lower().split("/"))
    if path_parts & LOW_RISK_PATHS:
        score -= 0.25

    # .env files are high risk
    filename = file_path.split("/")[-1].lower()
    if filename in (".env", ".env.local", ".env.production", ".env.staging"):
        score += 0.15
    elif filename.endswith(".example") or filename.endswith(".sample"):
        score -= 0.3

    # --- Placeholder Detection ---
    for placeholder_re in PLACEHOLDER_PATTERNS:
        if placeholder_re.search(matched_text):
            score -= 0.5
            break

    # --- Context Analysis ---
    for ctx_re in SAFE_CONTEXT_PATTERNS:
        if ctx_re.search(line):
            score -= 0.2
            break

    # Check if it's in a comment
    stripped = line.lstrip()
    if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*"):
        # Still might be a secret in a comment, but lower confidence
        score -= 0.1

    # --- Pattern-Specific Validation ---
    score += _validate_specific(matched_text, pattern)

    # Clamp to [0.0, 1.0]
    return max(0.0, min(1.0, score))


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0

    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    length = len(text)
    entropy = 0.0

    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)

    return entropy


def _validate_specific(text: str, pattern: SecretPattern) -> float:
    """Pattern-specific validation to adjust confidence."""
    pid = pattern.id
    adjustment = 0.0

    if pid == "aws-access-key":
        # AWS keys are exactly AKIA + 16 alphanumeric chars
        if re.match(r'^AKIA[0-9A-Z]{16}$', text):
            adjustment += 0.15

    elif pid == "github-pat":
        if text.startswith("ghp_") and len(text) >= 40:
            adjustment += 0.2

    elif pid == "github-fine-grained":
        if text.startswith("github_pat_"):
            adjustment += 0.2

    elif pid == "stripe-secret":
        if text.startswith("sk_live_"):
            adjustment += 0.2
        elif text.startswith("sk_test_"):
            adjustment -= 0.3

    elif pid == "jwt-token":
        # Validate JWT structure (3 base64url parts)
        parts = text.split(".")
        if len(parts) == 3:
            adjustment += 0.1
        else:
            adjustment -= 0.3

    elif pid in ("postgres-url", "mysql-url", "mongodb-url"):
        # Higher confidence if it has a real hostname
        if "localhost" in text or "127.0.0.1" in text:
            adjustment -= 0.2
        else:
            adjustment += 0.1

    elif pid == "generic-api-key" or pid == "generic-secret" or pid == "generic-token":
        # Generic patterns need higher entropy
        entropy = _shannon_entropy(text)
        if entropy < 3.0:
            adjustment -= 0.2

    elif pid.endswith("-private-key"):
        # Private keys are always high confidence
        adjustment += 0.2

    return adjustment
