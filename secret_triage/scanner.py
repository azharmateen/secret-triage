"""File scanner: scans files for secrets using pattern matching."""

from dataclasses import dataclass, field
from pathlib import Path

from .patterns import get_all_patterns, SecretPattern
from .scorer import calculate_confidence
from .remediation import get_remediation


# Default binary extensions to skip
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
    ".zip", ".tar", ".gz", ".bz2", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".pyc", ".pyo", ".class", ".jar",
    ".db", ".sqlite", ".sqlite3",
}

# Default directories to skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "coverage", ".tox",
    ".eggs", "target", ".idea", ".vscode", ".gradle",
}

MAX_FILE_SIZE = 1024 * 1024  # 1 MB max per file


@dataclass
class Finding:
    """A detected secret finding."""
    pattern_id: str
    pattern_name: str
    severity: str
    category: str
    description: str
    file_path: str
    line_number: int
    line_content: str
    matched_text: str
    confidence: float
    is_git_history: bool = False
    commit_sha: str = ""
    remediation: str = ""

    @property
    def severity_order(self) -> int:
        """Numeric severity for sorting."""
        return {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(self.severity, 4)

    def to_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "pattern_name": self.pattern_name,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_text": self._redact(self.matched_text),
            "confidence": round(self.confidence, 2),
            "is_git_history": self.is_git_history,
            "commit_sha": self.commit_sha,
            "remediation": self.remediation,
        }

    def _redact(self, text: str) -> str:
        """Redact the middle portion of a secret for display."""
        if len(text) <= 8:
            return text[:2] + "*" * (len(text) - 2)
        show = max(4, len(text) // 4)
        return text[:show] + "*" * (len(text) - show * 2) + text[-show:]


def scan_directory(
    root: Path,
    respect_gitignore: bool = True,
    exclude_patterns: list[str] = None,
    verbose: bool = False,
) -> list[Finding]:
    """Scan all files in a directory for secrets."""
    findings = []
    patterns = get_all_patterns()
    gitignore_patterns = _load_gitignore(root) if respect_gitignore else set()

    extra_excludes = set(exclude_patterns or [])

    for file_path in _walk_files(root, gitignore_patterns | extra_excludes):
        if verbose:
            print(f"  Scanning: {file_path.relative_to(root)}")

        file_findings = _scan_file(file_path, patterns, root)
        findings.extend(file_findings)

    return findings


def _scan_file(file_path: Path, patterns: list[SecretPattern], root: Path) -> list[Finding]:
    """Scan a single file for secrets."""
    findings = []

    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return findings

    lines = content.split("\n")
    rel_path = str(file_path.relative_to(root))

    for line_num, line in enumerate(lines, 1):
        # Skip very short or very long lines
        if len(line) < 5 or len(line) > 2000:
            continue

        for pattern in patterns:
            match = pattern.pattern.search(line)
            if not match:
                continue

            # Extract the matched secret text
            try:
                matched = match.group("secret")
            except IndexError:
                matched = match.group(0)

            # Calculate confidence
            confidence = calculate_confidence(
                matched_text=matched,
                line=line,
                file_path=rel_path,
                pattern=pattern,
            )

            if confidence < 0.1:
                continue

            remediation = get_remediation(pattern.id)

            findings.append(Finding(
                pattern_id=pattern.id,
                pattern_name=pattern.name,
                severity=pattern.severity,
                category=pattern.category,
                description=pattern.description,
                file_path=rel_path,
                line_number=line_num,
                line_content=line.strip()[:120],
                matched_text=matched,
                confidence=confidence,
                remediation=remediation,
            ))

    return findings


def _walk_files(root: Path, excludes: set[str]):
    """Walk files, skipping binary files, large files, and excluded patterns."""

    def _should_skip(name: str) -> bool:
        if name in SKIP_DIRS or name in excludes:
            return True
        for pattern in excludes:
            if pattern.startswith("*.") and name.endswith(pattern[1:]):
                return True
        return False

    def _walk(directory: Path):
        try:
            entries = sorted(directory.iterdir())
        except PermissionError:
            return

        for entry in entries:
            if entry.name.startswith(".") and entry.name not in (".env", ".env.local", ".env.production"):
                if entry.is_dir():
                    continue

            if entry.is_dir():
                if not _should_skip(entry.name):
                    yield from _walk(entry)
            elif entry.is_file():
                ext = entry.suffix.lower()
                if ext in BINARY_EXTENSIONS:
                    continue
                try:
                    if entry.stat().st_size > MAX_FILE_SIZE:
                        continue
                except OSError:
                    continue
                yield entry

    yield from _walk(root)


def _load_gitignore(root: Path) -> set[str]:
    """Load .gitignore patterns."""
    patterns = set()
    gitignore = root / ".gitignore"

    if gitignore.exists():
        try:
            for line in gitignore.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    patterns.add(line.rstrip("/"))
        except Exception:
            pass

    return patterns
