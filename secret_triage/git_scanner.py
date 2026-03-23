"""Git history scanner: finds secrets in previous commits."""

import subprocess
from pathlib import Path

from .patterns import get_all_patterns
from .scorer import calculate_confidence
from .remediation import get_remediation
from .scanner import Finding


def scan_git_history(root: Path, max_commits: int = 100, verbose: bool = False) -> list[Finding]:
    """Scan git history for secrets that may have been committed and later removed."""
    findings = []

    if not (root / ".git").exists():
        if verbose:
            print("  Not a git repository, skipping history scan.")
        return findings

    patterns = get_all_patterns()

    # Get list of commits
    try:
        result = subprocess.run(
            ["git", "log", "--all", "--diff-filter=A", "--pretty=format:%H", f"-{max_commits}"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=30,
        )
        commits = result.stdout.strip().split("\n")
        commits = [c for c in commits if c]
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return findings

    if verbose:
        print(f"  Scanning {len(commits)} commits...")

    for commit_sha in commits:
        try:
            # Get diff for this commit
            diff_result = subprocess.run(
                ["git", "diff-tree", "--no-commit-id", "-r", "-p", commit_sha],
                cwd=str(root),
                capture_output=True,
                text=True,
                timeout=15,
            )
            diff_text = diff_result.stdout
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

        # Parse added lines from the diff
        current_file = ""
        line_num = 0

        for line in diff_text.split("\n"):
            if line.startswith("+++ b/"):
                current_file = line[6:]
                line_num = 0
                continue

            if line.startswith("@@"):
                # Parse line number from hunk header
                try:
                    parts = line.split("+")[1].split(",")
                    line_num = int(parts[0]) - 1
                except (IndexError, ValueError):
                    line_num = 0
                continue

            if line.startswith("+") and not line.startswith("+++"):
                line_num += 1
                added_line = line[1:]  # Remove the leading +

                if len(added_line) < 5 or len(added_line) > 2000:
                    continue

                for pattern in patterns:
                    match = pattern.pattern.search(added_line)
                    if not match:
                        continue

                    try:
                        matched = match.group("secret")
                    except IndexError:
                        matched = match.group(0)

                    confidence = calculate_confidence(
                        matched_text=matched,
                        line=added_line,
                        file_path=current_file,
                        pattern=pattern,
                    )

                    if confidence < 0.3:
                        continue

                    # Check if the secret still exists in the current working tree
                    still_exists = _secret_still_in_tree(root, matched)

                    # Reduce confidence if no longer present (already rotated?)
                    if not still_exists:
                        confidence *= 0.7

                    remediation = get_remediation(pattern.id)

                    findings.append(Finding(
                        pattern_id=pattern.id,
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        category=pattern.category,
                        description=pattern.description + " (found in git history)",
                        file_path=current_file,
                        line_number=line_num,
                        line_content=added_line.strip()[:120],
                        matched_text=matched,
                        confidence=confidence,
                        is_git_history=True,
                        commit_sha=commit_sha[:8],
                        remediation=remediation + "\nNote: This secret was found in git history. Even if removed from current files, it may still be accessible. Consider force-pushing with history rewrite (BFG Repo-Cleaner) or rotating the credential immediately.",
                    ))

            elif not line.startswith("-"):
                line_num += 1

    return findings


def _secret_still_in_tree(root: Path, secret: str) -> bool:
    """Check if a secret string still exists in the current working tree."""
    try:
        result = subprocess.run(
            ["git", "grep", "-q", "--fixed-strings", secret],
            cwd=str(root),
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False
