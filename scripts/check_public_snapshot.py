"""Reject tracked runtime databases and common secret material before publication."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Iterator
from pathlib import Path

SQLITE_HEADER = b"SQLite format 3\x00"
JWT_PATTERN = re.compile(rb"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}")
PRIVATE_KEY_PATTERN = re.compile(rb"-----BEGIN (?:[A-Z0-9-]+ )*PRIVATE KEY-----")
LOCAL_PATH_PATTERN = re.compile(
    rb"(?:/"
    + rb"Users/[^/\s]+/|[A-Za-z]:\\"
    + rb"Users\\[^\\\r\n]+\\|~[/\\]One"
    + rb"Drive(?:\s+-\s+[^\\/\r\n]+)?[/\\])",
    re.IGNORECASE,
)
SAFE_DOTENV_TEMPLATES = {".env.example"}
LOCAL_METADATA_DIRECTORIES = {".idea", ".vscode"}
INDEX_BLOB_MODES = {b"100644", b"100755", b"120000"}


def is_runtime_dotenv(path: Path) -> bool:
    """Return whether a path is a secret-bearing dotenv file by policy."""
    name = path.name.casefold()
    is_dotenv_name = name == ".env" or name.startswith(".env.") or name == ".env~"
    return is_dotenv_name and name not in SAFE_DOTENV_TEMPLATES


def inspect_file(path: Path, data: bytes) -> list[str]:
    """Inspect candidate bytes without exposing matching secret values."""
    violations: list[str] = []
    if any(part.casefold() in LOCAL_METADATA_DIRECTORIES for part in path.parts):
        violations.append("local IDE metadata")
    if is_runtime_dotenv(path):
        violations.append("tracked environment file")

    if data.startswith(SQLITE_HEADER):
        violations.append("SQLite database content")
    # Poetry lock hashes can contain several long base64-like segments separated by dots.
    # Gitleaks remains the history-level credential scanner; this focused gate avoids that
    # deterministic lock-file false positive.
    if path.name != "poetry.lock" and JWT_PATTERN.search(data):
        violations.append("JWT-like credential")
    if PRIVATE_KEY_PATTERN.search(data):
        violations.append("private key material")
    if LOCAL_PATH_PATTERN.search(data):
        violations.append("local workstation path")
    return violations


def tracked_files(repo_root: Path) -> Iterator[tuple[Path, bytes]]:
    """Read candidate paths and blob contents directly from Git's index."""
    result = subprocess.run(
        ["git", "ls-files", "-z", "--stage"],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
    )
    entries: list[tuple[bytes, Path]] = []

    for entry in result.stdout.split(b"\0"):
        if not entry:
            continue
        metadata, separator, encoded_path = entry.partition(b"\t")
        if not separator:
            raise RuntimeError("unexpected Git index entry")
        mode, object_id, stage = metadata.split()
        path = Path(os.fsdecode(encoded_path))
        if stage != b"0":
            raise RuntimeError(f"unmerged Git index entry: {path}")
        if mode not in INDEX_BLOB_MODES:
            raise RuntimeError(f"unsupported Git index entry mode {mode.decode()}: {path}")
        entries.append((object_id, path))

    with subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=repo_root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    ) as process:
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("failed to open Git object stream")

        for object_id, path in entries:
            process.stdin.write(object_id + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().rstrip(b"\n")
            try:
                returned_id, object_type, encoded_size = header.split()
                size = int(encoded_size)
            except ValueError as error:
                raise RuntimeError(f"unexpected Git object header for {path}") from error
            if returned_id != object_id or object_type != b"blob":
                raise RuntimeError(f"unexpected Git object type for {path}")

            data = process.stdout.read(size)
            trailer = process.stdout.read(1)
            if len(data) != size or trailer != b"\n":
                raise RuntimeError(f"incomplete Git blob for {path}")
            yield path, data

        process.stdin.close()
        if process.wait() != 0:
            raise subprocess.CalledProcessError(process.returncode, process.args)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    findings: list[tuple[Path, str]] = []

    try:
        for path, data in tracked_files(repo_root):
            for violation in inspect_file(path, data):
                findings.append((path, violation))
    except (RuntimeError, subprocess.CalledProcessError) as error:
        print(f"Public snapshot check failed: {error}")
        return 1

    if findings:
        print("Public snapshot check failed:")
        for path, violation in findings:
            print(f"- {path}: {violation}")
        return 1

    print(
        "Public snapshot check passed: no tracked databases, targeted secrets "
        "or workstation metadata found."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
