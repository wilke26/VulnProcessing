import subprocess
from pathlib import Path

from scripts.check_public_snapshot import inspect_file, tracked_files


def _write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _inspect(path: Path) -> list[str]:
    return inspect_file(path, path.read_bytes())


def test_rejects_sqlite_content_without_database_extension(tmp_path: Path) -> None:
    path = _write(tmp_path, "runtime-state", b"SQLite format 3\x00" + b"\x00" * 64)

    assert _inspect(path) == ["SQLite database content"]


def test_rejects_jwt_like_credentials(tmp_path: Path) -> None:
    token = b"a" * 20 + b"." + b"b" * 20 + b"." + b"c" * 20
    path = _write(tmp_path, "settings.txt", b"TOKEN=" + token)

    assert _inspect(path) == ["JWT-like credential"]


def test_rejects_private_key_header_families(tmp_path: Path) -> None:
    labels = (
        b"PRIVATE KEY",
        b"ENCRYPTED PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"DSA PRIVATE KEY",
        b"EC PRIVATE KEY",
        b"OPENSSH PRIVATE KEY",
        b"FUTURE-ALGORITHM PRIVATE KEY",
    )

    for label in labels:
        path = _write(tmp_path, "identity.txt", b"-----BEGIN " + label + b"-----\nredacted")
        assert _inspect(path) == ["private key material"]


def test_allows_non_private_pem_headers(tmp_path: Path) -> None:
    labels = (
        b"PUBLIC KEY",
        b"RSA PUBLIC KEY",
        b"CERTIFICATE",
        b"CERTIFICATE REQUEST",
        b"X509 CRL",
        b"DSA PARAMETERS",
        b"EC PARAMETERS",
    )

    for label in labels:
        path = _write(tmp_path, "public.pem", b"-----BEGIN " + label + b"-----\nredacted")
        assert _inspect(path) == []


def test_rejects_tracked_dotenv_even_without_secret_pattern(tmp_path: Path) -> None:
    path = _write(tmp_path, ".env", b"LOG_LEVEL=INFO\n")

    assert _inspect(path) == ["tracked environment file"]


def test_rejects_tracked_dotenv_variants(tmp_path: Path) -> None:
    names = (
        ".env.local",
        ".env.production",
        ".env.development.local",
        ".env.bak",
        ".env~",
        ".ENV",
        ".ENV.local",
        "config/.Env.production",
        "config/.env.local",
        ".env.production.example",
        ".ENV.production.example",
    )

    for name in names:
        path = _write(tmp_path, name, b"LOG_LEVEL=INFO\n")
        assert _inspect(path) == ["tracked environment file"]


def test_allows_safe_source_and_exact_dotenv_example(tmp_path: Path) -> None:
    path = _write(tmp_path, "settings.example", b"TOKEN=replace-me\n")
    dotenv_example = _write(tmp_path, ".env.example", b"TOKEN=replace-me\n")
    uppercase_dotenv_example = _write(tmp_path, ".ENV.example", b"TOKEN=replace-me\n")

    assert _inspect(path) == []
    assert _inspect(dotenv_example) == []
    assert _inspect(uppercase_dotenv_example) == []


def test_rejects_local_ide_metadata(tmp_path: Path) -> None:
    for name in (".idea/misc.xml", ".vscode/settings.json"):
        path = _write(tmp_path, name, b"shared-looking but workstation-specific settings\n")
        assert _inspect(path) == ["local IDE metadata"]


def test_rejects_local_workstation_paths(tmp_path: Path) -> None:
    examples = (
        b"/" + b"Users/example/One" + b"Drive/project/input.json",
        b"C:\\" + b"Users\\example\\Documents\\input.json",
        b"~/One" + b"Drive - Example Organisation/project/input.json",
    )

    for content in examples:
        path = _write(tmp_path, "config.txt", content)
        assert _inspect(path) == ["local workstation path"]


def test_allows_non_path_onedrive_references(tmp_path: Path) -> None:
    examples = (
        b"Use One" + b"Drive for backups.",
        b"One" + b"DriveSync is an example identifier.",
    )

    for content in examples:
        path = _write(tmp_path, "documentation.txt", content)
        assert _inspect(path) == []


def test_reads_staged_blob_instead_of_worktree_copy(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    candidate = _write(
        tmp_path,
        "candidate",
        b"SQLite format 3\x00" + b"staged database content",
    )
    subprocess.run(["git", "add", "candidate"], cwd=tmp_path, check=True)
    candidate.write_bytes(b"safe working-tree replacement\n")

    files = dict(tracked_files(tmp_path))

    assert inspect_file(Path("candidate"), files[Path("candidate")]) == ["SQLite database content"]


def test_does_not_read_unstaged_or_deleted_worktree_content(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "--quiet"], cwd=tmp_path, check=True)
    candidate = _write(tmp_path, "candidate", b"safe staged content\n")
    subprocess.run(["git", "add", "candidate"], cwd=tmp_path, check=True)
    candidate.write_bytes(b"SQLite format 3\x00" + b"unstaged database content")

    files = dict(tracked_files(tmp_path))
    candidate.unlink()
    files_after_deletion = dict(tracked_files(tmp_path))

    assert inspect_file(Path("candidate"), files[Path("candidate")]) == []
    assert files_after_deletion == files
