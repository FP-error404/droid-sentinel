from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .config import DANGEROUS_EXT, MAX_HASH_BYTES


def sha256_file(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def hash_cached(
    file_path: Path,
    hash_cache: dict[tuple[str, float, int], str],
    max_bytes: int = MAX_HASH_BYTES,
) -> tuple[str | None, bool]:
    """
    Kembalikan (sha256_hex_atau_None, skipped_due_to_size).
    Cache di-key berdasarkan (path, mtime, size).
    """
    st = file_path.stat()
    if st.st_size > max_bytes:
        return None, True

    cache_key = (str(file_path), st.st_mtime, st.st_size)
    if cache_key in hash_cache:
        return hash_cache[cache_key], False

    digest = sha256_file(file_path)
    hash_cache[cache_key] = digest
    return digest, False


def check_apk_name(filename: str) -> tuple[bool, bool]:
    """Kembalikan (is_apk, has_dangerous_double_ext)."""
    lower = filename.lower()
    is_apk = lower.endswith(".apk")
    parts = lower.split(".")
    has_double_ext = (
        len(parts) >= 3
        and parts[-1] == "apk"
        and parts[-2] in DANGEROUS_EXT
    )
    return is_apk, has_double_ext


def sync_and_scan_files(
    watch_dirs: list[Path],
    known_files: set[str],
    hash_cache: dict[tuple[str, float, int], str],
    max_bytes: int = MAX_HASH_BYTES,
) -> tuple[list[dict[str, Any]], int]:
    """
    Sinkronkan file yang sudah terhapus, lalu pindai file baru.
    Kembalikan (alerts, removed_count).
    """
    current_paths: set[str] = set()
    candidate_files: list[Path] = []

    for base_dir in watch_dirs:
        if not base_dir.exists() or not base_dir.is_dir():
            continue
        try:
            for entry in base_dir.iterdir():
                if entry.is_file():
                    p_str = str(entry)
                    current_paths.add(p_str)
                    candidate_files.append(entry)
        except (PermissionError, OSError):
            continue

    # Bersihkan file yang sudah tidak ada di direktori pantauan
    removed_paths = known_files - current_paths
    removed_count = len(removed_paths)
    if removed_paths:
        known_files.difference_update(removed_paths)
        stale_cache_keys = [k for k in hash_cache if k[0] in removed_paths]
        for k in stale_cache_keys:
            del hash_cache[k]

    alerts: list[dict[str, Any]] = []
    for entry in candidate_files:
        p_str = str(entry)
        if p_str in known_files:
            continue

        try:
            digest, skipped_large = hash_cached(entry, hash_cache, max_bytes=max_bytes)
        except OSError:
            continue

        known_files.add(p_str)
        is_apk, has_double_ext = check_apk_name(entry.name)

        if is_apk or has_double_ext:
            severity = "HIGH" if has_double_ext else "MEDIUM"
            alerts.append(
                {
                    "severity": severity,
                    "name": entry.name,
                    "sha256": digest,
                    "skipped_large": skipped_large,
                    "double_ext": has_double_ext,
                }
            )

    return alerts, removed_count
