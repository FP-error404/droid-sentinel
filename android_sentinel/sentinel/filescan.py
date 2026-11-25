from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import DANGEROUS_EXT, DEFAULT_MAX_HASH_MB


@dataclass
class FileSnapshot:
    path: str
    size: int
    mtime: float
    sha256: str | None
    skipped_large: bool


def sha256_file(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def compute_hash_with_cache(
    file_path: Path,
    st_size: int,
    st_mtime: float,
    hash_cache: dict[tuple[str, float, int], str],
    max_bytes: int,
) -> tuple[str | None, bool]:
    """
    Kembalikan (sha256_hex_atau_None, skipped_due_to_size).
    Cache di-key berdasarkan (path, mtime, size).
    """
    if st_size > max_bytes:
        return None, True

    cache_key = (str(file_path), st_mtime, st_size)
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


def seed_file_snapshots(
    watch_dirs: list[Path],
    snapshots: dict[str, FileSnapshot],
    hash_cache: dict[tuple[str, float, int], str],
    max_bytes: int = DEFAULT_MAX_HASH_MB * 1024 * 1024,
) -> None:
    """Bangun snapshot awal file yang sudah ada saat startup."""
    for base_dir in watch_dirs:
        if not base_dir.exists() or not base_dir.is_dir():
            continue
        try:
            for entry in base_dir.iterdir():
                if not entry.is_file():
                    continue
                try:
                    st = entry.stat()
                    digest, skipped = compute_hash_with_cache(
                        entry, st.st_size, st.st_mtime, hash_cache, max_bytes
                    )
                    snapshots[str(entry)] = FileSnapshot(
                        path=str(entry),
                        size=st.st_size,
                        mtime=st.st_mtime,
                        sha256=digest,
                        skipped_large=skipped,
                    )
                except OSError:
                    pass
        except (PermissionError, OSError):
            pass


def sync_and_scan_files(
    watch_dirs: list[Path],
    snapshots: dict[str, FileSnapshot],
    hash_cache: dict[tuple[str, float, int], str],
    max_bytes: int = DEFAULT_MAX_HASH_MB * 1024 * 1024,
) -> tuple[list[dict[str, Any]], int]:
    """
    Sinkronkan file yang terhapus, deteksi file baru (NEW_FILE),
    dan deteksi perubahan isi/metadata pada file yang sudah ada (MODIFIED_FILE).
    Kembalikan (events, removed_count).
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

    removed_paths = set(snapshots.keys()) - current_paths
    removed_count = len(removed_paths)
    if removed_paths:
        for r_path in removed_paths:
            snapshots.pop(r_path, None)
        stale_keys = [k for k in hash_cache if k[0] in removed_paths]
        for k in stale_keys:
            del hash_cache[k]

    events: list[dict[str, Any]] = []

    for entry in candidate_files:
        p_str = str(entry)
        try:
            st = entry.stat()
        except OSError:
            continue

        prev = snapshots.get(p_str)
        is_apk, has_double_ext = check_apk_name(entry.name)

        if prev is None:
            try:
                digest, skipped_large = compute_hash_with_cache(
                    entry, st.st_size, st.st_mtime, hash_cache, max_bytes
                )
            except OSError:
                continue

            snapshots[p_str] = FileSnapshot(
                path=p_str,
                size=st.st_size,
                mtime=st.st_mtime,
                sha256=digest,
                skipped_large=skipped_large,
            )

            if is_apk or has_double_ext:
                severity = "HIGH" if has_double_ext else "MEDIUM"
                events.append(
                    {
                        "event_type": "NEW_FILE",
                        "severity": severity,
                        "path": p_str,
                        "name": entry.name,
                        "size": st.st_size,
                        "sha256": digest,
                        "skipped_large": skipped_large,
                        "is_apk": is_apk,
                        "double_ext": has_double_ext,
                    }
                )
            continue

        # File sudah dikenal: cek apakah ukuran, mtime, atau sha256 berubah
        if st.st_size != prev.size or st.st_mtime != prev.mtime:
            try:
                new_digest, skipped_large = compute_hash_with_cache(
                    entry, st.st_size, st.st_mtime, hash_cache, max_bytes
                )
            except OSError:
                continue

            hash_changed = (
                prev.sha256 is not None
                and new_digest is not None
                and new_digest != prev.sha256
            )
            size_or_mtime_changed = (st.st_size != prev.size) or (
                st.st_mtime != prev.mtime
            )

            snapshots[p_str] = FileSnapshot(
                path=p_str,
                size=st.st_size,
                mtime=st.st_mtime,
                sha256=new_digest,
                skipped_large=skipped_large,
            )

            if hash_changed or ((is_apk or has_double_ext) and size_or_mtime_changed):
                if has_double_ext or (is_apk and hash_changed):
                    severity = "HIGH"
                elif is_apk or hash_changed:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                events.append(
                    {
                        "event_type": "MODIFIED_FILE",
                        "severity": severity,
                        "path": p_str,
                        "name": entry.name,
                        "size": st.st_size,
                        "sha256": new_digest,
                        "skipped_large": skipped_large,
                        "is_apk": is_apk,
                        "double_ext": has_double_ext,
                    }
                )

    return events, removed_count
