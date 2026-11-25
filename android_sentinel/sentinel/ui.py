from __future__ import annotations

import logging
import subprocess
from collections import deque
from datetime import datetime
from typing import Any

from .config import BOLD, CYAN, DIM, GREEN, RED, RESET, SUSPICIOUS_PORTS, YELLOW


class Notifier:
    def __init__(self, logger: logging.Logger, enabled: bool = True) -> None:
        self.logger = logger
        self.enabled = enabled
        self._warned_missing = False

    def send(self, title: str, content: str) -> None:
        if not self.enabled:
            return
        try:
            proc = subprocess.run(
                [
                    "termux-notification",
                    "-t",
                    title,
                    "-c",
                    content,
                    "--priority",
                    "high",
                ],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            if proc.returncode != 0 and not self._warned_missing:
                self._warned_missing = True
                self.logger.warning(
                    "termux-notification keluar dengan kode %s; pastikan paket termux-api dan aplikasi Termux:API terpasang.",
                    proc.returncode,
                )
        except FileNotFoundError:
            if not self._warned_missing:
                self._warned_missing = True
                self.logger.warning(
                    "termux-api tidak tersedia, notifikasi Android dimatikan."
                )
        except subprocess.TimeoutExpired:
            self.logger.warning("termux-notification timeout saat mengirim alert.")


def render_cli(
    cycle: int,
    interval: float,
    max_hash_mb: int,
    notify_enabled: bool,
    active_conns: list[dict[str, Any]],
    new_conns: deque[dict[str, Any]],
    file_events: deque[dict[str, Any]],
    recent_events: deque[str],
    allowlist_count: int,
    log_name: str,
) -> None:
    print("\033[2J\033[H", end="")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    notif_status = "ON" if notify_enabled else "OFF"
    print(f"{CYAN}{BOLD}=== DROID SENTINEL (CLI v0.3) ==={RESET}")
    print(
        f"Waktu : {now_str} | Siklus: #{cycle} ({interval:.1f}s) | "
        f"MaxHash: {max_hash_mb}MB | Notif: {notif_status}"
    )
    print(f"Allowlist: {allowlist_count} | Log: {log_name} | DB: sentinel.db")
    print("-" * 60)

    print(
        f"{BOLD}[1] KONEKSI EKSTERNAL AKTIF (NON-ALLOWLIST): {len(active_conns)}{RESET}"
    )
    if not active_conns:
        print(f"    {GREEN}Tidak ada koneksi publik non-allowlist aktif.{RESET}")
    else:
        for c in active_conns[:10]:
            flag = f" {RED}[PORT ANOMALI]{RESET}" if c["port"] in SUSPICIOUS_PORTS else ""
            host_info = f" ({c['host']})" if c.get("host") else ""
            print(f"    - {c['ip']}:{c['port']}{host_info} [{c['state']}]{flag}")
        if len(active_conns) > 10:
            print(f"    {DIM}... +{len(active_conns) - 10} koneksi lainnya{RESET}")

    print("-" * 60)
    print(f"{BOLD}[2] PERINGATAN TERBARU (KONEKSI BARU / FILE & APK){RESET}")
    has_alert = False
    for nc in list(new_conns)[-5:]:
        has_alert = True
        warn = RED if nc["port"] in SUSPICIOUS_PORTS else YELLOW
        host_info = f" ({nc['host']})" if nc.get("host") else ""
        print(
            f"    {warn}! [NEW_CONN] {nc['ip']}:{nc['port']}{host_info} "
            f"({nc['state']}){RESET}"
        )
    for fe in list(file_events)[-5:]:
        has_alert = True
        ev_tag = "MODIFIED" if fe["event_type"] == "MODIFIED_FILE" else "NEW"
        apk_tag = "DOUBLE_EXT_APK" if fe["double_ext"] else ("APK" if fe["is_apk"] else "FILE")
        if fe["sha256"]:
            digest_label = f"SHA256: {fe['sha256'][:16]}..."
        elif fe["skipped_large"]:
            digest_label = "SHA256: SKIPPED (FILE_TOO_LARGE)"
        else:
            digest_label = "SHA256: N/A"
        color = RED if fe["severity"] == "HIGH" else YELLOW
        print(
            f"    {color}! [{ev_tag}/{apk_tag}] {fe['name']} | {digest_label}{RESET}"
        )

    if not has_alert:
        print(f"    {GREEN}Bersih - belum ada peringatan baru.{RESET}")

    print("-" * 60)
    print(f"{BOLD}[3] LOG AKTIVITAS TERAKHIR{RESET}")
    for ev in list(recent_events)[-6:]:
        print(f"    {ev}")
    print("-" * 60)
    print("Tekan Ctrl+C untuk menghentikan Droid Sentinel.")
