from __future__ import annotations

import logging
import subprocess
from collections import deque
from datetime import datetime
from typing import Any

from .config import BOLD, CYAN, DIM, GREEN, RED, RESET, SUSPICIOUS_PORTS, YELLOW


class Notifier:
    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger
        self._warned_missing = False

    def send(self, title: str, content: str) -> None:
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
    active_conns: list[dict[str, Any]],
    new_conns: deque[dict[str, Any]],
    file_alerts: deque[dict[str, Any]],
    recent_events: deque[str],
    allowlist_count: int,
    log_name: str,
) -> None:
    print("\033[2J\033[H", end="")
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{CYAN}{BOLD}=== ANDROID DEFENSE SENTINEL (CLI v0.2) ==={RESET}")
    print(
        f"Waktu : {now_str} | Siklus: #{cycle} | "
        f"Allowlist: {allowlist_count} | Log: {log_name}"
    )
    print("-" * 56)

    print(
        f"{BOLD}[1] KONEKSI EKSTERNAL AKTIF (NON-ALLOWLIST): {len(active_conns)}{RESET}"
    )
    if not active_conns:
        print(f"    {GREEN}Tidak ada koneksi publik baru/non-allowlist aktif.{RESET}")
    else:
        for c in active_conns[:10]:
            flag = f" {RED}[PORT ANOMALI]{RESET}" if c["port"] in SUSPICIOUS_PORTS else ""
            host_info = f" ({c['host']})" if c.get("host") else ""
            print(f"    - {c['ip']}:{c['port']}{host_info} [{c['state']}]{flag}")
        if len(active_conns) > 10:
            print(f"    {DIM}... +{len(active_conns) - 10} koneksi lainnya{RESET}")

    print("-" * 56)
    print(f"{BOLD}[2] PERINGATAN TERBARU (APK / KONEKSI BARU){RESET}")
    has_alert = False
    for nc in list(new_conns)[-5:]:
        has_alert = True
        warn = RED if nc["port"] in SUSPICIOUS_PORTS else YELLOW
        host_info = f" ({nc['host']})" if nc.get("host") else ""
        print(
            f"    {warn}! Koneksi baru -> {nc['ip']}:{nc['port']}{host_info} "
            f"({nc['state']}){RESET}"
        )
    for fa in list(file_alerts)[-5:]:
        has_alert = True
        tag = "DOUBLE EXT APK" if fa["double_ext"] else "APK BARU"
        if fa["sha256"]:
            digest_label = f"SHA256: {fa['sha256'][:16]}..."
        elif fa["skipped_large"]:
            digest_label = "SHA256: dilewati (> batas ukuran)"
        else:
            digest_label = "SHA256: tidak tersedia"
        print(f"    {RED}! [{tag}] {fa['name']} | {digest_label}{RESET}")

    if not has_alert:
        print(f"    {GREEN}Bersih - belum ada peringatan baru.{RESET}")

    print("-" * 56)
    print(f"{BOLD}[3] LOG AKTIVITAS TERAKHIR{RESET}")
    for ev in list(recent_events)[-6:]:
        print(f"    {ev}")
    print("-" * 56)
    print("Tekan Ctrl+C untuk menghentikan sentinel.")
