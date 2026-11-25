from __future__ import annotations

import signal
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import (
    BASELINE_FILE,
    SCAN_INTERVAL,
    SUSPICIOUS_PORTS,
    WATCH_DIRS,
    load_allowlist,
    setup_logger,
)
from .filescan import hash_cached, sha256_file, sync_and_scan_files
from .network import (
    is_allowlisted,
    load_baseline_endpoints,
    parse_proc_net,
    reverse_dns,
    save_baseline_endpoints,
)
from .ui import Notifier, render_cli


def seed_initial_files(
    watch_dirs: list[Path],
    known_files: set[str],
    hash_cache: dict[tuple[str, float, int], str],
) -> None:
    for base_dir in watch_dirs:
        if not base_dir.exists() or not base_dir.is_dir():
            continue
        try:
            for entry in base_dir.iterdir():
                if entry.is_file():
                    known_files.add(str(entry))
                    try:
                        hash_cached(entry, hash_cache)
                    except OSError:
                        pass
        except (PermissionError, OSError):
            pass


def main() -> None:
    logger = setup_logger()
    notifier = Notifier(logger)
    stop_event = threading.Event()

    def _handle_signal(_signum: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    allowed_ips, allowed_domains = load_allowlist()
    allowlist_count = len(allowed_ips) + len(allowed_domains)

    known_files: set[str] = set()
    hash_cache: dict[tuple[str, float, int], str] = {}
    dns_cache: dict[str, str] = {}

    seed_initial_files(WATCH_DIRS, known_files, hash_cache)
    seen_endpoints: set[tuple[str, int]] = load_baseline_endpoints(BASELINE_FILE)

    new_conn_history: deque[dict[str, Any]] = deque(maxlen=100)
    file_alert_history: deque[dict[str, Any]] = deque(maxlen=100)
    recent_events: deque[str] = deque(maxlen=200)

    start_msg = (
        f"Sentinel v0.2 aktif. Baseline endpoint: {len(seen_endpoints)}, "
        f"Allowlist: {allowlist_count}."
    )
    recent_events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {start_msg}")
    logger.info(start_msg)

    cycle = 0
    baseline_dirty = False

    while not stop_event.is_set():
        cycle += 1
        raw_conns = parse_proc_net(Path("/proc/net/tcp"), is_v6=False) + parse_proc_net(
            Path("/proc/net/tcp6"), is_v6=True
        )

        visible_conns: list[dict[str, Any]] = []
        for c in raw_conns:
            ip = c["ip"]
            port = c["port"]
            host = reverse_dns(ip, dns_cache)
            c["host"] = host

            if is_allowlisted(ip, host, allowed_ips, allowed_domains):
                continue

            visible_conns.append(c)
            endpoint = (ip, port)
            if endpoint not in seen_endpoints:
                seen_endpoints.add(endpoint)
                baseline_dirty = True

                conn_record = dict(c)
                new_conn_history.append(conn_record)

                is_sus = port in SUSPICIOUS_PORTS
                host_part = f" ({host})" if host else ""
                msg = f"Koneksi baru {ip}:{port}{host_part} [{c['state']}]"
                recent_events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

                if is_sus:
                    logger.warning("SUSPICIOUS_PORT %s", msg)
                    notifier.send(
                        "Sentinel: Port Mencurigakan",
                        f"Koneksi ke {ip}:{port}{host_part}",
                    )
                else:
                    logger.info("NEW_CONN %s", msg)

        if baseline_dirty:
            save_baseline_endpoints(BASELINE_FILE, seen_endpoints)
            baseline_dirty = False

        file_alerts, removed_count = sync_and_scan_files(
            WATCH_DIRS, known_files, hash_cache
        )
        if removed_count > 0:
            logger.info("Synced %d file terhapus dari direktori pantauan.", removed_count)

        for fa in file_alerts:
            file_alert_history.append(fa)
            digest_info = (
                f"SHA256={fa['sha256']}"
                if fa["sha256"]
                else "SHA256=SKIPPED_LARGE_FILE"
            )
            msg = f"File {fa['name']} [{fa['severity']}] ({digest_info})"
            recent_events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
            logger.warning("FILE_ALERT %s", msg)
            notifier.send(
                f"Sentinel: {fa['severity']} APK Alert",
                f"{fa['name']}",
            )

        render_cli(
            cycle=cycle,
            active_conns=visible_conns,
            new_conns=new_conn_history,
            file_alerts=file_alert_history,
            recent_events=recent_events,
            allowlist_count=allowlist_count,
            log_name="sentinel.log",
        )

        stop_event.wait(SCAN_INTERVAL)

    save_baseline_endpoints(BASELINE_FILE, seen_endpoints)
    logger.info("Sentinel dihentikan dengan rapi.")
    print(f"\n{CYAN}Sentinel dihentikan. Log tersimpan di: {BASELINE_FILE.parent}{RESET}")


if __name__ == "__main__":
    main()
