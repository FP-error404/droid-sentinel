from __future__ import annotations

import argparse
import signal
import threading
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Any

from .config import (
    BASELINE_FILE,
    DB_FILE,
    DEFAULT_MAX_HASH_MB,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_WATCH_DIRS,
    SUSPICIOUS_PORTS,
    load_allowlist,
    setup_logger,
)
from .db import SentinelDB
from .filescan import FileSnapshot, seed_file_snapshots, sync_and_scan_files
from .network import (
    is_allowlisted,
    load_baseline_endpoints,
    parse_proc_net,
    reverse_dns,
    save_baseline_endpoints,
)
from .ui import Notifier, render_cli


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Droid Sentinel - Android defensive monitoring CLI for Termux.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_SCAN_INTERVAL,
        help=f"Interval pemindaian dalam detik (default: {DEFAULT_SCAN_INTERVAL}).",
    )
    parser.add_argument(
        "--dir",
        action="append",
        dest="dirs",
        default=None,
        help="Direktori yang dipantau (bisa diulang beberapa kali; default: /sdcard/Download).",
    )
    parser.add_argument(
        "--max-hash-size",
        type=int,
        default=DEFAULT_MAX_HASH_MB,
        help=f"Batas ukuran file untuk hashing SHA-256 dalam MB (default: {DEFAULT_MAX_HASH_MB}).",
    )
    parser.add_argument(
        "--no-notify",
        action="store_true",
        help="Nonaktifkan notifikasi Termux:API.",
    )
    args = parser.parse_args(argv)
    if args.interval <= 0:
        parser.error("--interval harus lebih besar dari 0.")
    if args.max_hash_size <= 0:
        parser.error("--max-hash-size harus lebih besar dari 0.")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    watch_dirs = [Path(d) for d in args.dirs] if args.dirs else list(DEFAULT_WATCH_DIRS)
    max_hash_bytes = args.max_hash_size * 1024 * 1024

    logger = setup_logger()
    db = SentinelDB(DB_FILE)
    notifier = Notifier(logger, enabled=not args.no_notify)
    stop_event = threading.Event()

    def _handle_signal(_signum: int, _frame: Any) -> None:
        stop_event.set()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    allowed_ips, allowed_domains = load_allowlist()
    allowlist_count = len(allowed_ips) + len(allowed_domains)

    snapshots: dict[str, FileSnapshot] = {}
    hash_cache: dict[tuple[str, float, int], str] = {}
    dns_cache: dict[str, str] = {}

    seed_file_snapshots(watch_dirs, snapshots, hash_cache, max_bytes=max_hash_bytes)
    seen_endpoints: set[tuple[str, int]] = load_baseline_endpoints(BASELINE_FILE)

    new_conn_history: deque[dict[str, Any]] = deque(maxlen=100)
    file_event_history: deque[dict[str, Any]] = deque(maxlen=100)
    recent_events: deque[str] = deque(maxlen=200)

    dirs_label = ", ".join(str(p) for p in watch_dirs)
    start_msg = (
        f"Droid Sentinel v0.3 aktif. Dirs=[{dirs_label}] | "
        f"Baseline={len(seen_endpoints)} | Allowlist={allowlist_count}"
    )
    recent_events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {start_msg}")
    logger.info(start_msg)

    cycle = 0
    baseline_dirty = False

    try:
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
                is_new = endpoint not in seen_endpoints
                is_sus = port in SUSPICIOUS_PORTS

                db.record_connection(
                    ip=ip,
                    port=port,
                    host=host,
                    state=c["state"],
                    is_new=is_new,
                    suspicious_port=is_sus,
                )

                if is_new:
                    seen_endpoints.add(endpoint)
                    baseline_dirty = True

                    conn_record = dict(c)
                    new_conn_history.append(conn_record)

                    host_part = f" ({host})" if host else ""
                    msg = f"Koneksi baru {ip}:{port}{host_part} [{c['state']}]"
                    recent_events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

                    if is_sus:
                        logger.warning("SUSPICIOUS_PORT %s", msg)
                        db.record_alert(
                            severity="MEDIUM",
                            category="NETWORK",
                            title="Port Mencurigakan",
                            message=msg,
                        )
                        notifier.send(
                            "Sentinel: Port Mencurigakan",
                            f"Koneksi ke {ip}:{port}{host_part}",
                        )
                    else:
                        logger.info("NEW_CONN %s", msg)

            if baseline_dirty:
                save_baseline_endpoints(BASELINE_FILE, seen_endpoints)
                baseline_dirty = False

            file_events, removed_count = sync_and_scan_files(
                watch_dirs, snapshots, hash_cache, max_bytes=max_hash_bytes
            )
            if removed_count > 0:
                logger.info("Synced %d file terhapus dari direktori pantauan.", removed_count)

            for fe in file_events:
                file_event_history.append(fe)
                db.record_file_event(
                    path=fe["path"],
                    filename=fe["name"],
                    event_type=fe["event_type"],
                    size_bytes=fe["size"],
                    sha256=fe["sha256"],
                    skipped_large=fe["skipped_large"],
                    is_apk=fe["is_apk"],
                    double_ext=fe["double_ext"],
                )

                digest_info = (
                    f"SHA256={fe['sha256']}"
                    if fe["sha256"]
                    else "SHA256=SKIPPED(FILE_TOO_LARGE)"
                )
                msg = (
                    f"[{fe['event_type']}] {fe['name']} [{fe['severity']}] "
                    f"({digest_info})"
                )
                recent_events.append(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")
                logger.warning("FILE_EVENT %s", msg)
                db.record_alert(
                    severity=fe["severity"],
                    category="FILE",
                    title=f"{fe['event_type']} ({fe['severity']})",
                    message=msg,
                )
                notifier.send(
                    f"Sentinel: {fe['severity']} {fe['event_type']}",
                    f"{fe['name']}",
                )

            render_cli(
                cycle=cycle,
                interval=args.interval,
                max_hash_mb=args.max_hash_size,
                notify_enabled=not args.no_notify,
                active_conns=visible_conns,
                new_conns=new_conn_history,
                file_events=file_event_history,
                recent_events=recent_events,
                allowlist_count=allowlist_count,
                log_name="sentinel.log",
            )

            stop_event.wait(args.interval)
    finally:
        save_baseline_endpoints(BASELINE_FILE, seen_endpoints)
        db.close()
        logger.info("Droid Sentinel dihentikan dengan rapi.")
        print(f"\n{CYAN}Droid Sentinel dihentikan. Data tersimpan di: {BASELINE_FILE.parent}{RESET}")


if __name__ == "__main__":
    main()
