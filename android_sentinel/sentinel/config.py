from __future__ import annotations

import ipaddress
import logging
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_DIR = Path.home() / "sentinel_logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

BASELINE_FILE = LOG_DIR / "baseline_conns.json"
DB_FILE = LOG_DIR / "sentinel.db"
ALLOWLIST_FILE = BASE_DIR / "allowlist.txt"

DEFAULT_SCAN_INTERVAL = 4.0
DEFAULT_WATCH_DIRS = [Path("/sdcard/Download")]
DEFAULT_MAX_HASH_MB = 100
SUSPICIOUS_PORTS = {4444, 5555, 8080, 9001, 1337, 31337, 6666}

DANGEROUS_EXT = {
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "webp",
    "txt",
    "csv",
    "mp4",
    "mkv",
    "mp3",
    "zip",
    "rar",
    "7z",
    "html",
    "htm",
}

# Warna ANSI
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


def setup_logger() -> logging.Logger:
    logger = logging.getLogger("sentinel")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    logger.propagate = False

    log_path = LOG_DIR / "sentinel.log"
    handler = TimedRotatingFileHandler(
        filename=log_path,
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8",
    )
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    return logger


def load_allowlist(path: Path = ALLOWLIST_FILE) -> tuple[set[str], set[str]]:
    """Kembalikan (allowed_ips, allowed_domains) dari allowlist.txt."""
    ips: set[str] = set()
    domains: set[str] = set()
    if not path.exists():
        return ips, domains

    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return ips, domains

    for raw in lines:
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
            ips.add(line)
        except ValueError:
            domains.add(line.rstrip("."))
    return ips, domains
