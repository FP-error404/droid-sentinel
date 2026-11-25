from __future__ import annotations

import ipaddress
import json
import socket
from pathlib import Path
from typing import Any


def hex_ipv4_to_str(hex_ip: str) -> str:
    if len(hex_ip) != 8:
        return hex_ip
    octets = [str(int(hex_ip[i : i + 2], 16)) for i in (6, 4, 2, 0)]
    return ".".join(octets)


def hex_ipv6_to_str(hex_ip: str) -> str:
    if len(hex_ip) != 32:
        return hex_ip
    raw_bytes = bytearray()
    for i in range(0, 32, 8):
        word = hex_ip[i : i + 8]
        raw_bytes.extend(bytes.fromhex(word)[::-1])
    try:
        return socket.inet_ntop(socket.AF_INET6, bytes(raw_bytes))
    except OSError:
        return hex_ip


def is_private_or_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_unspecified
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return True


def reverse_dns(ip: str, cache: dict[str, str], timeout: float = 1.0) -> str:
    if ip in cache:
        return cache[ip]
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        cleaned = host.strip().lower().rstrip(".")
    except (socket.herror, socket.gaierror, TimeoutError, OSError):
        cleaned = ""
    finally:
        socket.setdefaulttimeout(old_timeout)
    cache[ip] = cleaned
    return cleaned


def is_allowlisted(
    ip: str,
    hostname: str,
    allowed_ips: set[str],
    allowed_domains: set[str],
) -> bool:
    if ip in allowed_ips:
        return True
    if hostname:
        if hostname in allowed_domains:
            return True
        for dom in allowed_domains:
            if hostname.endswith(f".{dom}"):
                return True
    return False


def parse_proc_net(path: Path, is_v6: bool = False) -> list[dict[str, Any]]:
    conns: list[dict[str, Any]] = []
    if not path.exists():
        return conns
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
    except (PermissionError, OSError):
        return conns

    state_map = {
        "01": "ESTABLISHED",
        "02": "SYN_SENT",
        "03": "SYN_RECV",
        "06": "TIME_WAIT",
        "0A": "LISTEN",
    }

    for line in lines:
        parts = line.split()
        if len(parts) < 4:
            continue
        rem_addr = parts[2]
        state = state_map.get(parts[3].upper(), parts[3].upper())
        if state not in ("ESTABLISHED", "SYN_SENT") or ":" not in rem_addr:
            continue

        ip_hex, port_hex = rem_addr.split(":", 1)
        ip = hex_ipv6_to_str(ip_hex) if is_v6 else hex_ipv4_to_str(ip_hex)
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue

        if port <= 0 or is_private_or_loopback(ip):
            continue

        conns.append({"ip": ip, "port": port, "state": state})
    return conns


def load_baseline_endpoints(baseline_file: Path) -> set[tuple[str, int]]:
    if not baseline_file.exists():
        return set()
    try:
        data = json.loads(baseline_file.read_text(encoding="utf-8"))
        endpoints: set[tuple[str, int]] = set()
        for item in data:
            if isinstance(item, list) and len(item) == 2:
                ip, port = item[0], int(item[1])
                if isinstance(ip, str) and port > 0:
                    endpoints.add((ip, port))
        return endpoints
    except (OSError, ValueError, TypeError):
        return set()


def save_baseline_endpoints(baseline_file: Path, endpoints: set[tuple[str, int]]) -> None:
    try:
        serialized = sorted([[ip, port] for ip, port in endpoints])
        baseline_file.write_text(json.dumps(serialized, indent=2), encoding="utf-8")
    except OSError:
        pass
