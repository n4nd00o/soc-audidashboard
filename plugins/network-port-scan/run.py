"""TCP connect scan of a target host; reports open ports and risky exposed services."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from audidash_sdk import Reporter, run

# Top-100 commonly exposed TCP ports.
# fmt: off
DEFAULT_PORTS = [
    7, 20, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139,
    143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587,
    631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755,
    1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051,
    5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 5985, 6000, 6001, 6379, 6646, 7001, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9200, 9999, 10000, 11211, 27017, 32768, 49152,
]
# fmt: on

RISKY_PORTS = {
    21: "FTP (cleartext credentials)",
    23: "Telnet (cleartext remote shell)",
    135: "Microsoft RPC endpoint mapper",
    139: "NetBIOS session service",
    445: "SMB file sharing",
    3389: "Remote Desktop (RDP)",
    5900: "VNC remote desktop",
    6379: "Redis (often unauthenticated)",
    9200: "Elasticsearch HTTP API",
    11211: "Memcached",
    27017: "MongoDB",
}
REFERENCES = ["CIS Control 4.4", "ISO27002:2022 8.20"]
MAX_WORKERS = 50
MAX_PORTS = 1024
OPEN, CLOSED, NO_ANSWER, SKIPPED = "open", "closed", "no-answer", "skipped"


def parse_ports(value: object) -> list[int]:
    if not value:  # missing or empty: use the built-in list
        return list(DEFAULT_PORTS)
    if not isinstance(value, list):
        raise ValueError("'ports' must be a list of integers")
    ports: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or not 1 <= item <= 65535:
            raise ValueError(f"invalid port {item!r}: ports must be integers from 1 to 65535")
        ports.append(item)
    return sorted(set(ports))


def parse_budget(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 3600:
        raise ValueError("'budget_s' must be an integer from 1 to 3600")
    return float(value)


def parse_timeout(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 60000:
        raise ValueError("'timeout_ms' must be an integer from 1 to 60000")
    return value / 1000


def probe(address: tuple[Any, ...], family: int, timeout: float) -> str:
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect(address)
        return OPEN
    except ConnectionRefusedError:
        return CLOSED
    except OSError:
        return NO_ANSWER


def main(data: dict[str, Any], report: Reporter) -> None:
    params = data.get("parameters") or {}
    try:
        ports = parse_ports(params.get("ports", DEFAULT_PORTS))
        timeout = parse_timeout(params.get("timeout_ms", 500))
        budget = parse_budget(params.get("budget_s", 240))
    except ValueError as exc:
        report.warn(f"Invalid parameters, nothing scanned: {exc}")
        return
    if len(ports) > MAX_PORTS:
        report.warn(f"Too many ports ({len(ports)}); only the first {MAX_PORTS} are scanned.")
        ports = ports[:MAX_PORTS]
    host = str(data["target"])
    try:
        family, _, _, _, sockaddr = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0]
    except (socket.gaierror, UnicodeError) as exc:
        report.warn(f"Could not resolve target {host!r}: {exc}")
        return
    ip = str(sockaddr[0])

    deadline = time.monotonic() + budget

    def check(port: int) -> str:
        if time.monotonic() >= deadline:
            return SKIPPED
        return probe((ip, port), family, timeout)

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        states = dict(zip(ports, pool.map(check, ports), strict=True))
    skipped = sum(1 for state in states.values() if state == SKIPPED)
    if skipped:
        report.warn(f"Time budget of {budget:g}s exhausted; {skipped} ports were not scanned.")

    open_ports = [port for port, state in states.items() if state == OPEN]
    for port in open_ports:
        report.add(
            id="NET-OPEN-PORT",
            title=f"Open TCP port {port}",
            severity="info",
            category="misconfiguration",
            evidence=f"{host} ({ip}) accepted a TCP connection on port {port}.",
            recommendation="Confirm the service is required and restrict access with a firewall.",
            references=REFERENCES,
            item_key=str(port),
        )
        if port in RISKY_PORTS:
            report.add(
                id="NET-RISKY-PORT",
                title=f"Risky service exposed on TCP port {port}",
                severity="high",
                category="misconfiguration",
                evidence=f"Port {port} is open on {host} ({ip}): {RISKY_PORTS[port]}.",
                recommendation="Do not expose this service to untrusted networks; "
                "restrict it with a firewall or VPN, or disable it.",
                references=REFERENCES,
                item_key=str(port),
            )
    if not open_ports and CLOSED not in states.values() and NO_ANSWER in states.values():
        report.warn(f"No response from {host} ({ip}) on any scanned port; host may be unreachable.")


if __name__ == "__main__":
    run(main)
