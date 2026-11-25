# network-port-scan

TCP connect scan of a host. Reports every open port and flags services that should rarely be exposed (FTP, Telnet, RPC, NetBIOS, SMB, RDP, VNC, Redis, Elasticsearch, Memcached, MongoDB).

Use only on hosts you are authorized to audit. The plugin completes TCP handshakes only; it sends no payloads.

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `ports` | list | top-100 TCP ports (embedded in `run.py`) | Ports to scan, integers 1-65535, at most 1024 (extra ports are dropped with a warning); empty or omitted uses the default list |
| `timeout_ms` | integer | 500 | Per-port connect timeout in milliseconds (1-60000) |
| `budget_s` | integer | 240 | Overall time budget in seconds (1-3600); remaining ports are skipped with one warning and findings gathered so far are still reported |

Invalid parameters or an unresolvable host produce one warning and no findings. Up to 50 ports are probed in parallel.

## Findings

| ID | Severity | `item_key` | Raised when |
|---|---|---|---|
| `NET-OPEN-PORT` | info | port | a scanned port accepts a TCP connection |
| `NET-RISKY-PORT` | high | port | an open port is one of 21, 23, 135, 139, 445, 3389, 5900, 6379, 9200, 11211, 27017 (reported in addition to `NET-OPEN-PORT`) |

## References

- CIS Control 4.4
- ISO27002:2022 8.20

## Example

```
uv run audidash run network-port-scan --target 192.0.2.10 --target-type network
```

(Run it with `uv run audidash run <plugin-id> ...`; see the main README.)
