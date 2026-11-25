# tls-certificate-check

Connects to a TLS service, reads its certificate and checks expiry, trust, host name match and support for deprecated protocol versions. Standard library only.

Use only on hosts you are authorized to audit.

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `port` | integer | 443 | TCP port of the TLS service |

The target is a host name or IP (a `https://` URL is also accepted). A target that is unreachable or does not speak TLS produces one warning and no findings.

## How it works

The certificate is fetched with an unverified handshake and its validity dates are read with a small DER parser. A second, verifying handshake classifies untrusted chains and host name mismatches. For untrusted certificates the host name is re-checked with the presented certificate pinned as the only trust anchor. TLS 1.0 and 1.1 are probed with handshakes limited to exactly that version. Limitation: a certificate that is both expired and mismatched may report only the expiry.

## Findings

| ID | Severity | Raised when |
|---|---|---|
| `TLS-EXPIRED` | critical | the certificate is past its `notAfter` date |
| `TLS-EXPIRING` | high (14 days or less) / medium (30 days or less) | the certificate expires soon |
| `TLS-SELF-SIGNED` | medium | the chain does not lead to a trusted root (self-signed or unknown issuer) |
| `TLS-HOSTNAME-MISMATCH` | high | the certificate is not valid for the target host name |
| `TLS-WEAK-PROTOCOL` | high | a TLS 1.0 or 1.1 handshake succeeds |

## References

- ISO27002:2022 8.24

## Example

```
uv run audidash run tls-certificate-check --target example.org --target-type network --param port=443
```

(The `audidash run` command arrives with the CLI task; until then use `audidash_core.runner.run_local`.)
