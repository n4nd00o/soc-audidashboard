# http-security-headers

Requests a URL once (GET, redirects are not followed) and checks the response headers for common browser security protections. Certificate problems are ignored here; use `tls-certificate-check` for those.

Use only on sites you are authorized to audit.

## Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `url` | string | the run target | `http://` or `https://` URL to check; a bare host name is treated as `https://host` |

An invalid URL or an unreachable server produces one warning and no findings.

## Findings

| ID | Severity | Raised when |
|---|---|---|
| `HTTP-NO-HSTS` | medium | `Strict-Transport-Security` is missing (https URLs only) |
| `HTTP-NO-CSP` | medium | `Content-Security-Policy` is missing |
| `HTTP-NO-XCTO` | low | `X-Content-Type-Options` is missing |
| `HTTP-NO-FRAME-PROTECTION` | low | neither `X-Frame-Options` nor a CSP `frame-ancestors` directive is present |
| `HTTP-NO-REFERRER-POLICY` | low | `Referrer-Policy` is missing |
| `HTTP-SERVER-BANNER` | info | the `Server` header contains a version number |

## References

- OWASP ASVS 14.4
- ISO27002:2022 8.26

## Example

```
uv run audidash run http-security-headers --target https://example.org --target-type web
```

(Run it with `uv run audidash run <plugin-id> ...`; see the main README.)
