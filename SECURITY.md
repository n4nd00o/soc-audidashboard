# Security Policy

SOC AudiDashboard is a student project, maintained on a best-effort basis.

## Reporting a vulnerability

Please report vulnerabilities through **GitHub private vulnerability reporting**
(repository "Security" tab, then "Report a vulnerability").

**Do not open public issues, pull requests or discussions for vulnerabilities.**

Include the affected version or commit, reproduction steps and impact. We will
acknowledge the report as soon as we can and coordinate a fix and disclosure with you.

## Scope

In scope: the code in this repository (core, desktop app, server, SDK, official plugins).
Out of scope: vulnerabilities in third-party plugins, and the intentionally insecure
lab targets under `lab/`.

## Ethical use

This tool must only be used against systems you own or are explicitly authorized to audit.

## Server threat model / Modelo de ameaças do servidor

> Scope: `packages/audidash-server` and `deploy/` at `0.2.0-alpha.1`. Student project, not
> audited by third parties. / Escopo: servidor e `deploy/` em `0.2.0-alpha.1`; projeto estudantil,
> sem auditoria externa.

### Trust boundaries / Fronteiras de confiança

| Boundary | Protection | Trust placed in it |
|---|---|---|
| Browser <-> Caddy `:8443` | TLS (Caddy internal CA); `/api*` answers 404 here | Dashboard users, authenticated by password + TOTP session |
| CLI <-> Caddy `:9443` | TLS 1.3 + **mutual TLS**: client certificate issued by the AudiDashboard internal CA; server certificate from the same CA, pinned by the CLI | Enrolled devices only |
| Caddy <-> app | Internal Docker network (`internal: true`, no egress) + secret header `X-Audidash-Proxy-Secret`; Caddy strips client-supplied copies of the proxy headers and sets the peer IP and (on `:9443`) the verified client-certificate fingerprint | The app trusts these headers **only** when the secret matches (constant-time compare) |
| App <-> PostgreSQL | Same internal network; credentials from the environment | The database holds findings, users (Argon2id hashes, encrypted TOTP secrets) and the audit log |

Fronteiras equivalentes em PT: navegador -> Caddy `:8443` (TLS + sessão); CLI -> Caddy `:9443`
(mTLS com certificado de dispositivo emitido pela CA interna); Caddy -> app (rede interna +
cabeçalho com segredo do proxy); app -> PostgreSQL (rede interna).

### Proxy secret / Segredo do proxy

The app takes the device identity (client-certificate fingerprint) and client IP from headers set
by Caddy. The proxy secret is what lets the app tell Caddy's headers from a forgery: a request
without the correct secret is rejected, so a direct request to the app cannot claim to be a device.

**Limits:** anyone who can reach the app on the backend network **and** knows the secret can
impersonate any device (the fingerprint header is then trusted). Keep the backend network
`internal`, never publish the app port, keep the secret out of logs and images, and rotate it
(`AUDIDASH_PROXY_SECRET`, then recreate `server` and `proxy`) if it may have leaked. It must be
>= 32 URL-safe characters; the server refuses to start in production otherwise.

### Internal CA / CA interna

- EC P-256 CA (10-year validity); device certificates are valid for 90 days; the proxy's API
  certificate is re-validated on every `server` start (`check-server-cert`).
- The CA private key is stored **encrypted at rest** with `AUDIDASH_CA_PASSPHRASE` and is never
  overwritten: `init-ca` is a no-op when a CA exists, and `init-ca --force` moves the old CA aside
  instead of deleting it. Anyone with the key file **and** the passphrase can mint device
  certificates; back both up separately and treat the data volume as secret.
- There is no CRL/OCSP: revoking a device marks it revoked in the dashboard and the app rejects
  it on every request (`revoked_at` is checked together with the certificate fingerprint), but
  the certificate itself stays cryptographically valid until it expires. `init-ca --force` makes
  all enrolled devices re-enrol. / Não há CRL/OCSP: a revogação é checada pelo app.

### Dashboard session model / Modelo de sessão

Argon2id password hashing; **mandatory TOTP** (first login forces enrolment; a used code cannot be
replayed); account lockout after 5 failures (15 minutes) plus a per-IP login rate limit; opaque
server-side session ids in a `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Strict`), idle timeout
30 min and absolute timeout 12 h; CSRF token on every state-changing request; role-based access
control (RBAC) on every route; strict CSP/security headers (no inline scripts, no third-party
JavaScript: charts are server-rendered SVG, htmx is vendored); every security-relevant action goes
to a hash-chained audit log (`audidash-server audit verify`).

### Device enrolment is trust-on-first-use / Inscrição é TOFU

An enrolment token is single-use and expires in 24 h, so a stolen token is useful only until it
is used. **Limits:** an active man-in-the-middle on the very first connection can capture and
*burn* the token (denial of enrolment) and present its own CA. The `--ca-fingerprint` check, which
the operator copies out-of-band from `audidash-server show-ca-fingerprint`, catches CA
substitution; do not skip it. After enrolment, the CLI pins the CA certificate.

### Known server limitations / Limitações conhecidas do servidor

- **Per-process, in-memory rate limiter.** The per-IP login limiter lives in process memory: it
  resets on restart and is not shared between workers/replicas (the per-account lockout is stored
  in the database and is not affected). / O limitador por IP é em memória, por processo.
- **SQLite is development-only.** Concurrency (and the SQL-side lockout/audit-chain guarantees
  under load) is only exercised on PostgreSQL; production configuration requires a database URL
  and the compose stack uses PostgreSQL. / SQLite é só para desenvolvimento.
- **Caddy loads the API certificate only at start.** A reissued server certificate (or a changed
  `AUDIDASH_API_HOSTS`) takes effect after `docker compose up -d --force-recreate server proxy`.
- **`verified.json` cache trust is client-side.** The CLI caches the server's list of verified
  plugin hashes (`plugins list --sync-verified`) locally; whoever can write that file on the
  analyst's machine can alter what the client treats as `verified`. The catalog signature remains
  the root of trust for `official`. / O cache `verified.json` é confiado no cliente.
- **No revocation lists, no HSM/KMS.** Keys live in files/volumes protected by file permissions
  and a passphrase.

## Known limitations / Limitações conhecidas

- **Windows spawn race.** There is a short window between spawning a plugin process and
  assigning it to its Job Object; a plugin that spawns children immediately could escape
  the kill-on-close guarantee in that window. / Há uma janela curta entre criar o processo
  do plugin e associá-lo ao Job Object no Windows.
- **POSIX `setsid()` escape.** On POSIX the whole process group is killed with `killpg`, but a
  child that calls `setsid()` leaves the group and survives. / Em POSIX, um filho que chama
  `setsid()` escapa do `killpg`.
- **Port-scan budget vs. runner timeout.** A `budget_s` above roughly 295 s for the
  `network-port-scan` plugin can exceed the runner's 300 s timeout, so the run is killed
  instead of finishing with a budget warning. / Um `budget_s` acima de ~295 s pode estourar o
  tempo limite de 300 s do executor.
- **Pattern-based redaction.** Redaction covers `title`, `evidence`, `recommendation`,
  `references`, `item_key`, `warnings` and `stderr` (a finding's `target` is always replaced by
  the run's target). It is regex-based: secret shapes it does not know (e.g. an arbitrary
  password in free text without a `password=`-style key) can still pass. / A sanitização é
  baseada em padrões e pode não detectar todo segredo.
- **Official trust requires the maintainer's key.** The Ed25519 public key must be placed at
  `packages/audidash-core/src/audidash_core/keys/catalog.pub` by the maintainer (done for the bundled plugins). The matching private key is kept offline by
  the maintainer; if it is lost, a new key must be issued and the catalog re-signed. See
  [docs/plugins.md](docs/plugins.md#níveis-de-confiança). / A chave privada fica offline com o
  mantenedor.
