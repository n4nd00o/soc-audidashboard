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
  `packages/audidash-core/src/audidash_core/keys/catalog.pub` by the maintainer. It is not
  present yet, so **all plugins are currently treated as `community`** (confirmation
  required). See [docs/plugins.md](docs/plugins.md#níveis-de-confiança). / Enquanto a chave
  pública não existir, todos os plugins são `community`.
