# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0-alpha.1] - 2026-11-25

First alpha: the foundation and core of the platform (Plan 1). CLI only.

### Added
- uv workspace monorepo (`audidash-core`, `audidash-sdk`), Apache-2.0 license and community files.
- Finding model and scoring (`findings`, `scoring`).
- Client-side sanitizer that redacts secrets and personal data (LGPD) from findings.
- Plugin manifest (`plugin.yaml`) with strict validation and SHA-256 integrity verification.
- Plugin runner with isolated subprocess execution, minimal environment, timeout and output caps,
  and whole-process-tree termination (Windows Job Objects, POSIX `killpg`).
- Ed25519-signed plugin catalog with trust tiers (`official`, `verified`, `community`)
  and `tools/sign_catalog.py`.
- `audidash` CLI: list, inspect, hash, validate and run plugins.
- Plugin SDK for Python plugins and plugin-authoring docs (PT-BR and EN).
- Three official plugins: `http-security-headers`, `tls-certificate-check`, `network-port-scan`.
- CI matrix (Ubuntu and Windows, Python 3.12 and 3.13; macOS, Python 3.12) with ruff, mypy, pytest coverage
  (>= 85 %), bandit and pip-audit; CodeQL, gitleaks and Dependabot.
- Issue and pull request templates, CODEOWNERS.
- ISO/IEC 27001/27002 and LGPD alignment documents (alignment, not certification).
- "Known limitations" section in `SECURITY.md`.

### Security
- `run_local` pins the reviewed manifest (`expected_manifest`, `expected_manifest_sha256`);
  the CLI passes the catalog pin and shows source only from bytes matching the pinned hashes,
  so code swapped after review is blocked (`integrity`).
- `verified` tier requires the `plugin.yaml` sha256 in the allow-list plus full file integrity.
- CLI escapes bidirectional/invisible Unicode (Trojan Source, CVE-2021-42574) and warns before
  the prompt; the manifest summary (permissions, connection, parameters) is shown before every run.
- Sanitizer also redacts URI userinfo passwords, `token`/`secret`/`api_key`-style values,
  quoted and `;`-terminated passwords, and GitHub/Slack/Stripe token formats.
- Findings: `target` forced to the run's target; `references` (max 50 x 200 chars) and
  `item_key` (max 255) are bounded and redacted; `RunResult` gains `manifest_sha256` and `trust`.
- Non-Python interpreters are resolved on the plugin's PATH (`interpreter_not_found:<name>`).

### Notes
- The catalog public key ships in `keys/catalog.pub`; the three bundled plugins are signed and
  load as `official`.
