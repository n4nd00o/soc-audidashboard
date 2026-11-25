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
- CI matrix (Ubuntu and Windows, Python 3.12 and 3.13) with ruff, mypy, pytest coverage
  (>= 85 %), bandit and pip-audit; CodeQL, gitleaks and Dependabot.
- Issue and pull request templates, CODEOWNERS.
- ISO/IEC 27001/27002 and LGPD alignment documents (alignment, not certification).
- "Known limitations" section in `SECURITY.md`.

### Notes
- No catalog public key ships yet, so all plugins are treated as `community` until the
  maintainer adds `keys/catalog.pub`.
