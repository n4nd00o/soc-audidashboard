# Plan 1 — Foundation & Core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the open-source repo and the `audidash-core` engine (finding/manifest schemas, sanitizer, scoring, signed catalog, isolated local runner), a Python plugin SDK, the first three `local` plugins, a minimal `audidash` CLI and full CI — usable end-to-end from the terminal.

**Architecture:** uv workspace monorepo. `audidash-core` is a pure library consumed later by the server (Plan 2) and the desktop app (Plan 3); remote SSH/WinRM execution and the Linux/Windows plugins come in Plan 4. Plugins are standalone directories executed in a subprocess that receives JSON on stdin and prints JSON findings on stdout.

**Tech Stack:** Python 3.12, uv, pydantic v2, PyYAML, cryptography (Ed25519, test certs), pytest, ruff, mypy, bandit, pip-audit, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-11-25-soc-audidashboard-design.md`

**Roadmap (other plans, written after this one ships):**
- Plan 2 — Server: FastAPI API + HTMX dashboard, PostgreSQL, auth (Argon2id + TOTP), RBAC, assets registry, finding lifecycle, audit log, docker compose.
- Plan 3 — Desktop app (PySide6), device enrollment + internal CA + mTLS, keyring credentials, upload.
- Plan 4 — Remote execution (SSH/WinRM), wave-1 Linux/Windows plugins, PowerShell/Bash examples, `lab/` targets.

## Global Constraints

- Python `>=3.12`; workspace managed by `uv`; package import names `audidash_core`, `audidash_sdk`.
- Code, identifiers, commits and docstrings in English; README in PT-BR (`README.md`) and EN (`README.en.md`).
- License Apache-2.0. README states clearly: student project, for portfolio; use only on infrastructure you are authorized to audit; aligned with (not certified for) ISO 27001/27002 and LGPD.
- Conventional Commits; SemVer starting at `0.1.0`.
- Severity weights: info 0, low 1, medium 3, high 7, critical 10; `suspicious` category ×1.5.
- Asset criticality weights: low 0.5, medium 1.0, high 1.5. Score `100 × (1 − e^(−Σ/k))`, k = 20. Bands: 0–24 Baixo/Low, 25–49 Moderado/Moderate, 50–74 Alto/High, 75–100 Crítico/Critical.
- Only findings with status `open` or `acknowledged` count toward the score.
- Plugin `trust` is never read from `plugin.yaml`; it is assigned by the catalog (`official` / `verified` / `community`).
- Credentials are passed to plugins only via stdin JSON — never argv, never environment variables.
- The repo path contains a space (`D:\SOC AudiDashboard`); every subprocess call uses argument lists, never shell strings.
- Plugins in `plugins/` use only the Python standard library plus `audidash_sdk`.

## Review Focus

1. A plugin that prints megabytes or never-ending output → runner caps stdout at 10 MiB and returns status `error` with reason `output_too_large`, never OOMs. (Task 6 test `test_output_cap`.)
2. A plugin that spawns children and hangs → on timeout the whole process tree is killed and status is `timeout`. (Task 6 test `test_timeout_kills_tree`.)
3. Secrets leaking through `title` or `recommendation`, not only `evidence` → sanitizer applies to every free-text field. (Task 3 test `test_sanitizes_all_text_fields`.)
4. Manifest `entrypoint` or hashed file pointing outside the plugin dir (`../`, absolute path, symlink) → rejected at load. (Task 4 test `test_rejects_path_escape`.)
5. Plugin output that is not valid UTF-8 or not valid JSON → status `error` with reason `invalid_output`, raw output not echoed into findings. (Task 6 test `test_invalid_output`.)

---

### Task 1: Repository scaffold and community files

**Files:**
- Create: `pyproject.toml` (workspace root: `[tool.uv.workspace] members = ["packages/*"]`, ruff, mypy strict, pytest config)
- Create: `packages/audidash-core/pyproject.toml`, `packages/audidash-core/src/audidash_core/__init__.py` (`__version__ = "0.1.0"`)
- Create: `LICENSE` (Apache-2.0 full text), `README.md`, `README.en.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md` (Contributor Covenant 2.1), `CHANGELOG.md`, `.gitignore`, `.editorconfig`
- Test: `packages/audidash-core/tests/test_version.py`

**Interfaces:**
- Produces: importable `audidash_core` with `__version__: str`.

- [ ] **Step 1: Write failing test** `test_version`: `assert audidash_core.__version__ == "0.1.0"`.
- [ ] **Step 2: Run** `uv run pytest packages/audidash-core -q` → FAIL (module missing).
- [ ] **Step 3: Create the workspace and package files.** Dependencies of core: `pydantic>=2.9`, `pyyaml>=6`, `cryptography>=43`. Dev group: `pytest`, `pytest-cov`, `ruff`, `mypy`, `types-PyYAML`, `bandit`, `pip-audit`. README sections (PT and EN mirror): banner "Projeto estudantil / Student project", what it is, architecture diagram (copy from spec §5), ethical-use notice, ISO/LGPD alignment disclaimer, quickstart (CLI for now), how to write a plugin (link to `docs/plugins.md`, created in Task 7), roadmap (Plans 2–4), license. SECURITY.md: report via GitHub private vulnerability reporting, no public issues for vulns.
- [ ] **Step 4: Run** `uv sync && uv run pytest packages/audidash-core -q` → PASS; `uv run ruff check . && uv run mypy packages` → clean.
- [ ] **Step 5: Commit** `chore: scaffold uv workspace, license and community docs`

---

### Task 2: Finding schema and fingerprint

**Files:**
- Create: `packages/audidash-core/src/audidash_core/findings.py`
- Test: `packages/audidash-core/tests/test_findings.py`

**Interfaces:**
- Produces:
  - `class Severity(StrEnum)`: `info, low, medium, high, critical`
  - `class Category(StrEnum)`: `misconfiguration, vulnerability, suspicious, compliance`
  - `class FindingStatus(StrEnum)`: `open, acknowledged, resolved, auto_resolved, false_positive, accepted_risk`
  - `class Finding(BaseModel, extra="forbid", frozen=True)`: `id: str` (pattern `^[A-Z0-9][A-Z0-9_-]{1,63}$`), `title: str` (1–200), `severity: Severity`, `category: Category`, `target: str` (1–255), `evidence: str = ""`, `recommendation: str = ""`, `references: list[str] = []`, `item_key: str | None = None`
  - `class PluginOutput(BaseModel, extra="forbid")`: `findings: list[Finding]`, `warnings: list[str] = []`
  - `def fingerprint(plugin_id: str, finding_id: str, asset_id: str, item_key: str | None = None) -> str` — sha256 hex of `"\x1f".join([...])` with `item_key or ""`.

- [ ] **Step 1: Write failing tests**
  - `test_parses_valid_finding` — dict from spec §6 example parses; `severity is Severity.high`.
  - `test_rejects_unknown_severity` — `"severity": "urgent"` raises `ValidationError`.
  - `test_rejects_extra_fields` — extra key `"trust"` raises `ValidationError`.
  - `test_fingerprint_stable_and_distinct` — same inputs equal; `item_key="alice"` vs `"bob"` differ; length 64.
- [ ] **Step 2: Run** `uv run pytest packages/audidash-core/tests/test_findings.py -q` → FAIL.
- [ ] **Step 3: Implement** in `findings.py`.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(core): add finding schema and fingerprint`

---

### Task 3: Sanitizer

**Files:**
- Create: `packages/audidash-core/src/audidash_core/sanitizer.py`
- Test: `packages/audidash-core/tests/test_sanitizer.py`

**Interfaces:**
- Consumes: `Finding` (Task 2).
- Produces: `MAX_EVIDENCE_CHARS = 2000`; `def redact(text: str) -> str`; `def sanitize_finding(f: Finding) -> Finding` (applies `redact` to `title`, `evidence`, `recommendation`, `target` is left intact; truncates evidence to `MAX_EVIDENCE_CHARS` appending `"…[truncated]"`).

Replacement tokens (exact): `[REDACTED:private_key]`, `[REDACTED:aws_access_key]`, `[REDACTED:aws_secret]`, `[REDACTED:password]`, `[REDACTED:jwt]`, `[REDACTED:azure_key]`, `[REDACTED:bearer]`, `[REDACTED:cpf]`, `[REDACTED:email]`, `[REDACTED:phone]`.

- [ ] **Step 1: Write failing tests** (one per pattern, parametrized `test_redacts`):
  - `"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"` → contains `[REDACTED:private_key]`, not `abc`
  - `"AKIAIOSFODNN7EXAMPLE"` → `[REDACTED:aws_access_key]`
  - `"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"` → `[REDACTED:aws_secret]`
  - `"Server=x;Password=Hunter2!;"` and `"password: hunter2"` → `[REDACTED:password]`
  - `"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig_part-1"` → `[REDACTED:jwt]`
  - `"AccountKey=abc123+/==;"` → `[REDACTED:azure_key]`
  - `"Authorization: Bearer abc.def"` → `[REDACTED:bearer]`
  - `"123.456.789-09"` and `"12345678909"` → `[REDACTED:cpf]`
  - `"joao@empresa.com.br"` → `[REDACTED:email]`
  - `"(11) 98765-4321"` and `"+55 11 987654321"` → `[REDACTED:phone]`
  - `test_does_not_redact_ip_or_port` — `"10.0.0.5:22"` unchanged.
  - `test_sanitizes_all_text_fields` — secret in `title` and `recommendation` is redacted.
  - `test_truncates_evidence` — 5000-char evidence → length ≤ 2000 + len(suffix), ends with `…[truncated]`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** with compiled regexes applied in the order listed (private key first so its body is not partially matched by others).
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(core): add client-side sanitizer for secrets and PII`

---

### Task 4: Plugin manifest and integrity

**Files:**
- Create: `packages/audidash-core/src/audidash_core/manifest.py`
- Test: `packages/audidash-core/tests/test_manifest.py`, fixtures under `packages/audidash-core/tests/fixtures/plugins/`

**Interfaces:**
- Produces:
  - `class Runtime(StrEnum)`: `python, powershell, bash`
  - `class Execution(StrEnum)`: `local, remote`
  - `class TargetType(StrEnum)`: `linux, windows, aws, azure, gcp, m365, network, web, local`
  - `class Connection(StrEnum)`: `ssh, winrm, cloud_api, network, local`
  - `class PluginManifest(BaseModel, extra="forbid")`: `id` (pattern `^[a-z0-9][a-z0-9-]{2,63}$`), `name`, `version` (SemVer regex), `author`, `license`, `description`, `runtime`, `execution`, `entrypoint: str`, `files: dict[str, str]` (relative path → sha256 hex; must include `entrypoint`), `targets: list[TargetType]` (min 1), `connection`, `permissions: list[str]` (min 1), `references: list[str] = []`, `parameters: dict[str, ParameterSpec] = {}`
  - `class ParameterSpec(BaseModel)`: `type: Literal["string","integer","boolean","list"]`, `default: object | None = None`, `description: str = ""`
  - `class ManifestError(Exception)`, `class IntegrityError(Exception)`
  - `def load_manifest(plugin_dir: Path) -> PluginManifest`
  - `def verify_integrity(plugin_dir: Path, manifest: PluginManifest) -> None` (raises `IntegrityError`)
  - `def compute_hashes(plugin_dir: Path, files: list[str]) -> dict[str, str]` (used by a `plugins hash` CLI helper)

- [ ] **Step 1: Write failing tests**
  - `test_loads_valid_manifest`
  - `test_rejects_trust_field` — `trust: official` in yaml → `ManifestError`
  - `test_rejects_unknown_runtime` — `runtime: ruby` → `ManifestError`
  - `test_rejects_path_escape` — parametrized: `entrypoint: ../evil.py`, `/etc/passwd`, `C:\\x.py`, and a symlink inside the dir pointing outside → `ManifestError`
  - `test_entrypoint_must_be_hashed` — entrypoint missing from `files` → `ManifestError`
  - `test_integrity_ok` / `test_integrity_tampered` — modify one byte of `run.py` → `IntegrityError` naming the file
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Use `yaml.safe_load`; resolve each path with `(plugin_dir / p).resolve()` and require `is_relative_to(plugin_dir.resolve())`; reject `Path(p).is_absolute()` or any drive. Hashes read in binary.
- [ ] **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(core): add plugin manifest schema and integrity checks`

---

### Task 5: Threat scoring

**Files:**
- Create: `packages/audidash-core/src/audidash_core/scoring.py`
- Test: `packages/audidash-core/tests/test_scoring.py`

**Interfaces:**
- Consumes: `Severity`, `Category`, `FindingStatus` (Task 2).
- Produces:
  - `class Criticality(StrEnum)`: `low, medium, high`
  - `class Band(StrEnum)`: `low, moderate, high, critical`
  - `@dataclass(frozen=True) class ScoredFinding`: `severity: Severity`, `category: Category`, `status: FindingStatus`
  - `def finding_weight(f: ScoredFinding) -> float`
  - `def asset_score(findings: Iterable[ScoredFinding], criticality: Criticality, k: float = 20.0) -> float` (rounded to 2 decimals)
  - `def global_score(assets: Iterable[tuple[float, Criticality]]) -> float` (criticality-weighted mean; empty → 0.0)
  - `def band(score: float) -> Band`

- [ ] **Step 1: Write failing tests**
  - `test_empty_asset_is_zero` → `0.0`
  - `test_single_critical_medium_asset` → `asset_score([critical/misconfiguration/open], medium) == 39.35`; `band(39.35) is Band.moderate`
  - `test_suspicious_multiplier` → one high suspicious on high-criticality asset: Σ = 7×1.5×1.5 = 15.75 → `54.5`
  - `test_resolved_not_counted` → resolved/false_positive/accepted_risk/auto_resolved findings → `0.0`
  - `test_saturates_below_100` → 50 critical on high asset → `<= 100.0` and `>= 99.9`; 3 critical on low asset → strictly between 0 and 100
  - `test_global_weighted` → `global_score([(80.0, high), (20.0, low)]) == 65.0`
  - `test_band_edges` → 24.99 low, 25 moderate, 50 high, 75 critical
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(core): add threat scoring model`

---

### Task 6: Isolated local runner

**Files:**
- Create: `packages/audidash-core/src/audidash_core/runner.py`, `packages/audidash-core/src/audidash_core/proc.py` (process-tree helpers)
- Test: `packages/audidash-core/tests/test_runner.py` (fake plugins built in `tmp_path` with `compute_hashes`)

**Interfaces:**
- Consumes: `load_manifest`, `verify_integrity`, `compute_hashes` (Task 4); `PluginOutput` (Task 2); `sanitize_finding` (Task 3).
- Produces:
  - `class RunInput(BaseModel, extra="forbid")`: `target: str`, `target_type: TargetType`, `parameters: dict[str, object] = {}`, `credentials: dict[str, str] = {}` (field uses `SecretStr` values; `repr` never shows them)
  - `class RunStatus(StrEnum)`: `ok, error, timeout, blocked`
  - `class RunResult(BaseModel)`: `plugin_id: str`, `plugin_version: str`, `target: str`, `status: RunStatus`, `reason: str | None`, `findings: list[Finding]`, `warnings: list[str]`, `started_at: datetime`, `finished_at: datetime`, `stderr_tail: str` (last 4 KiB, sanitized)
  - `MAX_STDOUT_BYTES = 10 * 1024 * 1024`; `DEFAULT_TIMEOUT_S = 300`
  - `def run_local(plugin_dir: Path, run_input: RunInput, timeout_s: int = DEFAULT_TIMEOUT_S) -> RunResult` — raises nothing for plugin failures; returns status.
  - `def interpreter_argv(runtime: Runtime, entrypoint: Path) -> list[str]` — python: `[sys.executable, "-I", entry]`; powershell: `["pwsh", "-NoLogo", "-NoProfile", "-NonInteractive", "-File", entry]`; bash: `["bash", "--noprofile", "--norc", entry]`.
  - `proc.kill_tree(p: subprocess.Popen) -> None`

- [ ] **Step 1: Write failing tests**
  - `test_runs_python_plugin` — plugin echoes one finding using its stdin `target` → status `ok`, finding `target` matches
  - `test_blocked_on_tamper` — edit file after hashing → status `blocked`, reason starts with `integrity`
  - `test_remote_execution_rejected` — manifest `execution: remote` → status `blocked`, reason `remote_not_supported` (Plan 4 adds it)
  - `test_env_is_clean` — parent sets `AUDIDASH_TEST_SECRET=x`; plugin dumps `os.environ` keys as a warning → key absent
  - `test_credentials_via_stdin_only` — plugin reports `sys.argv` and env; credential value absent from both, present in stdin payload
  - `test_timeout_kills_tree` — plugin spawns `sleep`-like child then sleeps; `timeout_s=2` → status `timeout`, child PID no longer alive
  - `test_output_cap` — plugin writes 11 MiB → status `error`, reason `output_too_large`
  - `test_invalid_output` — plugin prints `b"\xff\xfe"` / `not json` → status `error`, reason `invalid_output`
  - `test_findings_are_sanitized` — plugin emits evidence with `AKIAIOSFODNN7EXAMPLE` → redacted in result
  - `test_runs_from_path_with_space` — plugin dir `tmp_path / "with space"` → `ok`
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement.** Env: only `PATH`, plus `SYSTEMROOT`, `COMSPEC`, `PATHEXT` on Windows; `TEMP`/`TMP`/`HOME`/`USERPROFILE` → fresh `tempfile.TemporaryDirectory` which is also `cwd`. POSIX: `start_new_session=True`, kill with `os.killpg`; Windows: `CREATE_NEW_PROCESS_GROUP`, kill with `taskkill /F /T /PID`. Read stdout in a thread with a byte counter to enforce the cap. Use `bandit`-friendly `subprocess.Popen(argv, shell=False)`.
- [ ] **Step 4: Run** → PASS on Windows locally; CI runs on ubuntu and windows.
- [ ] **Step 5: Commit** `feat(core): add isolated local plugin runner`

---

### Task 7: Plugin SDK and plugin authoring guide

**Files:**
- Create: `packages/audidash-sdk/pyproject.toml` (no third-party deps), `packages/audidash-sdk/src/audidash_sdk/__init__.py`
- Create: `docs/plugins.md` (PT) and `docs/plugins.en.md` — manifest reference, output schema, examples in Python/PowerShell/Bash, trust tiers, how to compute hashes (`audidash plugins hash`)
- Test: `packages/audidash-sdk/tests/test_sdk.py`

**Interfaces:**
- Produces (stdlib-only, no import of `audidash_core` so plugins stay dependency-free):
  - `def read_input() -> dict[str, Any]` (reads stdin JSON)
  - `class Reporter`: `add(id: str, title: str, severity: str, category: str, evidence: str = "", recommendation: str = "", references: list[str] | None = None, item_key: str | None = None) -> None`; `warn(msg: str) -> None`; `emit() -> None` (prints `{"findings": [...], "warnings": [...]}` to stdout) — `target` filled from input.
  - `def run(main: Callable[[dict[str, Any], Reporter], None]) -> None` — reads input, calls `main`, emits; uncaught exception → exits 1 with message on stderr.
- Plugins import the SDK by having the runner add its path: **runner change** — `run_local` sets `PYTHONPATH` to the SDK's `src` dir for `runtime: python` (add test `test_sdk_available_to_python_plugins` to `test_runner.py`). Because `-I` ignores `PYTHONPATH`, the runner instead uses `[sys.executable, "-I", "-c", BOOTSTRAP, entry]` where `BOOTSTRAP` inserts the SDK path into `sys.path` and `runpy.run_path(entry, run_name="__main__")`. Update `interpreter_argv` accordingly.

- [ ] **Step 1: Write failing tests** — `test_reporter_emits_schema_valid_json` (output validates against `PluginOutput`), `test_run_handles_exception` (exit code 1), plus runner test above.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** SDK + runner bootstrap + docs. **Step 4: Run** all core and sdk tests → PASS.
- [ ] **Step 5: Commit** `feat(sdk): add stdlib-only plugin SDK and authoring guide`

---

### Task 8: Signed plugin catalog

**Files:**
- Create: `packages/audidash-core/src/audidash_core/catalog.py`
- Create: `tools/sign_catalog.py` (maintainer script, reads private key path from argv, never from repo)
- Create: `plugins/catalog.pub` (project public key, generated once by maintainer; for tests a temp key is used)
- Test: `packages/audidash-core/tests/test_catalog.py`

**Interfaces:**
- Consumes: `load_manifest`, `verify_integrity`, `PluginManifest` (Task 4).
- Produces:
  - `class Trust(StrEnum)`: `official, verified, community`
  - `@dataclass(frozen=True) class CatalogEntry`: `manifest: PluginManifest`, `path: Path`, `trust: Trust`
  - `def build_index(plugins_dir: Path) -> bytes` — canonical JSON (`sort_keys=True, separators=(",", ":")`) of `{plugin_id: {"version": ..., "files": {...}}}`
  - `def sign_index(index: bytes, private_key: Ed25519PrivateKey) -> bytes`
  - `def verify_index(index: bytes, signature: bytes, public_key: Ed25519PublicKey) -> bool`
  - `def load_catalog(plugins_dir: Path, public_key: Ed25519PublicKey | None, verified_hashes: set[str] = frozenset()) -> list[CatalogEntry]` — `official` if `index.json` + `index.sig` verify and the plugin's hashes match the index; else `verified` if sha256 of its entrypoint is in `verified_hashes` (populated by the server in Plan 2/3); else `community`. Plugins failing `load_manifest` are skipped with a logged warning, not fatal.

- [ ] **Step 1: Write failing tests** — `test_official_when_signed`, `test_community_when_signature_invalid`, `test_community_when_plugin_changed_after_signing`, `test_verified_by_hash_allowlist`, `test_bad_manifest_skipped`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(core): add Ed25519-signed plugin catalog with trust tiers`

---

### Task 9: First `local` plugins (network, TLS, HTTP headers)

**Files:**
- Create: `plugins/network-port-scan/{plugin.yaml,run.py,README.md}`
- Create: `plugins/tls-certificate-check/{plugin.yaml,run.py,README.md}`
- Create: `plugins/http-security-headers/{plugin.yaml,run.py,README.md}`
- Test: `plugins/tests/test_network_port_scan.py`, `plugins/tests/test_tls_certificate_check.py`, `plugins/tests/test_http_security_headers.py`, `plugins/tests/conftest.py` (local fixture servers: plain TCP listener, `http.server` with configurable headers, TLS server with cert generated via `cryptography`)

**Interfaces:**
- Consumes: SDK `run`, `Reporter` (Task 7); tests call `run_local` (Task 6).
- Produces finding IDs (exact):
  - `network-port-scan` (targets `network`; params `ports: list` default top-100 TCP list embedded in `run.py`, `timeout_ms: integer` default 500): `NET-OPEN-PORT` (info, `item_key` = port) for any open port; `NET-RISKY-PORT` (high) for open 21, 23, 135, 139, 445, 3389, 5900, 6379, 9200, 27017, 11211 (`item_key` = port). References `CIS Control 4.4`, `ISO27002:2022 8.20`.
  - `tls-certificate-check` (targets `web`, `network`; params `port` default 443): `TLS-EXPIRED` (critical), `TLS-EXPIRING` (high if ≤ 14 days, medium if ≤ 30), `TLS-SELF-SIGNED` (medium), `TLS-HOSTNAME-MISMATCH` (high), `TLS-WEAK-PROTOCOL` (high, if TLS 1.0/1.1 handshake succeeds). References `ISO27002:2022 8.24`.
  - `http-security-headers` (targets `web`; params `url`): `HTTP-NO-HSTS` (medium, only for https), `HTTP-NO-CSP` (medium), `HTTP-NO-XCTO` (low), `HTTP-NO-FRAME-PROTECTION` (low; satisfied by `X-Frame-Options` or CSP `frame-ancestors`), `HTTP-NO-REFERRER-POLICY` (low), `HTTP-SERVER-BANNER` (info, `Server` header with a version number). References `OWASP ASVS 14.4`, `ISO27002:2022 8.26`.

- [ ] **Step 1: Write failing tests** — per plugin, against the local fixtures: open port 6379 listener → `NET-RISKY-PORT`; cert expiring in 10 days → `TLS-EXPIRING` high; expired cert → `TLS-EXPIRED`; self-signed → `TLS-SELF-SIGNED`; server with no headers → the five missing-header findings; server with all headers → zero findings; unreachable target → status `ok`, zero findings, one warning (not a crash).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement** plugins (stdlib `socket`, `ssl`, `urllib`/`http.client`; scan with a bounded `ThreadPoolExecutor(max_workers=50)`), write manifests, fill hashes with `audidash plugins hash` (Task 10) or `compute_hashes`. **Step 4: Run** → PASS.
- [ ] **Step 5: Commit** `feat(plugins): add network, TLS and HTTP header audit plugins`

---

### Task 10: `audidash` CLI

**Files:**
- Create: `packages/audidash-core/src/audidash_core/cli.py` (argparse; entry point `audidash = "audidash_core.cli:main"`)
- Test: `packages/audidash-core/tests/test_cli.py`

**Interfaces:**
- Consumes: `load_catalog` (Task 8), `run_local` (Task 6), `asset_score`, `band` (Task 5), `compute_hashes` (Task 4).
- Produces commands (`main(argv: list[str] | None = None) -> int`):
  - `audidash plugins list [--plugins-dir DIR]` — table: id, version, trust, runtime, targets
  - `audidash plugins show ID` — manifest summary, permissions, then full source of every file
  - `audidash plugins hash DIR` — prints the `files:` YAML block
  - `audidash plugins validate [DIR]` — loads every manifest + integrity; exit 1 on any failure
  - `audidash run ID --target T --target-type TYPE [--param k=v ...] [--criticality medium] [--json] [--yes]` — `community` plugins print the source and require `--yes` or an interactive `y`; prints findings table sorted by severity and the asset score with band; `--json` prints `RunResult` JSON. Ethical-use notice printed once per run to stderr.
- Default plugins dir: `./plugins` if present.

- [ ] **Step 1: Write failing tests** — `test_list_shows_plugins`, `test_show_prints_source`, `test_validate_fails_on_tamper`, `test_run_community_requires_confirmation` (no `--yes`, stdin `n` → exit 2, nothing executed), `test_run_json_output_parses_as_RunResult`.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** → PASS; manual: `uv run audidash run http-security-headers --target example.com --target-type web --param url=https://example.com --yes`.
- [ ] **Step 5: Commit** `feat(cli): add audidash CLI for listing, inspecting and running plugins`

---

### Task 11: CI, supply-chain checks and project management templates

**Files:**
- Create: `.github/workflows/ci.yml` — matrix `ubuntu-latest`, `windows-latest`; steps: `astral-sh/setup-uv`, `uv sync --locked`, `ruff check`, `ruff format --check`, `mypy packages`, `pytest --cov --cov-fail-under=85`, `bandit -r packages plugins -x '*/tests/*'`, `pip-audit`, `audidash plugins validate plugins`
- Create: `.github/workflows/codeql.yml`, `.github/workflows/gitleaks.yml`, `.github/dependabot.yml` (pip/uv + github-actions, weekly)
- Create: `.github/ISSUE_TEMPLATE/{bug_report.yml,feature_request.yml,plugin_request.yml}`, `.github/pull_request_template.md` (checklist: tests, docs, no secrets, plugin hashes updated), `.github/CODEOWNERS`
- Create: `docs/compliance/iso27001-mapping.md`, `docs/compliance/lgpd.md` — table of controls implemented so far (sanitizer → LGPD art. 6º III/46; integrity/signing → ISO 27002 8.7/8.19; audit trail placeholder → Plan 2) marked `implemented` / `planned`
- Modify: `CHANGELOG.md` — `## [0.1.0-alpha.1]` entry

- [ ] **Step 1: Run the full local gate** `uv run ruff check . && uv run ruff format --check . && uv run mypy packages && uv run pytest --cov --cov-fail-under=85 && uv run bandit -q -r packages plugins -x "*/tests/*" && uv run pip-audit` → all pass (fix anything that fails before continuing).
- [ ] **Step 2: Create workflow and template files.**
- [ ] **Step 3: Validate YAML** with `uv run python -c "import yaml,glob;[yaml.safe_load(open(f)) for f in glob.glob('.github/**/*.yml',recursive=True)]"` → no error.
- [ ] **Step 4: Commit** `ci: add CI matrix, security scanning and contribution templates`
- [ ] **Step 5: Tag** `git tag v0.1.0-alpha.1` (push only when the user creates the GitHub repo and asks).
