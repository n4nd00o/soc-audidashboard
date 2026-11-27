# Plan 3 — Desktop App (PySide6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A cross-platform desktop app for analysts that browses the plugin catalog (with source review), lists the server's assets, runs plugins locally in the existing isolated runner, shows results with the threat score, and enrolls/logs in/uploads over the same mTLS flow as the CLI — shipped as unsigned PyInstaller executables attached to GitHub releases.

**Architecture:** New workspace package `audidash-desktop` (PySide6, Qt Widgets). All server/security logic lives in a new non-printing façade `audidash_core.client.service`, which the CLI (`cli_server.py`) is refactored onto first, so CLI and desktop share one implementation. UI work runs off the GUI thread (`QThread` workers). Plugins run through `audidash_core.runner.run_local`, using a system Python 3.12+ when the app is frozen.

**Tech Stack:** PySide6 6.x, pytest-qt (offscreen platform), PyInstaller, existing `audidash_core` (runner, catalog, scoring, client).

**Spec:** `docs/superpowers/specs/2026-11-25-soc-audidashboard-design.md` (§5, §6, §8, §11, §12, §14, §15).

## Global Constraints

- Python `>=3.12`; new import name `audidash_desktop`; GUI script `audidash-desktop`.
- UI text in PT-BR; code/commits/docstrings in English.
- Visual: same tokens as `packages/audidash-server/src/audidash_server/static/css/app.css` (background/surface/text/accent, severity `info/low/medium/high/critical`, bands `Baixo/Moderado/Alto/Crítico`); dark default + light toggle persisted in `QSettings`; left navigation: Catálogo, Alvos, Executar, Resultados, Conta.
- The desktop app never re-implements security logic: enrollment (CA fingerprint check before the token is sent; single re-serialized CA cert), login, token storage, upload, verified-allowlist sync and catalog trust all go through `audidash_core.client.service` / `audidash_core.catalog` / `audidash_core.runner`.
- Secrets (password, TOTP code, enrollment token) only in `QLineEdit` (password echo mode for password/token), cleared right after use, never logged, never stored in `QSettings`.
- Community plugins require reviewing the full source (escaped, Trojan-Source warning as in the CLI) and explicit confirmation before each run; official/verified show the permissions summary before running (spec §6). Runs pass the reviewed manifest pin to `run_local`.
- GUI thread never blocks: network calls and plugin runs execute in `QThread` workers; Cancel kills the plugin process tree.
- Frozen app: Python plugins run with a system Python ≥3.12 (PATH lookup or the path set in settings); if none, show a clear PT-BR message and disable running Python plugins (everything else works). Unfrozen (dev) runs keep using `sys.executable`. Never use the frozen executable itself as the plugin interpreter.
- Tests run headless with `QT_QPA_PLATFORM=offscreen`; coverage gate stays ≥85% overall.

## Review Focus

1. Secret material reaching logs, `QSettings`, history files, crash dialogs or exception text shown in the UI. (Task 7 `test_no_secret_persisted_or_logged`.)
2. Running a community plugin without source-review confirmation, or after files changed since review. (Task 5 `test_community_requires_review_and_pin`.)
3. GUI thread blocked by network/plugin work. (Tasks 4/5 assert calls happen in a worker.)
4. Frozen app using its own executable as plugin interpreter (breaks isolation). (Task 8 `test_frozen_uses_system_python_only`.)
5. Plugin-controlled text rendered as rich text/HTML (Qt auto-detects rich text in labels). (Tasks 3/6: `Qt.TextFormat.PlainText` wherever plugin data is shown.)

---

### Task 1: Non-printing client service façade (CLI refactor)

**Files:** create `packages/audidash-core/src/audidash_core/client/service.py`; modify `cli_server.py` (and `demo.py` if needed) to use it; tests `packages/audidash-core/tests/test_service.py`.

**Interfaces (produces):**
- `class ServiceError(Exception)`; `NotEnrolledError`, `CaFingerprintMismatch`; re-export `SessionExpiredError`.
- `@dataclass(frozen=True) EnrollRequest(dashboard_url: str, api_url: str, device_name: str, ca_fingerprint: str | None)`.
- `fetch_server_ca(dashboard_url, *, transport=None) -> tuple[str, str]` (canonical PEM, SHA-256) — no secrets involved.
- `enroll(req, token, *, ca_pem: str | None, directory, transport=None, force=False) -> EnrollResult` — `ca_pem` must already be verified against `req.ca_fingerprint` by the caller, or `None` for the explicit insecure mode; CSR/enroll/check/save exactly as today.
- `login(username, password, totp, *, directory, transport=None) -> TokenGrant`.
- `list_assets(...) -> list[AssetInfo]`, `ensure_assets(...)`, `sync_verified(...) -> frozenset[str]`, `cached_verified(directory) -> tuple[frozenset[str], bool]`.
- `upload(result: RunResult, asset: str, *, directory, transport=None) -> UploadSummary` (fresh `run_id`).
- `session_status(directory) -> SessionStatus(enrolled, device_id, dashboard_url, token_valid_until)`.
- No `print`, `sys.exit`, `input` or `getpass` anywhere in `service.py`.

- [ ] Step 1: tests per function against the in-process server (reuse `test_client.py` helpers), incl. fingerprint mismatch raising before any POST /enroll, plus a static test that `service.py` contains none of `print(`, `getpass`, `input(`, `sys.exit`.
- [ ] Step 2: RED. Step 3: implement; make `cli_server.py` handlers thin wrappers (prompts, printing, exit codes only). Step 4: full core suite GREEN, CLI behaviour unchanged.
- [ ] Step 5: commit `refactor(core): extract non-printing client service used by the CLI`

### Task 2: Desktop package, theme and main window

**Files:** `packages/audidash-desktop/pyproject.toml` (deps `PySide6>=6.8`, `audidash-core`; dev `pytest-qt`), `src/audidash_desktop/{__init__.py,app.py,theme.py,main_window.py,widgets/nav.py}`, `resources/theme_dark.qss`, `resources/theme_light.qss`; tests `tests/{conftest.py,test_main_window.py,test_theme.py}`.

**Interfaces:** `main(argv=None) -> int` (gui-script `audidash-desktop`); `MainWindow(QMainWindow)` with `pages: dict[str, QWidget]` keyed `catalog|targets|run|results|account`; `apply_theme(app, "dark"|"light")`; `ThemeTokens` dataclass with values copied from the dashboard CSS (cite the source in a comment).

- [ ] Tests: window opens offscreen with 5 nav entries in order with PT-BR labels; theme toggle persists in `QSettings` (temp org/app name in tests); severity colors equal dashboard tokens.
- [ ] Commit `feat(desktop): add PySide6 app shell with dashboard-matching theme`

### Task 3: Catálogo page (list, details, source viewer)

**Files:** `pages/catalog.py`, `widgets/code_view.py` (read-only `QPlainTextEdit` + simple `QSyntaxHighlighter` for Python/PowerShell/Bash), tests `test_catalog_page.py`.

**Behaviour:** `load_catalog(plugins_dir, packaged key, verified hashes)` (plugins dir: bundled `plugins/` in the frozen app, repo `plugins/` in dev; changeable in settings); table: id, versão, confiança (badge), runtime, alvos; details: summary incl. permissions/parameters as plain text; "Código" tab shows every manifest-listed file escaped with `cli_format.clean` plus a visible Trojan-Source warning when bidi/invisible characters exist.

- [ ] Tests incl. Review Focus 5 (title with `<b>` shown literally) and the bidi warning.
- [ ] Commit `feat(desktop): add plugin catalog with source review`

### Task 4: Conta page (enroll wizard, login, status, sync)

**Files:** `pages/account.py`, `dialogs/enroll.py`, `dialogs/login.py`, `workers.py` (`ServiceWorker(QObject)` running a callable in a `QThread`, signals `finished(object)` / `failed(str)`), tests `test_account_page.py`.

**Behaviour:** status panel (enrolled, device, dashboard URL, session valid until). Enroll wizard: step 1 URLs + device name + CA fingerprint → `fetch_server_ca` in a worker → fingerprint comparison (mismatch: stop with "possível interceptação"); empty fingerprint → explicit "primeiro contato inseguro" checkbox + dialog showing the fetched fingerprint requiring confirmation; step 2 token (password field) → `enroll`. Login dialog: username, password, TOTP → `login` in a worker; fields cleared afterwards. "Sincronizar plugins verificados" → `sync_verified`.

- [ ] Tests: `enroll` never called before fingerprint match / explicit confirmation; secrets cleared; error messages plain text without exception internals.
- [ ] Commit `feat(desktop): add enrollment wizard, login and session status`

### Task 5: Alvos and Executar pages

**Files:** `pages/targets.py`, `pages/run.py`, `widgets/param_form.py` (string→QLineEdit, integer→QSpinBox, boolean→QCheckBox, list→comma-separated QLineEdit), `dialogs/review.py`, `runner_bridge.py` (`RunWorker` calling `run_local(..., expected_manifest=…, expected_manifest_sha256=…)`), tests `test_run_page.py`; core: cancellation support in the runner if missing (`cancel_event: threading.Event | None` checked by the run loop; on set, kill the process group and return status `error`, reason `cancelled`) with core tests.

**Behaviour:** Alvos lists server assets (worker; offline → message and local-only mode with a free-text target). Executar: plugin (+ trust badge), asset (or free target when not enrolled), parameters form, "Enviar ao servidor" (enabled only when logged in). Run → permissions summary always; community → review dialog with full source → confirm; run in `RunWorker` with progress and Cancel. On completion → Resultados; optional `upload` in a worker; CLI-like summary line.

- [ ] Tests incl. Review Focus 2 and 3; Cancel stops a sleeping plugin within 5 s.
- [ ] Commit `feat(desktop): add targets and run pages with isolated execution`

### Task 6: Resultados page

**Files:** `pages/results.py`, `history.py` (last 50 sanitized `RunResult`s as JSON under the client config dir `history/`; never credentials; user can clear), tests `test_results_page.py`.

**Behaviour:** runs list (plugin, alvo, status, data, enviado?); detail: findings sorted by severity (token colors), evidence/recommendation as plain text, asset score + band via `audidash_core.scoring`; "Exportar JSON"; "Reenviar" for not-yet-uploaded runs when logged in.

- [ ] Tests: score parity; plain-text rendering; history cap 50; clear removes files.
- [ ] Commit `feat(desktop): add results history with scoring`

### Task 7: Settings, logging and secret hygiene

**Files:** `pages/settings.py` (plugins dir, Python interpreter path with "Detectar" + version check ≥3.12, theme), `logging_setup.py` (rotating file log in the config dir, INFO, filter redacting via `audidash_core.sanitizer.redact`), tests `test_settings.py`, `test_secrets.py`.

- [ ] Tests: Review Focus 1 — drive login/enroll with known secret values; assert they appear nowhere in QSettings storage, log file, history or widget text afterwards.
- [ ] Commit `feat(desktop): add settings, interpreter detection and redacting logs`

### Task 8: Frozen interpreter policy, PyInstaller packaging, CI release

**Files:** `packages/audidash-core/src/audidash_core/interpreter.py` (`python_for_plugins(configured: Path | None) -> Path | None`: frozen → configured path or system lookup (`python3`, `python`, Windows `py -3.12`), validated `>=3.12` via `--version` with timeout, never `sys.executable`; not frozen → `sys.executable`); runner uses it; `packaging/audidash-desktop.spec` (bundles `plugins/`, `audidash_sdk` source, `keys/catalog.pub`, QSS); `.github/workflows/release.yml` (on tag `v*`: build per OS on windows/ubuntu/macos, smoke-run `--version`, attach binaries + `SHA256SUMS` to the release; `permissions: contents: write` only here); README "Baixar o app" with the unsigned-binary warning.

- [ ] Tests: Review Focus 4 (`sys.frozen` monkeypatched → never `sys.executable`; none found → `None` and the run page shows the message); spec file parses; workflow YAML valid.
- [ ] Commit `feat(desktop): package with PyInstaller and publish release binaries`

### Task 9: Docs, compliance, changelog

README/README.en (desktop section, screenshot placeholders), `docs/desktop.md` (PT/EN guide: enroll, login, run, review, results, Python requirement), SECURITY.md (desktop notes: local history contents, log redaction, unsigned binaries, interpreter selection), CHANGELOG `[0.3.0-alpha.1]`, version bump `0.3.0a1` across packages. Commit `docs: document the desktop app for 0.3.0-alpha.1`.
