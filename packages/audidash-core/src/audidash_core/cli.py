"""``audidash`` command line: list, inspect, hash, validate and run plugins."""

import argparse
import sys
from importlib import resources
from pathlib import Path
from typing import TextIO

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from audidash_core import cli_server
from audidash_core.catalog import CatalogEntry, Trust, load_catalog, load_public_key
from audidash_core.cli_format import (
    TROJAN_SOURCE_WARNING,
    clean,
    clean_line,
    findings_table,
    has_invisible_chars,
    read_sources,
    render_source,
    summary,
    table,
)
from audidash_core.findings import FindingStatus
from audidash_core.manifest import (
    IntegrityError,
    ManifestError,
    ParameterSpec,
    PluginManifest,
    TargetType,
    compute_hashes,
    load_manifest,
    matches_hashes,
    verify_integrity,
)
from audidash_core.runner import RunInput, RunResult, RunStatus, run_local
from audidash_core.scoring import Criticality, ScoredFinding, asset_score, band

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2

DEFAULT_PLUGINS_DIR = "plugins"
PACKAGED_KEY = ("keys", "catalog.pub")
ETHICAL_NOTICE = (
    "NOTICE: use audidash only on infrastructure you are authorized to audit. "
    "Unauthorized scanning may be illegal."
)

_TRUE = {"true", "1", "yes"}
_FALSE = {"false", "0", "no"}
_HASH_SKIP_NAMES = {"plugin.yaml", "README.md"}
_HASH_SKIP_DIRS = {"tests", "__pycache__"}


class UsageError(Exception):
    """Invalid command-line input (exit code 2)."""


def _err(message: str) -> None:
    """Print one sanitized line to stderr (messages may embed plugin-controlled text)."""
    print(clean_line(message), file=sys.stderr)


def _out(message: str) -> None:
    """Print one sanitized line to stdout."""
    print(clean_line(message))


# ---------------------------------------------------------------- catalog helpers


def _plugins_dir(args: argparse.Namespace) -> Path:
    return Path(args.plugins_dir) if args.plugins_dir else Path(DEFAULT_PLUGINS_DIR)


def _packaged_key() -> Ed25519PublicKey | None:
    """The maintainer's catalog key shipped inside the package, if any.

    The trust root never comes from the (untrusted) plugins directory.
    """
    resource = resources.files("audidash_core").joinpath(*PACKAGED_KEY)
    if not resource.is_file():
        return None
    try:
        with resources.as_file(resource) as path:
            return load_public_key(path)
    except (ValueError, OSError) as exc:
        _err(f"warning: ignoring malformed packaged public key: {exc}")
        return None


def _load_key(args: argparse.Namespace) -> Ed25519PublicKey | None:
    """Explicit --public-key override, else the packaged key; None means all community."""
    if not args.public_key:
        return _packaged_key()
    path = Path(args.public_key)
    _err(f"notice: using custom trust root {path}")
    if not path.exists():
        _err(f"warning: public key {path} not found; treating all plugins as community")
        return None
    try:
        return load_public_key(path)
    except (ValueError, OSError) as exc:
        _err(f"warning: ignoring malformed public key {path}: {exc}")
        return None


def _catalog(args: argparse.Namespace) -> list[CatalogEntry]:
    plugins_dir = _plugins_dir(args)
    return load_catalog(plugins_dir, _load_key(args))


def _find(args: argparse.Namespace, plugin_id: str) -> CatalogEntry:
    matches = [e for e in _catalog(args) if e.manifest.id == plugin_id]
    if len(matches) > 1:
        dirs = ", ".join(str(e.path) for e in matches)
        raise UsageError(f"ambiguous plugin id {plugin_id!r}: found in {dirs}")
    if not matches:
        raise UsageError(f"unknown plugin {plugin_id!r} in {_plugins_dir(args)}")
    return matches[0]


# ---------------------------------------------------------------- parameters


def _parse_bool(value: str) -> bool:
    lowered = value.lower()
    if lowered in _TRUE:
        return True
    if lowered in _FALSE:
        return False
    raise ValueError("expected true/false/1/0/yes/no")


def _parse_list(value: str) -> list[object]:
    items = [item.strip() for item in value.split(",") if item.strip()]
    if items and all(item.isascii() and item.isdigit() for item in items):
        return [int(item) for item in items]
    return list(items)


def _convert(spec: ParameterSpec, value: str) -> object:
    if spec.type == "integer":
        return int(value)
    if spec.type == "boolean":
        return _parse_bool(value)
    if spec.type == "list":
        return _parse_list(value)
    return value


def _parse_params(manifest: PluginManifest, raw: list[str]) -> dict[str, object]:
    params: dict[str, object] = {}
    for item in raw:
        name, sep, value = item.partition("=")
        if not sep:
            raise UsageError(f"invalid --param {item!r}: expected k=v")
        spec = manifest.parameters.get(name)
        if spec is None:
            valid = ", ".join(sorted(manifest.parameters)) or "(none)"
            raise UsageError(f"unknown parameter {name!r}; valid parameters: {valid}")
        try:
            params[name] = _convert(spec, value)
        except ValueError as exc:
            raise UsageError(f"invalid value for {name!r} ({spec.type}): {exc}") from exc
    return params


# ---------------------------------------------------------------- commands


def _cmd_list(args: argparse.Namespace) -> int:
    entries = _catalog(args)
    rows = [
        [
            e.manifest.id,
            e.manifest.version,
            e.trust.value,
            e.manifest.runtime.value,
            ",".join(t.value for t in e.manifest.targets),
        ]
        for e in entries
    ]
    print(table(["ID", "VERSION", "TRUST", "RUNTIME", "TARGETS"], rows))
    return EXIT_OK


def _cmd_show(args: argparse.Namespace) -> int:
    entry = _find(args, args.id)
    try:
        files = read_sources(entry)
    except OSError as exc:
        _err(f"error: cannot read source of {entry.manifest.id}: {exc}")
        return EXIT_FAILED
    print(summary(entry))
    print()
    if has_invisible_chars(files):
        print(TROJAN_SOURCE_WARNING)
    print(render_source(files))
    return EXIT_OK


def _hash_targets(plugin_dir: Path) -> list[str]:
    if (plugin_dir / "plugin.yaml").is_file():
        return list(load_manifest(plugin_dir).files)
    found: list[str] = []
    for path in plugin_dir.rglob("*"):
        relative = path.relative_to(plugin_dir)
        if path.is_symlink() or not path.is_file():
            continue
        if relative.parts[0] in _HASH_SKIP_DIRS or "__pycache__" in relative.parts:
            continue
        if len(relative.parts) == 1 and relative.name in _HASH_SKIP_NAMES:
            continue
        found.append(relative.as_posix())
    return found


def _cmd_hash(args: argparse.Namespace) -> int:
    plugin_dir = Path(args.dir)
    if not plugin_dir.is_dir():
        raise UsageError(f"{plugin_dir} is not a directory")
    try:
        hashes = compute_hashes(plugin_dir, sorted(_hash_targets(plugin_dir)))
    except (ManifestError, OSError) as exc:
        _err(f"error: {exc}")
        return EXIT_FAILED
    print(yaml.safe_dump({"files": hashes}, default_flow_style=False, sort_keys=True), end="")
    return EXIT_OK


def _validate_one(plugin_dir: Path) -> str | None:
    """Return an error message, or None when the plugin is valid."""
    try:
        verify_integrity(plugin_dir, load_manifest(plugin_dir))
    except (ManifestError, IntegrityError, OSError) as exc:
        return str(exc)
    return None


def _cmd_validate(args: argparse.Namespace) -> int:
    root = Path(args.dir) if args.dir else Path(DEFAULT_PLUGINS_DIR)
    if not root.is_dir():
        raise UsageError(f"{root} is not a directory")
    if (root / "plugin.yaml").is_file():
        candidates = [root]
    else:
        candidates = sorted(p for p in root.iterdir() if (p / "plugin.yaml").is_file())
    failures = 0
    for plugin_dir in candidates:
        problem = _validate_one(plugin_dir)
        if problem is None:
            _out(f"ok      {plugin_dir.name}")
        else:
            failures += 1
            _err(f"FAILED  {plugin_dir.name}: {problem}")
    if not candidates:
        _err(f"error: no plugins found in {root}")
        return EXIT_FAILED
    return EXIT_FAILED if failures else EXIT_OK


def _confirm(entry: CatalogEntry, files: dict[str, bytes], assume_yes: bool, info: TextIO) -> bool:
    """Trust-tier gate; True when the run may proceed.

    The manifest summary (permissions, connection, parameters) is shown for every tier;
    community plugins also show the full source of ``files`` and need confirmation.
    """
    print(summary(entry), file=info)
    print(file=info)
    if entry.trust is not Trust.community:
        _err(f"Trust: {entry.trust.value} plugin {entry.manifest.id}")
        return True
    print(f"Trust: community plugin {entry.manifest.id} (unreviewed). Source:\n", file=info)
    print(render_source(files), file=info)
    if has_invisible_chars(files):
        print(f"\n{TROJAN_SOURCE_WARNING}", file=info)
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        _err("error: confirmation needed but stdin is not interactive; pass --yes to proceed")
        return False
    info.write("\nRun this community plugin? [y/N] ")
    info.flush()
    return sys.stdin.readline().strip().lower() in {"y", "yes"}


def _report(result: RunResult, criticality: Criticality) -> None:
    _out(f"Plugin: {result.plugin_id} {result.plugin_version}  Target: {result.target}")
    _out(f"Status: {result.status.value}" + (f" ({result.reason})" if result.reason else ""))
    for warning in result.warnings:
        _out(f"Warning: {warning}")
    if result.findings:
        print()
        print(findings_table(result.findings))
    if result.stderr_tail and result.status is not RunStatus.ok:
        print(f"\nstderr:\n{clean(result.stderr_tail)}")
    if result.status is RunStatus.ok:
        scored = [
            ScoredFinding(f.severity, f.category, FindingStatus.open) for f in result.findings
        ]
        score = asset_score(scored, criticality)
        print(f"\nAsset score: {score:.1f} ({band(score).value})")


def _cmd_run(args: argparse.Namespace) -> int:
    entry = _find(args, args.id)
    manifest = entry.manifest
    target_type = TargetType(args.target_type) if args.target_type else manifest.targets[0]
    if target_type not in manifest.targets:
        allowed = ", ".join(t.value for t in manifest.targets)
        raise UsageError(f"plugin {manifest.id} supports target types: {allowed}")
    params = _parse_params(manifest, args.param)
    plan = cli_server.prepare_upload(args)  # validates --upload/--asset before anything runs
    info = sys.stderr if args.json else sys.stdout
    _err(ETHICAL_NOTICE)
    files: dict[str, bytes] = {}
    if entry.trust is Trust.community:
        try:
            files = read_sources(entry)
        except OSError as exc:
            _err(f"error: cannot read source of {manifest.id}; plugin was not run: {exc}")
            return EXIT_FAILED
        if not matches_hashes(manifest, files):
            # Only bytes matching the pinned hashes may be shown as the plugin's source.
            _err(f"error: {manifest.id} files do not match plugin.yaml; plugin was not run")
            return EXIT_FAILED
    if not _confirm(entry, files, args.yes, info):
        _err("aborted: plugin was not run")
        return EXIT_USAGE
    run_input = RunInput(
        target=plan.target if plan else args.target,
        target_type=target_type,
        parameters=params,
        credentials={},
    )
    # Pin what was reviewed: the runner blocks if plugin.yaml or any hashed file changed since.
    result = run_local(
        entry.path,
        run_input,
        expected_manifest=manifest,
        expected_manifest_sha256=entry.manifest_sha256,
    ).model_copy(update={"trust": entry.trust.value})
    if args.json:
        print(result.model_dump_json())
    else:
        _report(result, Criticality(args.criticality))
    if result.status is not RunStatus.ok:
        if plan:
            _err("not uploaded: the run did not finish ok")
        return EXIT_FAILED
    if plan and cli_server.upload_result(plan, result, json_mode=args.json):
        return EXIT_FAILED
    return EXIT_OK


# ---------------------------------------------------------------- parser


def _build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--plugins-dir", help=f"plugins directory (default ./{DEFAULT_PLUGINS_DIR})"
    )
    common.add_argument(
        "--public-key", help="override the packaged catalog public key (custom trust root)"
    )
    parser = argparse.ArgumentParser(
        prog="audidash", description="SOC AudiDashboard plugin command line (student project)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    plugins = sub.add_parser("plugins", help="list, inspect, hash and validate plugins")
    psub = plugins.add_subparsers(dest="plugins_command", required=True)
    p_list = psub.add_parser("list", parents=[common], help="list available plugins")
    p_list.set_defaults(func=_cmd_list)
    p_show = psub.add_parser("show", parents=[common], help="show a plugin and its full source")
    p_show.add_argument("id")
    p_show.set_defaults(func=_cmd_show)
    p_hash = psub.add_parser("hash", help="print the files: YAML block for a plugin directory")
    p_hash.add_argument("dir")
    p_hash.set_defaults(func=_cmd_hash)
    p_val = psub.add_parser("validate", help="check every manifest and its file hashes")
    p_val.add_argument("dir", nargs="?")
    p_val.set_defaults(func=_cmd_validate)

    run = sub.add_parser(
        "run",
        parents=[common],
        help="run a plugin locally (credentials arrive with the desktop app, not the CLI)",
    )
    run.add_argument("id")
    run.add_argument("--target", required=True)
    run.add_argument(
        "--target-type",
        choices=[t.value for t in TargetType],
        help="default: the plugin's first supported target type",
    )
    run.add_argument("--param", action="append", default=[], metavar="K=V")
    run.add_argument("--criticality", choices=[c.value for c in Criticality], default="medium")
    run.add_argument("--json", action="store_true", help="print the RunResult JSON only")
    run.add_argument("--yes", action="store_true", help="skip the community-plugin confirmation")
    cli_server.add_upload_args(run)
    run.set_defaults(func=_cmd_run)
    cli_server.register(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        return int(args.func(args))
    except UsageError as exc:
        _err(f"error: {exc}")
        return EXIT_USAGE
    except cli_server.ServerCliError as exc:
        _err(f"error: {exc}")
        return EXIT_USAGE if exc.usage else EXIT_FAILED


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
