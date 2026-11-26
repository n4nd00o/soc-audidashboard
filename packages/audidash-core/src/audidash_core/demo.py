"""`audidash demo`: audit the bundled lab targets (compose stack) and upload the results.

Orchestration only: every run goes through the normal `audidash run --upload` path, so the
plugin, trust, sandbox and upload rules are exactly the ones a user gets by hand. All three lab
assets share the address 127.0.0.1, so they are addressed by NAME (`--asset`).
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass

from audidash_core import cli_server
from audidash_core.cli_format import clean_line
from audidash_core.cli_server import AssetSpec, ServerCliError
from audidash_core.manifest import TargetType
from audidash_core.scoring import Criticality

LAB_ADDRESS = "127.0.0.1"
_TAGS = ("demo", "lab")


@dataclass(frozen=True)
class LabRun:
    plugin_id: str
    asset: AssetSpec
    params: tuple[str, ...]


LAB_RUNS = (
    LabRun(
        "http-security-headers",
        AssetSpec("lab-web", LAB_ADDRESS, TargetType.web, Criticality.medium, _TAGS),
        ("url=http://127.0.0.1:18080/",),
    ),
    LabRun(
        "tls-certificate-check",
        AssetSpec("lab-tls", LAB_ADDRESS, TargetType.web, Criticality.high, _TAGS),
        ("port=18443",),
    ),
    LabRun(
        "network-port-scan",
        AssetSpec("lab-redis", LAB_ADDRESS, TargetType.network, Criticality.high, _TAGS),
        ("ports=16379,18080,18443",),
    ),
)

RunCli = Callable[[list[str]], int]


def _say(message: str, *, stderr: bool = False) -> None:
    print(clean_line(message), file=sys.stderr if stderr else sys.stdout)


def _invoke(run_cli: RunCli, argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = run_cli(argv)
    return code, out.getvalue(), err.getvalue()


def _finding_count(stdout: str) -> int | None:
    try:
        result = json.loads(stdout.strip().splitlines()[-1])
        return len(result["findings"])
    except (IndexError, ValueError, KeyError, TypeError):
        return None


def _argv(item: LabRun, plugins_args: list[str], *, assume_yes: bool) -> list[str]:
    argv = [
        "run",
        item.plugin_id,
        *plugins_args,
        "--target",
        item.asset.address,
        "--target-type",
        item.asset.asset_type.value,
        "--json",
        "--upload",
        "--asset",
        item.asset.name,
    ]
    for param in item.params:
        argv += ["--param", param]
    if assume_yes:
        argv.append("--yes")
    return argv


def run_demo(*, plugins_args: list[str], community: frozenset[str], run_cli: RunCli) -> int:
    """Create the lab assets and run + upload the three lab audits; 0 only if all succeeded.

    `community` lists the demo plugin ids that have no catalog signature: they get an explicit
    `--yes`, which is justified only because they come from the project's own bundled directory.
    """
    created = cli_server.ensure_assets([item.asset for item in LAB_RUNS])
    for name, is_new in created.items():
        _say(f"asset {name}: {'created' if is_new else 'already present'}")
    if community:
        _say(
            "NOTICE: "
            + ", ".join(sorted(community))
            + " are community-trust here (no catalog signature). Running them without a prompt "
            "because they are this project's own bundled lab plugins; never do this for plugins "
            "you have not read.",
            stderr=True,
        )
    failures = 0
    for item in LAB_RUNS:
        argv = _argv(item, plugins_args, assume_yes=item.plugin_id in community)
        code, stdout, stderr = _invoke(run_cli, argv)
        lines = stderr.splitlines()
        uploaded = next((ln for ln in lines if ln.startswith("Uploaded:")), None)
        label = f"{item.plugin_id} on {item.asset.name}"
        if code == 0 and uploaded:
            count = _finding_count(stdout)
            found = f"{count} finding(s)" if count is not None else "done"
            _say(f"{label}: {found}. {uploaded}")
            continue
        failures += 1
        _say(f"error: {label} failed (exit {code})", stderr=True)
        for line in lines:
            if line.startswith(("error:", "not uploaded")):
                _say(f"  {line}", stderr=True)
    if failures:
        raise ServerCliError(f"{failures} of {len(LAB_RUNS)} demo runs failed")
    _say(f"Demo complete. Open the dashboard: {cli_server.dashboard_url()}")
    return 0
