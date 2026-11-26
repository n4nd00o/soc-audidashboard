"""End to end: the real compose stack (Caddy mTLS) driven through the real CLIs.

Needs a running Docker daemon with the stack up (`docker compose up -d --wait` in deploy/), so
it only runs when AUDIDASH_E2E=1 (the CI ``compose-smoke`` job). It never touches the
developer's own audidash config: the client runs with isolated XDG_CONFIG_HOME / APPDATA /
LOCALAPPDATA / HOME. Linux (the CI runner) is the supported platform; the lab targets and the
published ports are Linux-docker oriented.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(os.environ.get("AUDIDASH_E2E") != "1", reason="set AUDIDASH_E2E=1 to run"),
]

DEPLOY = Path(__file__).resolve().parents[1]
REPO = DEPLOY.parent
DASHBOARD = "https://localhost:8443"
API = "https://localhost:9443"
USERNAME = "ci-admin"
TOTP_FILE_IN_CONTAINER = "/data/ci-totp.secret"
TIMEOUT = 300


def _compose(*args: str, stdin: str | None = None) -> str:
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        ["docker", "compose", *args],  # noqa: S607
        cwd=DEPLOY,
        input=stdin,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert done.returncode == 0, f"docker compose {args[0]} failed:\n{done.stderr}"
    return done.stdout


def _server(*args: str, stdin: str | None = None) -> str:
    return _compose("exec", "-T", "server", *args, stdin=stdin)


class Client:
    """The `audidash` CLI with an isolated config directory."""

    def __init__(self, home: Path) -> None:
        self.env = {
            **os.environ,
            "XDG_CONFIG_HOME": str(home / "config"),
            "HOME": str(home),
            "APPDATA": str(home / "appdata"),
            "LOCALAPPDATA": str(home / "localappdata"),
            "PYTHONUTF8": "1",
        }

    def run(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]:
        done = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [sys.executable, "-m", "audidash_core.cli", *args],
            cwd=REPO,
            env=self.env,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
        assert done.returncode == 0, f"audidash {args[0]} failed:\n{done.stdout}\n{done.stderr}"
        return done


def test_demo_end_to_end(tmp_path: Path) -> None:
    import pyotp

    password = "Ci-" + secrets.token_urlsafe(24)
    _server(
        "audidash-server",
        "create-admin",
        "--username",
        USERNAME,
        "--password-stdin",
        "--totp-secret-out",
        TOTP_FILE_IN_CONTAINER,
        stdin=password + "\n",
    )
    secret_file = tmp_path / "totp.secret"
    _compose("cp", f"server:{TOTP_FILE_IN_CONTAINER}", str(secret_file))
    totp = pyotp.TOTP(secret_file.read_text().strip())

    fingerprint = _server("audidash-server", "show-ca-fingerprint").strip()
    created = _server("audidash-server", "create-enrollment-token", "--created-by", USERNAME)
    match = re.search(r"^Token .*: (\S+)$", created, re.MULTILINE)
    assert match, "enrolment token not found in create-enrollment-token output"

    client = Client(tmp_path / "client")
    client.run(
        "enroll",
        "--server",
        DASHBOARD,
        "--api",
        API,
        f"--token={match.group(1)}",
        "--name",
        "ci-device",
        "--ca-fingerprint",
        fingerprint,
    )
    client.run(
        "login",
        "--username",
        USERNAME,
        "--password-stdin",
        "--totp-code",
        totp.now(),
        stdin=password + "\n",
    )

    demo = client.run("demo")
    assert "Demo complete" in demo.stdout
    assert DASHBOARD in demo.stdout

    listed = client.run("assets").stdout
    for name in ("lab-web", "lab-tls", "lab-redis"):
        assert name in listed

    # The client API has no findings listing, so read them where the server stored them.
    dump = _server(
        "python",
        "-c",
        "import os, json\n"
        "from sqlalchemy import select\n"
        "from sqlalchemy.orm import Session\n"
        "from audidash_server.db import make_engine\n"
        "from audidash_server.models import Asset, FindingRecord as F\n"
        "e = make_engine(os.environ['AUDIDASH_DATABASE_URL'])\n"
        "with Session(e) as s:\n"
        "    rows = s.execute(select(Asset.name, F.finding_id, F.severity)"
        ".join(Asset, Asset.id == F.asset_id)).all()\n"
        "print(json.dumps([[n, f, str(v)] for n, f, v in rows]))\n",
    )
    findings = {(name, fid): severity for name, fid, severity in json.loads(dump.strip())}
    context = f"findings={findings}\ndemo stdout:\n{demo.stdout}\ndemo stderr:\n{demo.stderr}"
    assert findings.get(("lab-tls", "TLS-EXPIRED")) == "critical", context
    assert ("lab-web", "HTTP-NO-CSP") in findings, context
    assert ("lab-redis", "NET-OPEN-PORT") in findings, context
