# Writing plugins (English)

[Versão em português](plugins.md)

SOC AudiDashboard is a student portfolio project. Use plugins **only on infrastructure you are authorized to audit**. The project is aligned with (not certified for) ISO 27001/27002 and LGPD.

A plugin is a small program that receives a target on stdin, checks it, and prints findings as JSON on stdout. Plugins can be written in Python, PowerShell or Bash.

## Directory layout

```
plugins/
  my-plugin/
    plugin.yaml      # manifest (required)
    run.py           # entrypoint (any file listed in `files`)
    helpers/...      # optional extra modules (importable by the entrypoint), must be listed in `files`
```

Every file the plugin needs must be listed in `files` with its sha256 hash. The runner copies the files to a temporary directory, verifies the hashes of the copy and only then runs it.

## `plugin.yaml` reference

| Field | Type | Rules |
|---|---|---|
| `id` | string | `^[a-z0-9][a-z0-9-]{2,63}$` |
| `name` | string | non-empty |
| `version` | string | SemVer (`0.1.0`) |
| `author` | string | non-empty |
| `license` | string | non-empty (e.g. `Apache-2.0`) |
| `description` | string | non-empty |
| `runtime` | enum | `python`, `powershell` or `bash` |
| `execution` | enum | `local` or `remote`. **Remote execution arrives in a later release; for now use `local`.** |
| `entrypoint` | string | relative POSIX path (no `..`, no drive, no `\`), must be listed in `files` |
| `files` | map | relative path -> sha256 hex (64 lowercase chars) |
| `targets` | list | at least one of `linux`, `windows`, `aws`, `azure`, `gcp`, `m365`, `network`, `web`, `local` |
| `connection` | enum | `ssh`, `winrm`, `cloud_api`, `network`, `local` |
| `permissions` | list | at least one entry describing what the plugin needs (e.g. `read-only`) |
| `references` | list | optional links (standards, docs) |
| `parameters` | map | optional; each key maps to `{type, default, description}` with `type` one of `string`, `integer`, `boolean`, `list` |

Unknown fields are rejected. There is **no** `trust` field (see trust tiers below).

```yaml
id: demo-plugin
name: Demo plugin
version: 0.1.0
author: Your Name
license: Apache-2.0
description: Example plugin
runtime: python
execution: local
entrypoint: run.py
files:
  run.py: "<sha256 of run.py>"
targets: [local]
connection: local
permissions: [read-only]
parameters:
  max_items:
    type: integer
    default: 10
    description: Maximum items to check
```

## Input (stdin)

The plugin receives a single JSON object on stdin:

```json
{
  "target": "host-01",
  "target_type": "linux",
  "parameters": {"max_items": 10},
  "credentials": {"password": "..."}
}
```

`credentials` is empty when the plugin needs none. Credentials are delivered **only** through stdin: never argv, never environment variables.

## Output (stdout)

Print exactly one JSON object and nothing else on stdout:

```json
{
  "findings": [
    {
      "id": "DEMO-1",
      "title": "Short title",
      "severity": "medium",
      "category": "misconfiguration",
      "target": "host-01",
      "evidence": "what was observed",
      "recommendation": "how to fix it",
      "references": ["https://example.org/doc"],
      "item_key": "optional-stable-key"
    }
  ],
  "warnings": ["checks that could not run"]
}
```

| Field | Rules |
|---|---|
| `id` | `^[A-Z0-9][A-Z0-9_-]{1,63}$` |
| `title` | 1 to 200 characters |
| `severity` | `info`, `low`, `medium`, `high`, `critical` |
| `category` | `misconfiguration`, `vulnerability`, `suspicious`, `compliance` |
| `target` | the audited target (copy it from the input) |
| `evidence`, `recommendation` | text |
| `references` | list of strings |
| `item_key` | optional; distinguishes several findings with the same `id` on one target (e.g. a file path) |

Invalid output makes the run fail. Evidence is sanitized (secret-like strings redacted) and size-capped by the runner. Use stderr for diagnostics; exit with a non-zero code on fatal errors.

The runner runs plugins with a clean environment, a temporary working directory, a timeout and a stdout size limit.

## Example: Python (with the SDK)

`audidash_sdk` is standard-library only and is made importable by the runner. Python plugins run with `-I -S`: **only the standard library and `audidash_sdk` are importable** (not `audidash_core`, `pydantic`, etc.).

```python
from typing import Any

from audidash_sdk import Reporter, run


def main(data: dict[str, Any], report: Reporter) -> None:
    limit = int(data["parameters"].get("max_items", 10))
    if limit > 5:
        report.add(
            id="DEMO-1",
            title="Limit above recommended value",
            severity="low",
            category="compliance",
            evidence=f"max_items={limit}",
            recommendation="Use 5 or fewer.",
        )
    report.warn("example warning")


run(main)
```

SDK API: `read_input() -> dict`, `Reporter.add(id, title, severity, category, evidence="", recommendation="", references=None, item_key=None)` (raises `ValueError` for an unknown severity or category), `Reporter.warn(msg)`, `Reporter.emit()`, `run(main)`. `run` fills `target` from the input, prints the JSON, and on an uncaught exception prints `Type: message` to stderr and exits with code 1.

## Example: PowerShell

PowerShell and Bash plugins print the JSON themselves. Use `execution: local` for now.

```powershell
$payload = [Console]::In.ReadToEnd() | ConvertFrom-Json
$findings = @()
if ($payload.target -eq 'host-01') {
    $findings += @{
        id = 'DEMO-PS-1'; title = 'Example finding'; severity = 'info'
        category = 'compliance'; target = $payload.target
        evidence = 'demo'; recommendation = 'none'
        references = @(); item_key = $null
    }
}
$out = [ordered]@{ findings = @($findings); warnings = @() }
ConvertTo-Json -InputObject $out -Depth 5 -Compress
```

`ConvertTo-Json -InputObject` keeps `findings` an array even with a single element.

## Example: Bash

```bash
#!/usr/bin/env bash
set -euo pipefail
payload="$(cat)"
target="$(printf '%s' "$payload" | python3 -c 'import json,sys; print(json.load(sys.stdin)["target"])')"
printf '{"findings":[{"id":"DEMO-SH-1","title":"Example finding","severity":"info","category":"compliance","target":"%s","evidence":"demo","recommendation":"none","references":[],"item_key":null}],"warnings":[]}\n' "$target"
```

Be careful when interpolating input into JSON by hand; prefer a tool that escapes (`jq`, `python3`).

## Trust tiers

Plugins are shown with a tier: `official`, `verified` or `community`. The tier is **assigned by the catalog**, never by the manifest: a `trust` key in `plugin.yaml` is rejected. Authors cannot promote their own plugin.

The trust root (the catalog's Ed25519 public key) is **never** read from the plugins directory,
because that directory is untrusted: a cloned folder could ship its own key and signature. The
key is a package resource, `packages/audidash-core/src/audidash_core/keys/catalog.pub`, which the
maintainer adds at release time. Without it every plugin is `community` and asks for
confirmation before running. `audidash --public-key PATH` overrides it explicitly (the CLI prints
a notice that a custom trust root is in use).

## Computing hashes

After any edit, recompute `files`. With the CLI (`audidash plugins hash` is available):

```
audidash plugins hash <dir>
```

Alternatively, use Python:

```python
from pathlib import Path
from audidash_core.manifest import compute_hashes

print(compute_hashes(Path("plugins/my-plugin"), ["run.py"]))
```

Paste the result into `files` in `plugin.yaml`. Any change to a listed file without updating its hash makes the run fail with an integrity error.

## Security rules

- Do not make network connections beyond the target you were given.
- Credentials arrive only via stdin. Never put them in argv or environment variables, and never print, log or write them to findings, warnings or stderr.
- Do not modify the audited system; request only the permissions you need and list them in `permissions`.
- Do not write outside your temporary working directory.
- Do not download or execute code at run time.
- Keep evidence minimal: do not include secrets or personal data.

## Ethical use

Only audit systems you own or have explicit written authorization to assess. Unauthorized scanning may be illegal. This is a student project provided without warranty; it is aligned with, not certified for, ISO 27001/27002 and LGPD.
