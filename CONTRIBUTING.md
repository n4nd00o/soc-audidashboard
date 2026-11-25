# Contributing

Thanks for your interest! This is a student portfolio project; contributions and
feedback are welcome. By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Setup

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest -q
uv run ruff check .
uv run mypy packages
```

## Workflow

1. Fork and create a branch (`feat/...`, `fix/...`, `docs/...`).
2. Write a failing test first, then the code (TDD).
3. Make sure tests, `ruff` and `mypy` pass.
4. Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `chore:`, `test:`).
5. Open a pull request describing the change and why.

## Code and language

Code, commits and docstrings are in English. README and docs are provided in PT-BR and EN.

## Plugins

See `docs/plugins.md` (added in a later milestone) for the plugin manifest and contract.
Plugins must never exfiltrate data, must keep their source readable, and must only audit
systems the user is authorized to test.

## Security issues

Do not file public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
