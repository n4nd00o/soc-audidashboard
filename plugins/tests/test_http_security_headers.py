from collections.abc import Callable
from typing import Any

from audidash_core.manifest import TargetType
from audidash_core.runner import RunStatus

PLUGIN = "http-security-headers"

GOOD_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}


def _check(run_plugin: Any, url: str) -> Any:
    return run_plugin(PLUGIN, url, TargetType.web, {"url": url})


def test_http_without_headers(run_plugin: Any, http_server: Callable[..., Any]) -> None:
    result = _check(run_plugin, http_server().url)
    assert result.status is RunStatus.ok
    # HSTS only applies to https, so plain http yields the other four.
    assert {f.id for f in result.findings} == {
        "HTTP-NO-CSP",
        "HTTP-NO-XCTO",
        "HTTP-NO-FRAME-PROTECTION",
        "HTTP-NO-REFERRER-POLICY",
    }
    severities = {f.id: f.severity.value for f in result.findings}
    assert severities["HTTP-NO-CSP"] == "medium"
    assert severities["HTTP-NO-XCTO"] == "low"


def test_https_without_headers_has_all_five(
    run_plugin: Any, tls_server: Callable[..., Any]
) -> None:
    result = _check(run_plugin, tls_server().https_url)
    assert result.status is RunStatus.ok
    assert {f.id for f in result.findings} == {
        "HTTP-NO-HSTS",
        "HTTP-NO-CSP",
        "HTTP-NO-XCTO",
        "HTTP-NO-FRAME-PROTECTION",
        "HTTP-NO-REFERRER-POLICY",
    }
    hsts = next(f for f in result.findings if f.id == "HTTP-NO-HSTS")
    assert hsts.severity.value == "medium"
    assert "OWASP ASVS 14.4" in hsts.references


def test_all_headers_present_no_findings(
    run_plugin: Any, http_server: Callable[..., Any], tls_server: Callable[..., Any]
) -> None:
    assert _check(run_plugin, http_server(GOOD_HEADERS).url).findings == []
    result = _check(run_plugin, tls_server(headers=GOOD_HEADERS).https_url)
    assert result.status is RunStatus.ok
    assert result.findings == []


def test_csp_frame_ancestors_satisfies_frame_protection(
    run_plugin: Any, http_server: Callable[..., Any]
) -> None:
    headers = dict(GOOD_HEADERS)
    del headers["X-Frame-Options"]
    headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
    assert _check(run_plugin, http_server(headers).url).findings == []


def test_server_banner_with_version(run_plugin: Any, http_server: Callable[..., Any]) -> None:
    result = _check(run_plugin, http_server({**GOOD_HEADERS, "Server": "Apache/2.4.41"}).url)
    assert [(f.id, f.severity.value) for f in result.findings] == [("HTTP-SERVER-BANNER", "info")]
    assert "2.4.41" in result.findings[0].evidence


def test_server_header_without_version_is_fine(
    run_plugin: Any, http_server: Callable[..., Any]
) -> None:
    result = _check(run_plugin, http_server({**GOOD_HEADERS, "Server": "nginx"}).url)
    assert result.findings == []


def test_unreachable_target_warns_once(run_plugin: Any, free_port: int) -> None:
    result = _check(run_plugin, f"http://127.0.0.1:{free_port}/")
    assert result.status is RunStatus.ok
    assert result.findings == []
    assert len(result.warnings) == 1


def test_invalid_url_warns_once(run_plugin: Any) -> None:
    result = run_plugin(PLUGIN, "x", TargetType.web, {"url": "ftp://example.org/"})
    assert result.status is RunStatus.ok
    assert result.findings == []
    assert len(result.warnings) == 1
