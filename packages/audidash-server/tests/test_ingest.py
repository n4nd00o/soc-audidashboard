import uuid
from typing import Any

import pytest
from audidash_core.findings import FindingStatus, fingerprint
from audidash_server.models import Asset, AuditEntry, FindingEvent, FindingRecord, Role, Run
from fastapi.testclient import TestClient
from sqlalchemy import select

PLUGIN = "linux-baseline"
ASSET = {"name": "srv1", "address": "srv1.local", "asset_type": "linux", "criticality": "high"}


def _finding(
    fid: str, *, target: str = "srv1.local", item_key: str | None = None
) -> dict[str, Any]:
    return {
        "id": fid,
        "title": f"title {fid}",
        "severity": "high",
        "category": "misconfiguration",
        "target": target,
        "item_key": item_key,
    }


def _result(
    findings: list[dict[str, Any]], *, status: str = "ok", plugin_id: str = PLUGIN
) -> dict[str, Any]:
    return {
        "plugin_id": plugin_id,
        "plugin_version": "1.2.0",
        "target": "srv1.local",
        "status": status,
        "reason": None if status == "ok" else "boom",
        "findings": findings,
        "warnings": [],
        "started_at": "2026-11-25T11:59:00Z",
        "finished_at": "2026-11-25T12:00:00Z",
        "stderr_tail": "",
        "manifest_sha256": "a" * 64,
        "trust": "official",
    }


def _upload(api: Any, result: dict[str, Any], run_id: uuid.UUID | None = None) -> Any:
    body = {"run_id": str(run_id or uuid.uuid4()), "asset": "srv1", "result": result}
    return api.post("/api/v1/runs", body)


def _rows(client: TestClient, model: Any) -> list[Any]:
    with client.app.state.sessionmaker() as s:  # type: ignore[attr-defined]
        return list(s.scalars(select(model)).all())


def _by_finding_id(client: TestClient) -> dict[str, FindingRecord]:
    return {f.finding_id: f for f in _rows(client, FindingRecord)}


@pytest.fixture
def api(make_api_user: Any) -> Any:
    user = make_api_user()
    assert user.post("/api/v1/assets", ASSET).status_code == 201
    return user


def test_unknown_asset_rejected(api: Any) -> None:
    body = {"run_id": str(uuid.uuid4()), "asset": "nope", "result": _result([])}
    r = api.post("/api/v1/runs", body)
    assert r.status_code == 422
    assert r.json() == {"detail": "unknown asset 'nope'"}
    assert _rows(api.client, Run) == []


def test_finding_target_mismatch_rejected(api: Any) -> None:
    r = _upload(api, _result([_finding("A-1"), _finding("B-2", target="other.host")]))
    assert r.status_code == 422
    assert "B-2" in r.json()["detail"]
    assert _rows(api.client, Run) == [] and _rows(api.client, FindingRecord) == []


def test_finding_target_may_be_asset_name(api: Any) -> None:
    assert _upload(api, _result([_finding("A-1", target="srv1")])).status_code == 201


def test_first_upload_creates_findings_run_events_and_audit(api: Any, frozen_clock: Any) -> None:
    run_id = uuid.uuid4()
    r = _upload(api, _result([_finding("A-1"), _finding("B-2", item_key="/etc/x")]), run_id)
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["run_id"] == str(run_id)
    assert (body["new"], body["updated"], body["auto_resolved"]) == (2, 0, 0)
    assert 0 < body["asset_score"] <= 100
    (run,) = _rows(api.client, Run)
    assert run.id == run_id and run.plugin_id == PLUGIN and run.plugin_version == "1.2.0"
    assert run.device_id == api.device.id and run.user_id == api.user.id
    (asset,) = _rows(api.client, Asset)
    found = _by_finding_id(api.client)
    assert found["B-2"].fingerprint == fingerprint(PLUGIN, "B-2", str(asset.id), "/etc/x")
    assert all(f.status is FindingStatus.open and f.last_run_id == run_id for f in found.values())
    events = _rows(api.client, FindingEvent)
    assert sorted((e.from_status, e.to_status, e.run_id) for e in events) == [
        (None, FindingStatus.open, run_id),
        (None, FindingStatus.open, run_id),
    ]
    audits = [a for a in _rows(api.client, AuditEntry) if a.action == "run.ingest"]
    assert len(audits) == 1 and audits[0].actor_device_id == api.device.id


def test_idempotent_reupload_same_device(api: Any, frozen_clock: Any) -> None:
    run_id = uuid.uuid4()
    first = _upload(api, _result([_finding("A-1")]), run_id)
    assert first.status_code == 201
    counts = [len(_rows(api.client, m)) for m in (Run, FindingRecord, FindingEvent, AuditEntry)]
    frozen_clock.advance(seconds=5)
    again = _upload(api, _result([_finding("A-1"), _finding("C-3")]), run_id)
    assert again.status_code == 200
    assert again.json() == first.json()
    assert [len(_rows(api.client, m)) for m in (Run, FindingRecord, FindingEvent, AuditEntry)] == (
        counts
    )


def test_same_run_id_from_other_device_conflicts(api: Any, make_api_user: Any) -> None:
    run_id = uuid.uuid4()
    assert _upload(api, _result([_finding("A-1")]), run_id).status_code == 201
    other = make_api_user("bob")
    assert _upload(other, _result([_finding("A-1")]), run_id).status_code == 409


def test_auto_resolve_and_reopen_over_three_uploads(api: Any, frozen_clock: Any) -> None:
    r1 = _upload(api, _result([_finding("A-1"), _finding("B-2")]))
    assert (r1.json()["new"], r1.json()["auto_resolved"]) == (2, 0)
    frozen_clock.advance(minutes=1)
    r2 = _upload(api, _result([_finding("A-1")]))
    assert (r2.json()["new"], r2.json()["updated"], r2.json()["auto_resolved"]) == (0, 1, 1)
    assert _by_finding_id(api.client)["B-2"].status is FindingStatus.auto_resolved
    assert r2.json()["asset_score"] < r1.json()["asset_score"]
    frozen_clock.advance(minutes=1)
    run3 = uuid.uuid4()
    r3 = _upload(api, _result([_finding("A-1"), _finding("B-2")]), run3)
    assert (r3.json()["new"], r3.json()["updated"], r3.json()["auto_resolved"]) == (0, 2, 0)
    b = _by_finding_id(api.client)["B-2"]
    assert b.status is FindingStatus.open and b.last_seen == frozen_clock.current
    assert b.last_run_id == run3
    with api.client.app.state.sessionmaker() as s:
        transitions = [
            (e.from_status, e.to_status)
            for e in s.scalars(
                select(FindingEvent)
                .where(FindingEvent.finding_id == b.id)
                .order_by(FindingEvent.at)
            )
        ]
    assert transitions == [
        (None, FindingStatus.open),
        (FindingStatus.open, FindingStatus.auto_resolved),
        (FindingStatus.auto_resolved, FindingStatus.open),
    ]


@pytest.mark.parametrize("manual", [FindingStatus.accepted_risk, FindingStatus.false_positive])
def test_manual_states_untouched_by_auto_resolve(
    api: Any, frozen_clock: Any, manual: FindingStatus
) -> None:
    _upload(api, _result([_finding("A-1"), _finding("B-2")]))
    with api.client.app.state.sessionmaker() as s:
        rec = s.scalars(select(FindingRecord).where(FindingRecord.finding_id == "B-2")).one()
        rec.status = manual
        rec.justification = "compensating control"
        s.commit()
    r = _upload(api, _result([_finding("A-1")]))
    assert r.json()["auto_resolved"] == 0
    assert _by_finding_id(api.client)["B-2"].status is manual
    r = _upload(api, _result([_finding("A-1"), _finding("B-2")]))
    assert _by_finding_id(api.client)["B-2"].status is manual


@pytest.mark.parametrize("status", ["error", "timeout", "blocked"])
def test_non_ok_run_does_not_auto_resolve(api: Any, status: str) -> None:
    _upload(api, _result([_finding("A-1"), _finding("B-2")]))
    r = _upload(api, _result([], status=status))
    assert r.status_code == 201 and r.json()["auto_resolved"] == 0
    assert all(f.status is FindingStatus.open for f in _rows(api.client, FindingRecord))


def test_auto_resolve_scoped_to_plugin(api: Any) -> None:
    _upload(api, _result([_finding("A-1")]))
    r = _upload(api, _result([_finding("Z-9")], plugin_id="other-plugin"))
    assert r.json()["auto_resolved"] == 0
    assert _by_finding_id(api.client)["A-1"].status is FindingStatus.open


def test_result_target_mismatch_rejected(api: Any) -> None:
    result = _result([])
    result["target"] = "elsewhere"
    assert _upload(api, result).status_code == 422


def test_oversized_body_rejected(api: Any) -> None:
    big = _result([_finding("A-1")])
    big["stderr_tail"] = "x" * (5 * 1024 * 1024 + 1)
    r = _upload(api, big)
    assert r.status_code == 413
    assert _rows(api.client, Run) == []


def test_ingest_requires_bearer(api: Any) -> None:
    body = {"run_id": str(uuid.uuid4()), "asset": "srv1", "result": _result([])}
    r = api.client.post("/api/v1/runs", json=body, headers=api.device.headers)
    assert r.status_code == 401


def test_viewer_cannot_ingest(api: Any, make_api_user: Any) -> None:
    viewer = make_api_user("vic", Role.viewer)
    assert _upload(viewer, _result([_finding("A-1")])).status_code == 403


def test_oversized_chunked_body_rejected_while_reading(api: Any) -> None:
    def chunks() -> Any:
        for _ in range(6):
            yield b" " * (1024 * 1024)

    headers = {**api.headers, "Content-Type": "application/json"}
    r = api.client.post("/api/v1/runs", content=chunks(), headers=headers)
    assert "content-length" not in {k.lower() for k in r.request.headers}
    assert r.status_code == 413


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("plugin_id", "Bad_Id"),
        ("plugin_id", "ab"),
        ("plugin_id", "-leading-dash"),
        ("plugin_id", "audidash.dotted"),
        ("plugin_id", "a" * 65),
        ("plugin_id", "evil\x07-plugin"),
        ("plugin_version", ""),
        ("plugin_version", "1.0 beta"),
        ("plugin_version", "1.0\x00"),
        ("plugin_version", "1.0\n"),
        ("plugin_version", "9" * 65),
        ("manifest_sha256", "A" * 64),
        ("manifest_sha256", "a" * 63),
        ("manifest_sha256", "g" * 64),
        ("manifest_sha256", "a" * 63 + "\n"),
        ("trust", "godlike"),
    ],
)
def test_run_metadata_validated(api: Any, field: str, value: str) -> None:
    result = _result([_finding("A-1")])
    result[field] = value
    r = _upload(api, result)
    assert r.status_code == 422
    assert field in r.json()["detail"]
    assert _rows(api.client, Run) == [] and _rows(api.client, FindingRecord) == []


def test_run_metadata_accepts_semverish_and_null_hash(api: Any) -> None:
    result = _result([_finding("A-1")])
    result["plugin_version"] = "1.2.0-rc.1+build.5"
    result["manifest_sha256"] = None
    result["trust"] = None
    assert _upload(api, result).status_code in (200, 201)


@pytest.mark.parametrize(
    ("started", "finished"),
    [
        ("2026-11-26T12:01:00Z", "2026-11-26T12:02:00Z"),  # > 24 h ahead of the server
        ("2026-11-25T11:59:00Z", "2026-11-26T12:00:11Z"),  # finished_at alone too far ahead
        ("1999-12-31T23:59:59Z", "2026-11-25T12:00:00Z"),  # before 2000-01-01
        ("1970-01-01T00:00:00Z", "1970-01-01T00:00:01Z"),
    ],
)
def test_implausible_run_times_rejected(
    api: Any, frozen_clock: Any, started: str, finished: str
) -> None:
    result = _result([_finding("A-1")])
    result |= {"started_at": started, "finished_at": finished}
    r = _upload(api, result)
    assert r.status_code == 422
    assert "started_at/finished_at" in r.json()["detail"]
    assert _rows(api.client, Run) == []


def test_run_times_within_bounds_accepted(api: Any, frozen_clock: Any) -> None:
    result = _result([_finding("A-1")])
    result |= {"started_at": "2000-01-01T00:00:00Z", "finished_at": "2026-11-26T12:00:00Z"}
    assert _upload(api, result).status_code == 201
