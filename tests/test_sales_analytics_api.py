from __future__ import annotations

import sqlite3

from fastapi.testclient import TestClient

from bitrix_ingest.api import app as app_module
from bitrix_ingest.domain.analysis_run import AnalysisRun


class _FakeSalesRepo:
    def build_report(self, *, tenant_id, run_id):
        return {
            "tenant_id": tenant_id,
            "run_id": run_id,
            "meta": {},
            "deal_dashboard": {},
            "task_status": {},
            "lead_status": {},
            "revenue_summary": {},
            "failure_reasons": {},
            "references": {},
        }

    def get_sales_audit_report(self, *, tenant_id, run_id):
        return None

    def list_sales_audit_reports(self, *, tenant_id, limit=50):
        return []

    def hide_sales_audit_report(self, *, tenant_id, run_id):
        return False


def _client(tmp_path, monkeypatch) -> TestClient:
    monkeypatch.setattr(app_module, "_DB_PATH", tmp_path / "app.db")
    monkeypatch.setattr(app_module, "_sales_repo", lambda: _FakeSalesRepo())
    monkeypatch.delenv("AI_AUDITOR_AUTH_REQUIRED", raising=False)
    monkeypatch.delenv("AUTH_REQUIRED", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AI_AUDITOR_OPENAI_API_KEY", raising=False)
    app_module._SALES_AUDIT_JOBS.clear()
    return TestClient(app_module.app)


def test_sales_analytics_run_wait_persists_run_and_reads_report(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    calls: dict[str, object] = {}

    def fake_execute_sales_analytics_pipeline(**kwargs):
        calls.update(kwargs)
        return {
            "tenant_id": kwargs["tenant_id"],
            "run_id": kwargs["run_id"],
            "storage": "postgres",
            "summary": {"meta": {"deals_unique": "3"}},
        }

    monkeypatch.setattr(
        app_module,
        "_execute_sales_analytics_pipeline",
        fake_execute_sales_analytics_pipeline,
    )

    response = client.post(
        "/sales-analytics/run",
        data={
            "date_from": "2026-04-01",
            "date_to": "2026-05-03",
            "include_tasks": "false",
            "include_leads": "false",
            "include_revenue": "false",
            "wait": "true",
        },
        headers={"X-Webhook-Url": "https://example.bitrix24.kz/rest/1/token/"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["storage"] == "postgres"
    assert payload["report"]["summary"]["meta"]["deals_unique"] == "3"
    assert calls["date_from"] == "2026-04-01"
    assert calls["date_to"] == "2026-05-03"
    assert calls["include_tasks"] is False
    assert calls["tenant_id"] == "default"


def test_sales_analytics_report_requires_existing_postgres_run(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    response = client.get(
        "/sales-analytics/report",
        params={"run_id": "missing"},
    )

    assert response.status_code == 404


def test_sales_audit_run_wait_returns_unified_report(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    calls: dict[str, object] = {}

    def fake_execute_sales_audit_pipeline(**kwargs):
        calls.update(kwargs)
        kwargs["progress_callback"](
            {
                "stage": "sales_quality",
                "stage_label": "AI",
                "current": 3,
                "total": 10,
                "percent": 75,
                "message": "AI evaluates communications",
            }
        )
        return {
            "report": {
                "generated_at": "2026-05-03T00:00:00+00:00",
                "scope": {"mode": "sales_audit"},
                "integral_rating": {"score_10": 6.8},
            }
        }

    monkeypatch.setattr(
        app_module,
        "_execute_sales_audit_pipeline",
        fake_execute_sales_audit_pipeline,
    )

    response = client.post(
        "/sales-audit/run",
        data={
            "date_from": "2026-04-01",
            "date_to": "2026-05-03",
            "wait": "true",
        },
        headers={
            "X-Webhook-Url": "https://example.bitrix24.kz/rest/1/token/",
            "X-Whatsapp-Webhook-Url": "https://example.bitrix24.kz/rest/1/token/",
            "X-OpenAI-Api-Key": "sk-test",
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["storage"] == "postgres"
    assert payload["executive_report"]["integral_rating"]["score_10"] == 6.8
    assert calls["tenant_id"] == "default"
    assert calls["date_from"] == "2026-04-01"
    run = app_module._runs_repo().get(payload["job_id"])
    assert run is not None
    assert run.progress_stage == "completed"
    assert run.progress_percent == 100


def test_sales_audit_run_uses_global_openai_key(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-global")
    calls: dict[str, object] = {}

    def fake_execute_sales_audit_pipeline(**kwargs):
        calls.update(kwargs)
        return {"report": {"integral_rating": {"score_10": 7.0}}}

    monkeypatch.setattr(
        app_module,
        "_execute_sales_audit_pipeline",
        fake_execute_sales_audit_pipeline,
    )

    response = client.post(
        "/sales-audit/run",
        data={
            "date_from": "2026-04-01",
            "date_to": "2026-05-03",
            "wait": "true",
        },
        headers={
            "X-Webhook-Url": "https://example.bitrix24.kz/rest/1/token/",
            "X-Whatsapp-Webhook-Url": "https://example.bitrix24.kz/rest/1/token/",
        },
    )

    assert response.status_code == 200
    assert calls["openai_key"] == "sk-global"


def test_sales_audit_history_returns_postgres_report_runs(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    class _FakeHistoryRepo(_FakeSalesRepo):
        def list_sales_audit_reports(self, *, tenant_id, limit=50):
            assert tenant_id == "default"
            assert limit == 50
            return [
                {
                    "run_id": "audit-123",
                    "updated_at": "2026-05-04T08:00:00+00:00",
                    "summary": {
                        "generated_at": "2026-05-04T07:59:00+00:00",
                        "scope": {
                            "mode": "sales_audit",
                            "date_from": "2026-03-01",
                            "date_to": "2026-04-16",
                            "category_ids": ["0"],
                            "responsible_ids": ["8"],
                        },
                        "integral_rating": {"score_10": 7.1, "score_pct": 71},
                        "deal_dashboard": {
                            "department": {
                                "total_deals": 12,
                                "in_work_count": 5,
                                "won_count": 3,
                                "failed_count": 4,
                            },
                        },
                        "task_status": {
                            "department": {
                                "without_open_tasks": 2,
                                "with_overdue_tasks": 1,
                            },
                        },
                    },
                },
            ]

    monkeypatch.setattr(app_module, "_sales_repo", lambda: _FakeHistoryRepo())

    response = client.get("/sales-audit/history")

    assert response.status_code == 200
    payload = response.json()
    assert payload["latest_run_id"] == "audit-123"
    assert payload["runs"][0]["id"] == "audit-123"
    assert payload["runs"][0]["source"] == "sales_audit_report"
    assert payload["runs"][0]["filters"]["period_from"] == "2026-03-01"
    assert payload["runs"][0]["filters"]["responsible_ids"] == ["8"]
    assert payload["runs"][0]["metric_snapshot"]["total_deals"] == 12


def test_sales_audit_frontend_adapter_endpoints_return_report_arrays(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    class _FakeFrontendRepo(_FakeSalesRepo):
        def list_sales_audit_reports(self, *, tenant_id, limit=50):
            assert tenant_id == "default"
            return [{"run_id": "audit-123"}]

        def get_sales_audit_report(self, *, tenant_id, run_id):
            assert tenant_id == "default"
            assert run_id == "audit-123"
            return {
                "references": {"manager_names": {"8": "Alice Manager"}},
                "interaction_index": [
                    {
                        "interaction_id": "wa-1",
                        "channel": "whatsapp",
                        "manager_id": "8",
                        "manager_name": "",
                        "deal_stage_semantic_id": "P",
                    },
                    {"interaction_id": "call-1", "channel": "call", "deal_stage_semantic_id": "P"},
                ],
                "urgent_alerts": [
                    {"deal_id": "777", "manager_id": "8", "trigger_type": "response_sla", "deal_stage_semantic_id": "P"},
                ],
            }

    monkeypatch.setattr(app_module, "_sales_repo", lambda: _FakeFrontendRepo())

    interactions = client.get(
        "/sales-audit/interactions",
        params={"channel": "whatsapp"},
    )
    assert interactions.status_code == 200
    assert interactions.json()["total"] == 1
    assert interactions.json()["interactions"][0]["interaction_id"] == "wa-1"
    assert interactions.json()["interactions"][0]["manager_name"] == "Alice Manager"

    alerts = client.get("/sales-audit/urgent-alerts")
    assert alerts.status_code == 200
    assert alerts.json()["total"] == 1
    assert alerts.json()["alerts"][0]["deal_id"] == "777"
    assert alerts.json()["alerts"][0]["manager_label"] == "Alice Manager"


def test_sales_audit_history_hide_removes_report_from_history(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    class _FakeHideRepo(_FakeSalesRepo):
        def __init__(self):
            self.hidden: set[str] = set()
            self.rows = [
                {
                    "run_id": "audit-new",
                    "updated_at": "2026-05-04T08:00:00+00:00",
                    "summary": {"scope": {"date_from": "2026-05-01", "date_to": "2026-05-04"}},
                },
                {
                    "run_id": "audit-old",
                    "updated_at": "2026-05-03T08:00:00+00:00",
                    "summary": {"scope": {"date_from": "2026-04-01", "date_to": "2026-04-30"}},
                },
            ]

        def list_sales_audit_reports(self, *, tenant_id, limit=50):
            assert tenant_id == "default"
            return [row for row in self.rows if row["run_id"] not in self.hidden][:limit]

        def hide_sales_audit_report(self, *, tenant_id, run_id):
            assert tenant_id == "default"
            if run_id not in {row["run_id"] for row in self.rows} or run_id in self.hidden:
                return False
            self.hidden.add(run_id)
            return True

    repo = _FakeHideRepo()
    monkeypatch.setattr(app_module, "_sales_repo", lambda: repo)

    response = client.post("/sales-audit/history/audit-new/hide")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["hidden"] is True
    history = client.get("/sales-audit/history").json()
    assert history["latest_run_id"] == "audit-old"
    assert [run["id"] for run in history["runs"]] == ["audit-old"]


def test_sales_audit_history_hide_missing_report_returns_404(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    response = client.post("/sales-audit/history/missing-audit/hide")

    assert response.status_code == 404


def test_sales_audit_job_marks_stale_persisted_run_as_error(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)
    monkeypatch.setenv("AI_AUDITOR_JOB_STALE_SECONDS", "300")

    app_module._runs_repo().create(
        AnalysisRun(
            run_id="stale-audit-1",
            tenant_id="default",
            status="running",
            date_from="2026-04-01",
            date_to="2026-05-03",
            output_dir="storage/default/stale-audit-1/sales-audit",
        )
    )
    with sqlite3.connect(tmp_path / "app.db") as conn:
        conn.execute(
            "UPDATE analysis_runs SET created_at = ? WHERE run_id = ?",
            ("2000-01-01T00:00:00+00:00", "stale-audit-1"),
        )

    response = client.get("/sales-audit/jobs/stale-audit-1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "error"
    assert payload["error_type"] == "StaleJobTimeout"
    assert "new report can be started" in payload["error"]
    assert app_module._runs_repo().get("stale-audit-1").status == "error"


def test_sales_audit_job_returns_persisted_progress(tmp_path, monkeypatch):
    client = _client(tmp_path, monkeypatch)

    app_module._runs_repo().create(
        AnalysisRun(
            run_id="progress-audit-1",
            tenant_id="default",
            status="running",
            date_from="2026-04-01",
            date_to="2026-05-03",
            output_dir="storage/default/progress-audit-1/sales-audit",
        )
    )
    app_module._runs_repo().update_progress(
        "progress-audit-1",
        stage="transcription",
        label="Transcription",
        current=42,
        total=100,
        percent=51.5,
        message="Transcribing calls: 42 of 100",
        eta_seconds=120,
        updated_at="2026-05-29T12:00:00+00:00",
    )

    response = client.get("/sales-audit/jobs/progress-audit-1")

    assert response.status_code == 200
    payload = response.json()
    assert payload["progress_stage"] == "transcription"
    assert payload["progress"]["current"] == 42
    assert payload["progress"]["percent"] == 51.5
    assert payload["progress"]["eta_seconds"] == 120
