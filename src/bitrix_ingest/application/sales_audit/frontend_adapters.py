"""Frontend-facing adapters for sales-audit reports."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_SLA_RESPONSE_MINUTES = 30
_LEGACY_DEFAULT_PORTAL_HOSTS = {"sapaplast.bitrix24.kz"}

_TRIGGER_META = {
    "response_sla": {
        "label": "Ответ > 30 минут",
        "severity": 5,
        "recommendation": "Ответить клиенту сейчас, признать задержку, дать конкретный ответ и поставить задачу на следующий контакт.",
    },
    "missed_call": {
        "label": "Пропущенный звонок",
        "severity": 5,
        "recommendation": "Перезвонить клиенту. Если не дозвонились, отправить сообщение с временем повторного звонка.",
    },
    "no_next_step": {
        "label": "Нет следующего шага",
        "severity": 4,
        "recommendation": "Зафиксировать следующий шаг в CRM: встреча, Zoom, замер, расчет, оплата или контрольный звонок.",
    },
    "no_active_task": {
        "label": "Нет активной задачи",
        "severity": 4,
        "recommendation": "Поставить активную задачу по сделке с ближайшим дедлайном и понятным результатом.",
    },
    "overdue_task": {
        "label": "Просроченная задача",
        "severity": 4,
        "recommendation": "Обновить просроченную задачу и связаться с клиентом до конца рабочего дня.",
    },
    "no_need_identified": {
        "label": "Продажа в лоб",
        "severity": 3,
        "recommendation": "Вернуться к квалификации: уточнить задачу, сроки, объем, бюджет и критерии выбора.",
    },
}


def load_sales_quality_features(sales_quality_dir: Path | None) -> list[dict[str, Any]]:
    """Load normalized sales-quality feature JSON files from a run directory."""
    if not sales_quality_dir:
        return []
    features_dir = sales_quality_dir / "features"
    if not features_dir.exists():
        return []
    rows: list[dict[str, Any]] = []
    for path in sorted(features_dir.glob("*.json")):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        if isinstance(raw, dict):
            rows.append(raw)
    return rows


def build_frontend_sales_audit_data(
    *,
    features: list[dict[str, Any]],
    report: dict[str, Any],
    scope_deals: list[dict[str, Any]] | None = None,
    portal_base_url: str = "",
) -> dict[str, Any]:
    """Build arrays consumed by the service-2.0 frontend screens."""
    manager_names = _report_manager_names(report)
    deal_index = _build_deal_index(
        report,
        scope_deals or [],
        portal_base_url,
        manager_names=manager_names,
    )
    all_interactions = build_interaction_index(
        features=features,
        deal_index=deal_index,
        portal_base_url=portal_base_url,
        manager_names=manager_names,
        in_work_only=False,
    )
    interactions = build_interaction_index(
        features=features,
        deal_index=deal_index,
        portal_base_url=portal_base_url,
        manager_names=manager_names,
    )
    urgent_alerts = build_urgent_alerts(
        interactions=interactions,
        report=report,
        deal_index=deal_index,
        portal_base_url=portal_base_url,
    )
    return {
        "interaction_index": interactions,
        "whatsapp_interactions": [
            row for row in interactions if row.get("channel") == "whatsapp"
        ],
        "call_interactions": [
            row for row in interactions if row.get("channel") == "call"
        ],
        "urgent_alerts": urgent_alerts,
        "alerts_dashboard": {
            "rows": urgent_alerts,
            "source": "sales_quality_features + sales_analytics_tasks",
        },
        "dashboard_rankings": build_dashboard_rankings(
            interactions=all_interactions,
            report=report,
            scope_deals=scope_deals or [],
            deal_index=deal_index,
        ),
    }


def build_interaction_index(
    *,
    features: list[dict[str, Any]],
    deal_index: dict[str, dict[str, Any]] | None = None,
    portal_base_url: str = "",
    manager_names: dict[str, str] | None = None,
    in_work_only: bool = True,
) -> list[dict[str, Any]]:
    """Flatten sales-quality features into rows for calls and WhatsApp tables."""
    deal_index = deal_index or {}
    manager_names = manager_names or {}
    rows = [
        row
        for row in (
            _interaction_row(
                feature,
                deal_index=deal_index,
                portal_base_url=portal_base_url,
                manager_names=manager_names,
            )
            for feature in features
            if isinstance(feature, dict)
        )
        if not in_work_only or _is_in_work_deal(row)
    ]
    return sorted(rows, key=lambda row: _timestamp(row.get("created_at")), reverse=True)


def build_dashboard_rankings(
    *,
    interactions: list[dict[str, Any]],
    report: dict[str, Any],
    scope_deals: list[dict[str, Any]],
    deal_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build dashboard-only ratings from AI communication and CRM source data."""
    return {
        "request_stats": _build_request_stats(interactions),
        "failure_stats": _build_failure_stats(
            interactions=interactions,
            report=report,
            deal_index=deal_index,
        ),
        "successful_sources": _build_successful_sources(scope_deals),
    }


def filter_frontend_sales_audit_in_work_sections(report: dict[str, Any]) -> dict[str, Any]:
    """Limit WhatsApp, calls, and urgent frontend sections to deals still in work."""
    if not isinstance(report, dict):
        return report

    filtered = dict(report)
    interactions = [
        row
        for row in filtered.get("interaction_index") or []
        if isinstance(row, dict) and _is_in_work_deal(row)
    ]
    active_ids = {_clean(row.get("deal_id")) for row in interactions if _clean(row.get("deal_id"))}
    active_ids.update(
        _clean(row.get("deal_id") or row.get("id"))
        for row in _task_deal_rows(filtered)
        if _clean(row.get("deal_id") or row.get("id"))
    )

    alerts = [
        row
        for row in filtered.get("urgent_alerts") or []
        if isinstance(row, dict)
        and (_is_in_work_deal(row) or _clean(row.get("deal_id")) in active_ids)
    ]

    filtered["interaction_index"] = interactions
    filtered["whatsapp_interactions"] = [
        row for row in interactions if row.get("channel") == "whatsapp"
    ]
    filtered["call_interactions"] = [
        row for row in interactions if row.get("channel") == "call"
    ]
    filtered["urgent_alerts"] = alerts

    dashboard = filtered.get("alerts_dashboard")
    if isinstance(dashboard, dict):
        filtered["alerts_dashboard"] = {
            **dashboard,
            "rows": alerts,
        }
    return filtered


def enrich_frontend_manager_names(report: dict[str, Any]) -> dict[str, Any]:
    """Fill frontend manager names from report references for saved reports."""
    if not isinstance(report, dict):
        return report
    manager_names = _report_manager_names(report)
    if not manager_names:
        return report

    enriched = dict(report)
    for key in ("interaction_index", "whatsapp_interactions", "call_interactions"):
        if key in enriched:
            enriched[key] = _enrich_manager_rows(enriched.get(key), manager_names)

    if "urgent_alerts" in enriched:
        enriched["urgent_alerts"] = _enrich_alert_rows(enriched.get("urgent_alerts"), manager_names)

    dashboard = enriched.get("alerts_dashboard")
    if isinstance(dashboard, dict) and "rows" in dashboard:
        enriched["alerts_dashboard"] = {
            **dashboard,
            "rows": _enrich_alert_rows(dashboard.get("rows"), manager_names),
        }

    return enriched


def enrich_frontend_deal_urls(report: dict[str, Any], portal_base_url: str) -> dict[str, Any]:
    """Fill frontend CRM links from the current tenant portal for saved reports."""
    if not isinstance(report, dict):
        return report
    if not _clean(portal_base_url):
        return report

    enriched = dict(report)
    for key in ("interaction_index", "whatsapp_interactions", "call_interactions", "urgent_alerts"):
        if key in enriched:
            enriched[key] = _enrich_deal_url_rows(enriched.get(key), portal_base_url)

    dashboard = enriched.get("alerts_dashboard")
    if isinstance(dashboard, dict) and "rows" in dashboard:
        enriched["alerts_dashboard"] = {
            **dashboard,
            "rows": _enrich_deal_url_rows(dashboard.get("rows"), portal_base_url),
        }

    return enriched


def build_urgent_alerts(
    *,
    interactions: list[dict[str, Any]],
    report: dict[str, Any],
    deal_index: dict[str, dict[str, Any]] | None = None,
    portal_base_url: str = "",
) -> list[dict[str, Any]]:
    """Build per-deal urgent alerts from interaction and CRM-task signals."""
    deal_index = deal_index or {}
    grouped: dict[str, dict[str, Any]] = {}

    for row in interactions:
        if not _is_urgent_candidate(row):
            continue
        triggers = _interaction_triggers(row)
        if not triggers:
            continue
        _merge_alert(
            grouped,
            _alert_base(row, deal_index=deal_index, portal_base_url=portal_base_url),
            triggers,
        )

    for task_row in _task_deal_rows(report):
        deal_id = _clean(task_row.get("deal_id") or task_row.get("id"))
        if not deal_id:
            continue
        indexed = deal_index.get(deal_id, {})
        if indexed and not _is_in_work_deal(indexed):
            continue
        triggers = []
        active_count = _int(task_row.get("active_task_count") or task_row.get("open_task_count"))
        overdue_count = _int(task_row.get("overdue_task_count") or task_row.get("overdue_tasks"))
        if active_count <= 0:
            triggers.append(_trigger("no_active_task", "По активной сделке не найдено открытых задач."))
        if overdue_count > 0:
            triggers.append(_trigger("overdue_task", f"В сделке просроченных задач: {overdue_count}."))
        if not triggers:
            continue
        base = {
            "id": deal_id,
            "deal_id": deal_id,
            "deal_title": indexed.get("deal_title") or task_row.get("deal_title") or f"Сделка #{deal_id}",
            "deal_url": indexed.get("deal_url") or _deal_url(deal_id, portal_base_url),
            "manager_id": _clean(indexed.get("manager_id") or task_row.get("manager_id")),
            "manager_label": indexed.get("manager_name") or task_row.get("manager_name") or _manager_label(task_row.get("manager_id")),
            "created_at": indexed.get("created_at") or task_row.get("created_at") or "",
            "deal_stage_id": indexed.get("stage_id") or "",
            "deal_stage_name": indexed.get("stage_name") or "",
            "deal_stage_semantic_id": indexed.get("stage_semantic_id") or "",
            "active_as_of_to": indexed.get("active_as_of_to"),
            "status_bucket": indexed.get("status_bucket") or "",
        }
        _merge_alert(grouped, base, triggers)

    return sorted(
        (_finalize_alert(row) for row in grouped.values()),
        key=lambda row: (-_num(row.get("score")), _timestamp(row.get("created_at")) * -1),
    )


def _build_request_stats(interactions: list[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, dict[str, Any]] = {}
    for row in interactions:
        if row.get("non_sales_interaction"):
            continue
        label = _request_label(row)
        key = _bucket_key(label)
        item = buckets.setdefault(
            key,
            {
                "key": key,
                "label": label,
                "count": 0,
                "channels": {},
                "examples": [],
            },
        )
        item["count"] += 1
        channel = _clean(row.get("channel")) or "unknown"
        item["channels"][channel] = _int(item["channels"].get(channel)) + 1
        if len(item["examples"]) < 3:
            item["examples"].append(
                {
                    "interaction_id": row.get("interaction_id") or "",
                    "deal_id": row.get("deal_id") or "",
                    "deal_title": row.get("deal_title") or "",
                    "client_request": row.get("client_request") or row.get("summary") or "",
                    "channel": channel,
                }
            )
    rows = sorted(buckets.values(), key=lambda item: (-_int(item.get("count")), str(item.get("label") or "")))
    total = sum(_int(row.get("count")) for row in rows)
    for row in rows:
        row["rate"] = _pct(_int(row.get("count")), total)
    return {
        "source": "sales_quality_features.client_request",
        "total_requests": total,
        "rows": rows[:10],
    }


def _build_failure_stats(
    *,
    interactions: list[dict[str, Any]],
    report: dict[str, Any],
    deal_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    buckets: dict[str, dict[str, Any]] = {}
    counted_deals: set[str] = set()

    for card in report.get("failed_deal_reanimation", {}).get("cards") or []:
        if not isinstance(card, dict):
            continue
        reason = _failure_card_label(card)
        deal_id = _clean(card.get("deal_id"))
        _add_failure_bucket(
            buckets,
            reason,
            deal_id=deal_id,
            deal_title=_clean(card.get("deal_title")),
            evidence=_clean(card.get("failure_reason") or card.get("failure_comment") or " ".join(card.get("reason_signals") or [])),
            source="failed_deal_reanimation",
        )
        if deal_id:
            counted_deals.add(deal_id)

    for row in interactions:
        deal_id = _clean(row.get("deal_id"))
        deal = deal_index.get(deal_id, {})
        if not deal_id or deal_id in counted_deals or not _is_failed_deal({**deal, **row}):
            continue
        reason = _failure_interaction_label(row)
        _add_failure_bucket(
            buckets,
            reason,
            deal_id=deal_id,
            deal_title=_clean(row.get("deal_title")),
            evidence=_clean(row.get("client_request") or row.get("summary")),
            source="sales_quality_features.last_interactions",
        )
        counted_deals.add(deal_id)

    rows = sorted(buckets.values(), key=lambda item: (-_int(item.get("count")), str(item.get("label") or "")))
    total = len(counted_deals) or sum(_int(row.get("count")) for row in rows)
    for row in rows:
        row["rate"] = _pct(_int(row.get("count")), total)
    return {
        "source": "ai_failure_reasons_from_last_interactions",
        "manager_declared_reasons_trusted": False,
        "failed_deals_analyzed": total,
        "rows": rows[:10],
    }


def _build_successful_sources(scope_deals: list[dict[str, Any]]) -> dict[str, Any]:
    buckets: dict[str, dict[str, Any]] = {}
    for deal in scope_deals:
        if not isinstance(deal, dict) or not _is_successful_deal(deal):
            continue
        label = _deal_source_label(deal)
        key = _bucket_key(label)
        item = buckets.setdefault(
            key,
            {
                "key": key,
                "label": label,
                "count": 0,
                "amount": 0.0,
                "examples": [],
            },
        )
        item["count"] += 1
        item["amount"] += _num(deal.get("OPPORTUNITY") or deal.get("opportunity"))
        if len(item["examples"]) < 3:
            item["examples"].append(
                {
                    "deal_id": _clean(deal.get("ID") or deal.get("id") or deal.get("deal_id")),
                    "deal_title": _clean(deal.get("TITLE") or deal.get("title") or deal.get("deal_title")),
                    "source_id": _clean(deal.get("SOURCE_ID") or deal.get("source_id")),
                    "source_description": _clean(deal.get("SOURCE_DESCRIPTION") or deal.get("source_description")),
                }
            )
    rows = sorted(
        buckets.values(),
        key=lambda item: (-_int(item.get("count")), -_num(item.get("amount")), str(item.get("label") or "")),
    )
    total = sum(_int(row.get("count")) for row in rows)
    for row in rows:
        row["amount"] = round(_num(row.get("amount")), 2)
        row["rate"] = _pct(_int(row.get("count")), total)
    return {
        "source": "crm_deal_successful_sources",
        "successful_deals": total,
        "rows": rows[:10],
    }


def _interaction_row(
    feature: dict[str, Any],
    *,
    deal_index: dict[str, dict[str, Any]],
    portal_base_url: str,
    manager_names: dict[str, str],
) -> dict[str, Any]:
    source = feature.get("source") or {}
    source_type = _source_type(source)
    deal_id = _clean(source.get("deal_id"))
    deal = deal_index.get(deal_id, {})
    response = feature.get("response_time") or {}
    stages = feature.get("sales_stages") or {}
    problems = feature.get("problems") or {}
    next_step = feature.get("next_step") or {}
    lead_quality = feature.get("lead_quality") or {}
    started_at = _clean(source.get("started_at") or feature.get("generated_at"))
    tags = [str(item) for item in feature.get("tags") or [] if str(item).strip()]
    source_file = _clean(source.get("source_file_path"))
    manager_id = _clean(source.get("manager_id") or deal.get("manager_id"))
    manager_name = _resolve_manager_name(
        manager_id,
        source.get("manager_name"),
        deal.get("manager_name"),
        manager_names=manager_names,
    )

    return {
        "interaction_id": _interaction_id(source, source_type),
        "channel": source_type,
        "created_at": started_at,
        "manager_id": manager_id,
        "manager_name": manager_name,
        "deal_id": deal_id,
        "deal_title": deal.get("deal_title") or (f"Сделка #{deal_id}" if deal_id else ""),
        "deal_url": deal.get("deal_url") or _deal_url(deal_id, portal_base_url),
        "crm_url": deal.get("deal_url") or _deal_url(deal_id, portal_base_url),
        "deal_stage_id": deal.get("stage_id") or _clean(source.get("stage_id")) or "",
        "deal_stage_name": deal.get("stage_name") or _clean(source.get("stage_name")) or "",
        "deal_stage_semantic_id": deal.get("stage_semantic_id") or _clean(source.get("stage_semantic_id")) or "",
        "active_as_of_to": deal.get("active_as_of_to", source.get("active_as_of_to")),
        "status_bucket": deal.get("status_bucket") or _clean(source.get("status_bucket")) or "",
        "summary": _clean(feature.get("summary")),
        "primary_topic": _primary_topic(feature, tags),
        "client_request": _client_request(feature),
        "outcome_status": _outcome_status(feature),
        "need_identified": _yes_no(stages.get("need_identified")),
        "manager_asked_questions": "no" if bool(problems.get("manager_did_not_ask_questions")) else "yes",
        "manager_presented_service": _yes_no(stages.get("product_presented")),
        "manager_agreed_next_step": "yes" if _has_next_step(feature) else "no",
        "short_or_low_content": bool(problems.get("fragmented_or_low_content")),
        "non_sales_interaction": bool(problems.get("not_target_lead") or lead_quality.get("status") == "not_target"),
        "fragmented_or_unclear": bool(
            problems.get("fragmented_or_low_content") or problems.get("unclear_audio_or_text")
        ),
        "labels": tags,
        "tags": tags,
        "response_wait_minutes": _minutes(response.get("first_response_time_sec")),
        "first_response_time_sec": response.get("first_response_time_sec"),
        "avg_response_latency_sec": response.get("avg_response_latency_sec"),
        "stage_score_pct": feature.get("stage_score_pct"),
        "transcript_file_path": source_file if source_type == "call" else "",
        "conversation_file_path": source_file if source_type == "whatsapp" else "",
        "crm_activity_id": _clean(source.get("crm_activity_id")),
        "record_file_id": _clean(source.get("record_file_id")),
        "contact_id": _clean(source.get("contact_id")),
        "source": {
            **source,
            "manager_id": manager_id,
            "manager_name": manager_name,
            "transcript_file_path": source_file if source_type == "call" else "",
            "conversation_file_path": source_file if source_type == "whatsapp" else "",
            "deal_url": deal.get("deal_url") or _deal_url(deal_id, portal_base_url),
        },
    }


def _interaction_triggers(row: dict[str, Any]) -> list[dict[str, Any]]:
    triggers = []
    wait_minutes = _num(row.get("response_wait_minutes"))
    if wait_minutes > _SLA_RESPONSE_MINUTES and _is_working_time(row.get("created_at")):
        triggers.append(_trigger("response_sla", f"Клиент ждет ответа {round(wait_minutes, 1)} мин в рабочее время."))
    if row.get("channel") == "call" and str(row.get("outcome_status") or "").lower() in {"no_answer", "missed_call"}:
        triggers.append(_trigger("missed_call", "В сделке есть пропущенный звонок или неуспешная попытка связи."))
    if str(row.get("manager_agreed_next_step") or "").lower() != "yes":
        triggers.append(_trigger("no_next_step", "Коммуникация завершилась без конкретного следующего шага."))
    if str(row.get("need_identified") or "").lower() != "yes" and str(row.get("manager_presented_service") or "").lower() == "yes":
        triggers.append(_trigger("no_need_identified", "Менеджер перешел к презентации до выявления потребности клиента."))
    return triggers


def _request_label(row: dict[str, Any]) -> str:
    tags = [str(item).strip() for item in row.get("tags") or row.get("labels") or [] if str(item).strip()]
    for value in [
        row.get("primary_topic"),
        tags[0] if tags else "",
        row.get("client_request"),
        row.get("summary"),
    ]:
        text = _clean(value)
        if text:
            return _trim_label(text)
    return "Запрос не распознан"


def _failure_card_label(card: dict[str, Any]) -> str:
    for value in [
        card.get("failure_category"),
        card.get("failure_reason_type"),
        card.get("reason_type"),
        card.get("reason_bucket"),
        card.get("failure_reason"),
        card.get("failure_comment"),
    ]:
        text = _clean(value)
        if text:
            return _trim_label(text)
    signals = [str(item).strip() for item in card.get("reason_signals") or [] if str(item).strip()]
    return _trim_label(signals[0]) if signals else "Причина не распознана"


def _failure_interaction_label(row: dict[str, Any]) -> str:
    if row.get("non_sales_interaction"):
        return "Нецелевой лид"
    if row.get("manager_asked_questions") == "no":
        return "Менеджер не выявил потребность"
    if row.get("need_identified") != "yes" and row.get("manager_presented_service") == "yes":
        return "Презентация до выявления потребности"
    if row.get("manager_agreed_next_step") != "yes":
        return "Нет следующего шага"
    return _request_label(row)


def _add_failure_bucket(
    buckets: dict[str, dict[str, Any]],
    label: str,
    *,
    deal_id: str,
    deal_title: str,
    evidence: str,
    source: str,
) -> None:
    key = _bucket_key(label)
    item = buckets.setdefault(
        key,
        {
            "key": key,
            "label": label,
            "count": 0,
            "examples": [],
            "sources": {},
        },
    )
    item["count"] += 1
    item["sources"][source] = _int(item["sources"].get(source)) + 1
    if len(item["examples"]) < 3:
        item["examples"].append(
            {
                "deal_id": deal_id,
                "deal_title": deal_title,
                "evidence": evidence,
            }
        )


def _deal_source_label(deal: dict[str, Any]) -> str:
    source_id = _clean(deal.get("SOURCE_ID") or deal.get("source_id"))
    source_description = _clean(deal.get("SOURCE_DESCRIPTION") or deal.get("source_description"))
    utm_source = _clean(deal.get("UTM_SOURCE") or deal.get("utm_source"))
    title = _clean(deal.get("TITLE") or deal.get("title"))
    for value in (source_description, utm_source, source_id):
        if value:
            return _trim_label(value)
    hash_tag = next((part for part in title.split() if part.startswith("#") and len(part) > 1), "")
    if hash_tag:
        return _trim_label(hash_tag)
    return "Источник не указан"


def _is_successful_deal(row: dict[str, Any]) -> bool:
    semantic = _clean(row.get("STAGE_SEMANTIC_ID") or row.get("stage_semantic_id")).upper()
    if semantic:
        return semantic == "S"
    status = _clean(row.get("status_bucket") or row.get("STATUS_BUCKET")).lower()
    if status:
        return status in {"won", "success", "successful"}
    won = _maybe_bool(row.get("won") or row.get("WON"))
    return bool(won)


def _is_failed_deal(row: dict[str, Any]) -> bool:
    semantic = _clean(row.get("deal_stage_semantic_id") or row.get("stage_semantic_id") or row.get("STAGE_SEMANTIC_ID")).upper()
    if semantic:
        return semantic == "F"
    status = _clean(row.get("status_bucket") or row.get("STATUS_BUCKET")).lower()
    return status in {"failed", "lost"}


def _bucket_key(value: str) -> str:
    return " ".join(_clean(value).lower().split()) or "unknown"


def _trim_label(value: str, limit: int = 96) -> str:
    text = " ".join(_clean(value).split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _task_deal_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    task_status = report.get("task_status") or {}
    return [
        row
        for row in task_status.get("deals") or task_status.get("per_deal") or []
        if isinstance(row, dict)
    ]


def _alert_base(
    row: dict[str, Any],
    *,
    deal_index: dict[str, dict[str, Any]],
    portal_base_url: str,
) -> dict[str, Any]:
    deal_id = _clean(row.get("deal_id"))
    indexed = deal_index.get(deal_id, {})
    return {
        "id": deal_id or _clean(row.get("interaction_id")),
        "deal_id": deal_id,
        "deal_title": indexed.get("deal_title") or row.get("deal_title") or f"Сделка #{deal_id}",
        "deal_url": indexed.get("deal_url") or row.get("deal_url") or _deal_url(deal_id, portal_base_url),
        "manager_id": _clean(row.get("manager_id")),
        "manager_label": row.get("manager_name") or _manager_label(row.get("manager_id")),
        "created_at": row.get("created_at") or "",
        "deal_stage_id": indexed.get("stage_id") or row.get("deal_stage_id") or "",
        "deal_stage_name": indexed.get("stage_name") or row.get("deal_stage_name") or "",
        "deal_stage_semantic_id": indexed.get("stage_semantic_id") or row.get("deal_stage_semantic_id") or "",
        "active_as_of_to": indexed.get("active_as_of_to", row.get("active_as_of_to")),
        "status_bucket": indexed.get("status_bucket") or row.get("status_bucket") or "",
    }


def _merge_alert(
    grouped: dict[str, dict[str, Any]],
    base: dict[str, Any],
    triggers: list[dict[str, Any]],
) -> None:
    key = _clean(base.get("deal_id") or base.get("id"))
    if not key:
        return
    current = grouped.get(key)
    if current is None:
        current = {**base, "triggers": []}
        grouped[key] = current
    existing = {trigger.get("type") for trigger in current["triggers"]}
    for trigger in triggers:
        if trigger.get("type") not in existing:
            current["triggers"].append(trigger)
            existing.add(trigger.get("type"))


def _finalize_alert(row: dict[str, Any]) -> dict[str, Any]:
    triggers = sorted(
        row.get("triggers") or [],
        key=lambda trigger: (-_int(trigger.get("severity")), str(trigger.get("label") or "")),
    )
    primary = triggers[0] if triggers else _trigger("no_next_step", "Сделка требует внимания.")
    reason = " ".join(str(trigger.get("reason") or "") for trigger in triggers).strip()
    recommendation = " ".join(
        str(trigger.get("recommendation") or "") for trigger in triggers[:3]
    ).strip()
    score = min(10, sum(_int(trigger.get("severity")) for trigger in triggers))
    return {
        **row,
        "score": score,
        "severity": score,
        "trigger_type": primary.get("type"),
        "reason": reason,
        "recommendation": recommendation,
        "what_wrong": reason,
        "what_to_do": recommendation,
        "triggers": triggers,
    }


def _trigger(trigger_type: str, reason: str) -> dict[str, Any]:
    meta = _TRIGGER_META[trigger_type]
    return {
        "type": trigger_type,
        "label": meta["label"],
        "severity": meta["severity"],
        "reason": reason,
        "recommendation": meta["recommendation"],
    }


def _build_deal_index(
    report: dict[str, Any],
    scope_deals: list[dict[str, Any]],
    portal_base_url: str,
    *,
    manager_names: dict[str, str] | None = None,
) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    manager_names = manager_names or {}
    for row in scope_deals:
        normalized = _normalize_deal(row, portal_base_url, manager_names=manager_names)
        if normalized.get("deal_id"):
            index[normalized["deal_id"]] = normalized
    report_deals = [
        *((report.get("deal_dashboard") or {}).get("deals") or []),
        *((report.get("task_status") or {}).get("deals") or []),
    ]
    for row in report_deals:
        normalized = _normalize_deal(row, portal_base_url, manager_names=manager_names)
        if not normalized.get("deal_id"):
            continue
        current = index.setdefault(normalized["deal_id"], {})
        for key, value in normalized.items():
            if value not in ("", None) and not current.get(key):
                current[key] = value
    return index


def _normalize_deal(
    row: dict[str, Any],
    portal_base_url: str,
    *,
    manager_names: dict[str, str],
) -> dict[str, Any]:
    deal_id = _clean(row.get("ID") or row.get("id") or row.get("deal_id"))
    manager_id = _clean(row.get("ASSIGNED_BY_ID") or row.get("assigned_by_id") or row.get("manager_id"))
    return {
        "deal_id": deal_id,
        "deal_title": _clean(row.get("TITLE") or row.get("title") or row.get("deal_title")) or (f"Сделка #{deal_id}" if deal_id else ""),
        "deal_url": _clean(row.get("deal_url") or row.get("crm_url")) or _deal_url(deal_id, portal_base_url),
        "manager_id": manager_id,
        "manager_name": _resolve_manager_name(
            manager_id,
            row.get("manager_name"),
            manager_names=manager_names,
        ),
        "stage_id": _clean(row.get("STAGE_ID") or row.get("stage_id")),
        "stage_name": _clean(row.get("stage_name") or row.get("STAGE_NAME")),
        "stage_semantic_id": _clean(row.get("STAGE_SEMANTIC_ID") or row.get("stage_semantic_id")),
        "active_as_of_to": row.get("active_as_of_to") if row.get("active_as_of_to") is not None else row.get("ACTIVE_AS_OF_TO"),
        "status_bucket": _clean(row.get("status_bucket") or row.get("STATUS_BUCKET")),
        "closed": _clean(row.get("CLOSED") or row.get("closed")),
        "created_at": _clean(row.get("DATE_CREATE") or row.get("date_create") or row.get("created_at")),
    }


def _source_type(source: dict[str, Any]) -> str:
    raw = str(source.get("source_type") or source.get("channel") or "").lower()
    if raw in {"call", "phone_call", "phone", "crm_call"}:
        return "call"
    if raw in {"whatsapp", "wa", "openline"}:
        return "whatsapp"
    return raw or "unknown"


def _interaction_id(source: dict[str, Any], source_type: str) -> str:
    source_id = _clean(source.get("source_id") or source.get("crm_activity_id") or source.get("deal_id"))
    return f"{source_type}-{source_id}" if source_id else source_type


def _primary_topic(feature: dict[str, Any], tags: list[str]) -> str:
    if tags:
        return tags[0]
    lead_quality = feature.get("lead_quality") or {}
    return _clean(lead_quality.get("reason")) or "Коммуникация с клиентом"


def _client_request(feature: dict[str, Any]) -> str:
    evidence = feature.get("evidence") or []
    if evidence:
        return _clean(evidence[0])
    return _clean(feature.get("summary"))


def _outcome_status(feature: dict[str, Any]) -> str:
    problems = feature.get("problems") or {}
    lead_quality = feature.get("lead_quality") or {}
    if problems.get("not_target_lead") or lead_quality.get("status") == "not_target":
        return "not_interested"
    if problems.get("client_negative_or_cold"):
        return "not_interested"
    if _has_next_step(feature):
        return "follow_up"
    if problems.get("missing_next_step") or problems.get("slow_response"):
        return "awaiting_response"
    return "qualified_interest"


def _has_next_step(feature: dict[str, Any]) -> bool:
    next_step = feature.get("next_step") or {}
    stages = feature.get("sales_stages") or {}
    flags = feature.get("stage_flags") or {}
    return (
        str(next_step.get("status") or "").lower() in {"agreed", "proposed"}
        or str(stages.get("next_step_attempted") or "").lower() == "yes"
        or str(stages.get("sale_attempted") or "").lower() == "yes"
        or bool(flags.get("next_step_or_sale"))
    )


def _is_urgent_candidate(row: dict[str, Any]) -> bool:
    if row.get("non_sales_interaction"):
        return False
    return _is_in_work_deal(row)


def _is_in_work_deal(row: dict[str, Any]) -> bool:
    semantic = str(
        row.get("deal_stage_semantic_id")
        or row.get("stage_semantic_id")
        or row.get("STAGE_SEMANTIC_ID")
        or ""
    ).strip().upper()
    if semantic:
        return semantic == "P"

    bucket = str(row.get("status_bucket") or row.get("STATUS_BUCKET") or "").strip().lower()
    if bucket:
        return bucket == "in_work"

    active = _maybe_bool(row.get("active_as_of_to", row.get("ACTIVE_AS_OF_TO")))
    if active is not None:
        return active

    closed = str(row.get("closed") or row.get("CLOSED") or "").strip().upper()
    if closed:
        return closed == "N"
    return False


def _is_working_time(value: Any) -> bool:
    dt = _parse_dt(value)
    if dt is None:
        return True
    return dt.weekday() < 5 and 10 <= dt.hour < 19


def _parse_dt(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _timestamp(value: Any) -> float:
    dt = _parse_dt(value)
    return dt.timestamp() if dt else 0.0


def _deal_url(deal_id: str, portal_base_url: str) -> str:
    if not deal_id or not portal_base_url:
        return ""
    return f"{portal_base_url.rstrip('/')}/crm/deal/details/{deal_id}/"


def _enrich_deal_url_rows(rows: Any, portal_base_url: str) -> Any:
    if not isinstance(rows, list):
        return rows
    enriched = []
    for row in rows:
        if not isinstance(row, dict):
            enriched.append(row)
            continue
        enriched.append(_enrich_deal_url_row(row, portal_base_url))
    return enriched


def _enrich_deal_url_row(row: dict[str, Any], portal_base_url: str) -> dict[str, Any]:
    source = row.get("source") if isinstance(row.get("source"), dict) else {}
    deal_id = _clean(row.get("deal_id") or source.get("deal_id"))
    next_url = _deal_url(deal_id, portal_base_url)
    if not next_url:
        return row

    next_row = dict(row)
    if _should_replace_deal_url(row.get("deal_url")):
        next_row["deal_url"] = next_url
    if _should_replace_deal_url(row.get("crm_url")):
        next_row["crm_url"] = next_url

    if source:
        next_source = dict(source)
        if _should_replace_deal_url(source.get("deal_url")):
            next_source["deal_url"] = next_url
        next_row["source"] = next_source

    return next_row


def _should_replace_deal_url(value: Any) -> bool:
    text = _clean(value)
    if not text:
        return True
    host = _url_host(text)
    return not host or host in _LEGACY_DEFAULT_PORTAL_HOSTS


def _url_host(value: str) -> str:
    raw = value.strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    return (parsed.hostname or "").lower()


def _manager_label(manager_id: Any) -> str:
    value = _clean(manager_id)
    return f"Менеджер #{value}" if value else "Менеджер не указан"


def _report_manager_names(report: dict[str, Any]) -> dict[str, str]:
    refs = report.get("references") or {}
    raw = refs.get("manager_names") or report.get("manager_names") or {}
    if not isinstance(raw, dict):
        return {}
    return {
        _clean(manager_id): _clean(name)
        for manager_id, name in raw.items()
        if _clean(manager_id) and _clean(name)
    }


def _resolve_manager_name(
    manager_id: Any,
    *candidates: Any,
    manager_names: dict[str, str],
) -> str:
    clean_id = _clean(manager_id)
    for candidate in candidates:
        name = _clean(candidate)
        if name and not _is_generated_manager_label(name, clean_id):
            return name
    if clean_id and manager_names.get(clean_id):
        return manager_names[clean_id]
    for candidate in candidates:
        name = _clean(candidate)
        if name:
            return name
    return _manager_label(clean_id)


def _is_generated_manager_label(value: str, manager_id: str) -> bool:
    if not manager_id:
        return False
    normalized = value.strip().lower().replace(" ", "")
    compact_id = manager_id.strip().lower()
    if normalized == compact_id:
        return True
    if normalized in {f"manager#{compact_id}", f"user{compact_id}", f"user#{compact_id}"}:
        return True
    return f"#{compact_id}" in normalized and len(normalized) <= len(compact_id) + 16


def _enrich_manager_rows(rows: Any, manager_names: dict[str, str]) -> Any:
    if not isinstance(rows, list):
        return rows
    enriched = []
    for row in rows:
        if not isinstance(row, dict):
            enriched.append(row)
            continue
        manager_id = _clean(row.get("manager_id"))
        manager_name = _resolve_manager_name(
            manager_id,
            row.get("manager_name"),
            manager_names=manager_names,
        )
        next_row = {**row, "manager_name": manager_name}
        source = row.get("source")
        if isinstance(source, dict):
            next_row["source"] = {**source, "manager_name": manager_name}
        enriched.append(next_row)
    return enriched


def _enrich_alert_rows(rows: Any, manager_names: dict[str, str]) -> Any:
    if not isinstance(rows, list):
        return rows
    enriched = []
    for row in rows:
        if not isinstance(row, dict):
            enriched.append(row)
            continue
        manager_id = _clean(row.get("manager_id"))
        manager_name = _resolve_manager_name(
            manager_id,
            row.get("manager_name"),
            row.get("manager_label"),
            manager_names=manager_names,
        )
        enriched.append({**row, "manager_name": manager_name, "manager_label": manager_name})
    return enriched


def _yes_no(value: Any) -> str:
    return "yes" if str(value or "").lower() == "yes" else "no"


def _minutes(value: Any) -> float | None:
    numeric = _optional_num(value)
    if numeric is None:
        return None
    return round(numeric / 60, 1)


def _clean(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def _num(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _pct(count: int | float, total: int | float) -> float:
    c = _num(count)
    t = _num(total)
    return round(c / t * 100, 1) if t else 0.0


def _maybe_bool(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y"}:
        return True
    if normalized in {"0", "false", "no", "n"}:
        return False
    return None


def _optional_num(value: Any) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
