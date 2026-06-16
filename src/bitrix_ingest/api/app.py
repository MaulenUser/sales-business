"""FastAPI application exposing the Bitrix exporters and OpenAI pipelines as HTTP endpoints."""
from __future__ import annotations

import json
import os
import logging
import re
import threading
import uuid
import base64
import contextvars
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

import requests
from fastapi import BackgroundTasks, FastAPI, Form, Header, HTTPException, Query, Request, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from ..domain.analysis_run import AnalysisRun
from ..domain.bitrix_connect_session import BitrixConnectSession
from ..domain.bitrix_oauth import BitrixOAuthToken
from ..domain.business_profile import BusinessProfile
from ..domain.client_registration import ClientRegistration
from ..domain.integrations import Integrations
from ..domain.tenant import Tenant
from ..domain.user import User
from ..infrastructure.database import (
    AnalysisRunRepository,
    BitrixConnectSessionRepository,
    BitrixOAuthRepository,
    BusinessProfileRepository,
    ClientRegistrationRepository,
    IntegrationsRepository,
    SalesAnalyticsRepository,
    TenantRepository,
    UserRepository,
)

from ..application.analytics import (
    AggregateFeatureRequest,
    AggregateFeatureService,
    GenerateRecommendationsRequest,
    GenerateRecommendationsService,
)
from ..application.audit import RunAuditRequest, RunAuditService
from ..application.call_features import ExtractCallFeaturesRequest, ExtractCallFeaturesService
from ..application.call_records import CallRecordsScanRequest, CallRecordsScanService
from ..application.catalog import GetCatalogService
from ..application.crm import CrmExportRequest, CrmExportService, StageHistoryRequest, StageHistoryService
from ..application.executive_report import BuildExecutiveReportRequest, BuildExecutiveReportService
from ..application.executive_pipeline import RunExecutivePipelineRequest, RunExecutivePipelineService
from ..application.recordings import DownloadRecordingsRequest, DownloadRecordingsService
from ..application.sales_analytics import ExportSalesAnalyticsRequest, ExportSalesAnalyticsService
from ..application.sales_audit import (
    build_sales_audit_report,
    enrich_frontend_deal_urls,
    enrich_frontend_manager_names,
    filter_frontend_sales_audit_in_work_sections,
)
from ..application.sales_quality import AnalyzeSalesQualityRequest, AnalyzeSalesQualityService
from ..application.transcribe import TranscribeRecordingsRequest, TranscribeRecordingsService
from ..application.whatsapp import WhatsAppExportRequest, WhatsAppExportService
from ..application.whatsapp_features import (
    ExtractWhatsAppFeaturesRequest,
    ExtractWhatsAppFeaturesService,
)
from ..application.whatsapp_timeline import (
    WhatsAppTimelineExportRequest,
    WhatsAppTimelineExportService,
)
from ..domain.exceptions import DomainError
from ..infrastructure.http import BitrixClient, BitrixOAuthClient
from ..infrastructure.http.file_downloader import RequestsFileDownloader
from ..infrastructure.openai import OpenAiResponsesClient, OpenAiTranscriptionClient
from ..infrastructure.audit_trace import AuditTraceRecorder, TracedJsonSink
from ..infrastructure.persistence import FileSystemJsonWriter
from ..infrastructure.persistence.memory_writer import InMemoryJsonSink, TeeJsonSink

logger = logging.getLogger(__name__)

_REQUIRED_BITRIX_OAUTH_SCOPES = (
    "crm",
    "task",
    "user_basic",
    "user",
    "imopenlines",
    "telephony",
    "disk",
    "department",
)

# ---------------------------------------------------------------------------
# Security schemes — shown in the Swagger "Authorize" dialog
# ---------------------------------------------------------------------------

_webhook_header = APIKeyHeader(
    name="X-Webhook-Url",
    scheme_name="WebhookUrl",
    description="Bitrix24 webhook URL для CRM и записей звонков",
    auto_error=False,
)

_whatsapp_webhook_header = APIKeyHeader(
    name="X-Whatsapp-Webhook-Url",
    scheme_name="WhatsappWebhookUrl",
    description="Bitrix24 webhook URL для WhatsApp-экспорта (можно отдельный)",
    auto_error=False,
)

_openai_key_header = APIKeyHeader(
    name="X-OpenAI-Api-Key",
    scheme_name="OpenAIApiKey",
    description="OpenAI API key для транскрипции и извлечения фич (sk-...)",
    auto_error=False,
)

_setup_token_header = APIKeyHeader(
    name="X-Setup-Token",
    scheme_name="SetupToken",
    description="Admin setup token for server-side integration provisioning",
    auto_error=False,
)

_authorization_header = APIKeyHeader(
    name="Authorization",
    scheme_name="BearerToken",
    description="Bearer access token from /api/auth/login",
    auto_error=False,
)

# ---------------------------------------------------------------------------

app = FastAPI(
    title="Bitrix Ingest API",
    version="0.2.0",
    description=(
        "Bitrix24 экспорт и OpenAI-пайплайн в одном интерфейсе.\n\n"
        "Нажмите **Authorize** и укажите:\n"
        "- `X-Webhook-Url` — для CRM / звонков\n"
        "- `X-Whatsapp-Webhook-Url` — для WhatsApp\n"
        "- `X-OpenAI-Api-Key` — для транскрипции и извлечения фич\n\n"
        "Передайте заголовок `X-Tenant-Id` (например `sapaplast`) для изоляции данных клиента.\n"
        "Если заголовок не передан, используется tenant `default`."
    ),
    swagger_ui_parameters={"persistAuthorization": True},
)
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https://([A-Za-z0-9-]+\.)*bitrix24\.[A-Za-z.]+$|^https://vendors\.bitrix24\.ru$",
    allow_methods=["GET", "POST", "HEAD", "OPTIONS"],
    allow_headers=["*"],
)

_DB_PATH = Path(os.environ.get("BITRIX_DB_PATH", "data/app.db"))

_EXECUTIVE_REPORT_JOBS: dict[str, dict[str, Any]] = {}
_EXECUTIVE_REPORT_JOBS_LOCK = threading.Lock()
_SALES_ANALYTICS_JOBS: dict[str, dict[str, Any]] = {}
_SALES_ANALYTICS_JOBS_LOCK = threading.Lock()
_SALES_AUDIT_JOBS: dict[str, dict[str, Any]] = {}
_SALES_AUDIT_JOBS_LOCK = threading.Lock()
_TENANT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.+@-]{3,128}$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^[0-9+().\-\s]{5,32}$")
_BITRIX_DOMAIN_RE = re.compile(r"^[A-Za-z0-9.-]+(?::[0-9]{1,5})?$")
_ROLE_VALUES = {"admin", "client"}
_AUTH_CONTEXT: contextvars.ContextVar[User | None] = contextvars.ContextVar(
    "auth_user",
    default=None,
)


# ---------------------------------------------------------------------------
# Repository factories
# ---------------------------------------------------------------------------


def _tenant_repo() -> TenantRepository:
    return TenantRepository(_DB_PATH)


def _profile_repo(tenant_id: str = "default") -> BusinessProfileRepository:
    return BusinessProfileRepository(_DB_PATH, tenant_id)


def _integrations_repo(tenant_id: str = "default") -> IntegrationsRepository:
    return IntegrationsRepository(_DB_PATH, tenant_id)


def _bitrix_oauth_repo() -> BitrixOAuthRepository:
    return BitrixOAuthRepository(_DB_PATH)


def _bitrix_connect_session_repo() -> BitrixConnectSessionRepository:
    return BitrixConnectSessionRepository(_DB_PATH)


def _client_registration_repo() -> ClientRegistrationRepository:
    return ClientRegistrationRepository(_DB_PATH)


def _runs_repo() -> AnalysisRunRepository:
    return AnalysisRunRepository(_DB_PATH)


def _sales_repo() -> SalesAnalyticsRepository:
    try:
        return SalesAnalyticsRepository(_DB_PATH)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _user_repo() -> UserRepository:
    return UserRepository(_DB_PATH)


def _get_integrations(tenant_id: str = "default") -> Integrations:
    return _integrations_repo(tenant_id).get() or Integrations()


def _flag_enabled(*names: str) -> bool:
    for name in names:
        value = os.environ.get(name, "").strip().lower()
        if value in {"1", "true", "yes", "on"}:
            return True
    return False


def _auth_required() -> bool:
    return _flag_enabled("AI_AUDITOR_AUTH_REQUIRED", "AUTH_REQUIRED")


def _auth_secret() -> str:
    secret = (
        os.environ.get("AI_AUDITOR_AUTH_SECRET", "").strip()
        or os.environ.get("AUTH_SECRET", "").strip()
    )
    if not secret:
        if _auth_required():
            raise HTTPException(
                status_code=503,
                detail="AI_AUDITOR_AUTH_SECRET is not configured on the backend.",
            )
        return "dev-only-ai-auditor-auth-secret"
    return secret


def _token_ttl_seconds() -> int:
    raw = os.environ.get("AI_AUDITOR_AUTH_TOKEN_TTL_SECONDS", "").strip()
    try:
        ttl = int(raw or "86400")
    except ValueError:
        ttl = 86400
    return max(300, ttl)


def _bitrix_oauth_client_id() -> str:
    return os.environ.get("BITRIX_OAUTH_CLIENT_ID", "").strip()


def _bitrix_oauth_client_secret() -> str:
    return os.environ.get("BITRIX_OAUTH_CLIENT_SECRET", "").strip()


def _bitrix_oauth_token_endpoint() -> str:
    return (
        os.environ.get("BITRIX_OAUTH_TOKEN_ENDPOINT", "").strip()
        or "https://oauth.bitrix.info/oauth/token/"
    )


def _bitrix_oauth_default_return_url() -> str:
    return os.environ.get("BITRIX_OAUTH_SUCCESS_RETURN_URL", "").strip()


def _public_base_url() -> str:
    return (
        os.environ.get("AI_AUDITOR_PUBLIC_BASE_URL", "").strip()
        or os.environ.get("BITRIX_OAUTH_PUBLIC_BASE_URL", "").strip()
    ).rstrip("/")


def _bitrix_oauth_settings_redirect() -> str:
    return os.environ.get("BITRIX_OAUTH_SETTINGS_REDIRECT", "").strip() or "/"


def _bitrix_oauth_state_ttl_seconds() -> int:
    raw = os.environ.get("BITRIX_OAUTH_STATE_TTL_SECONDS", "").strip()
    try:
        ttl = int(raw or "1200")
    except ValueError:
        ttl = 1200
    return max(60, ttl)


def _bitrix_connect_session_ttl_seconds() -> int:
    raw = os.environ.get("BITRIX_CONNECT_SESSION_TTL_SECONDS", "").strip()
    try:
        ttl = int(raw or "86400")
    except ValueError:
        ttl = 86400
    return max(300, ttl)


def _job_stale_seconds() -> int:
    raw = os.environ.get("AI_AUDITOR_JOB_STALE_SECONDS", "").strip()
    try:
        ttl = int(raw or "7200")
    except ValueError:
        ttl = 7200
    return max(300, ttl)


def _b64_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _hash_password(password: str, salt: str | None = None) -> str:
    if not password:
        raise HTTPException(status_code=422, detail="Password cannot be empty.")
    rounds = 260_000
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), rounds)
    return f"pbkdf2_sha256${rounds}${salt}${_b64_encode(digest)}"


def _verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, rounds_raw, salt, digest = password_hash.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        rounds = int(rounds_raw)
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            rounds,
        )
        return hmac.compare_digest(_b64_encode(actual), digest)
    except Exception:
        return False


def _create_access_token(user: User) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    payload = {
        "sub": user.username,
        "tenant_id": user.tenant_id,
        "role": user.role,
        "iat": now,
        "exp": now + _token_ttl_seconds(),
    }
    signing_input = ".".join(
        (
            _b64_encode(json.dumps(header, separators=(",", ":")).encode("utf-8")),
            _b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
        )
    )
    signature = hmac.new(
        _auth_secret().encode("utf-8"),
        signing_input.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{signing_input}.{_b64_encode(signature)}"


def _decode_access_token(token: str) -> User:
    credentials_error = HTTPException(status_code=401, detail="Invalid or expired auth token.")
    try:
        header_b64, payload_b64, signature_b64 = token.split(".", 2)
        signing_input = f"{header_b64}.{payload_b64}"
        expected_signature = hmac.new(
            _auth_secret().encode("utf-8"),
            signing_input.encode("ascii"),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(_b64_encode(expected_signature), signature_b64):
            raise credentials_error
        payload = json.loads(_b64_decode(payload_b64).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            raise credentials_error
        username = str(payload.get("sub") or "").strip()
    except HTTPException:
        raise
    except Exception as exc:
        raise credentials_error from exc

    user = _user_repo().get(username)
    if not user or not user.active:
        raise credentials_error
    return user


def _bearer_token(authorization: str | None) -> str | None:
    value = (authorization or "").strip()
    if not value:
        return None
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return None


def _current_user() -> User | None:
    return _AUTH_CONTEXT.get()


def _require_user() -> User:
    user = _current_user()
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def _require_admin_or_dev() -> User | None:
    user = _current_user()
    if not user:
        if _auth_required():
            raise HTTPException(status_code=401, detail="Authentication required.")
        return None
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin role required.")
    return user


def _public_auth_path(path: str) -> bool:
    return (
        path in {
            "/health",
            "/openapi.json",
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/status",
            "/api/auth/bootstrap",
        }
        or path.startswith("/api/bitrix/")
        or path.startswith("/docs")
        or path.startswith("/redoc")
    )


def _validate_tenant_id(tid: str) -> None:
    if not _TENANT_ID_RE.fullmatch(tid):
        raise HTTPException(
            status_code=422,
            detail="Invalid X-Tenant-Id. Use 1-64 characters: letters, digits, underscore, hyphen.",
        )


def _resolve_tenant_id(x_tenant_id: str | None) -> str:
    """Resolve tenant from auth token; X-Tenant-Id is allowed only for admins/dev."""
    user = _current_user()
    requested = (x_tenant_id or "").strip()
    if user:
        if user.is_admin:
            tid = requested or user.tenant_id or "default"
        else:
            if requested and requested != user.tenant_id:
                raise HTTPException(status_code=403, detail="Tenant access denied.")
            tid = user.tenant_id
    else:
        if _auth_required():
            raise HTTPException(status_code=401, detail="Authentication required.")
        tid = requested or "default"
    _validate_tenant_id(tid)
    _tenant_repo().ensure(tid)
    return tid


def _ensure_tenant_access(tenant_id: str) -> str:
    _validate_tenant_id(tenant_id)
    user = _current_user()
    if user and not user.is_admin and tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Tenant access denied.")
    if not user and _auth_required():
        raise HTTPException(status_code=401, detail="Authentication required.")
    return tenant_id


def _tenant_storage(tenant_id: str, run_id: str) -> Path:
    return Path(f"storage/tenants/{tenant_id}/runs/{run_id}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _none(value: str | None) -> str | None:
    """Treat form strings 'null', 'none', '' as None."""
    if not value or value.strip().lower() in ("null", "none"):
        return None
    return value


def _resolve_webhook(header_url: str | None, tenant_id: str = "default") -> str:
    """Header takes priority; falls back to DB bitrix_webhook_url for the tenant."""
    url = header_url or _get_integrations(tenant_id).bitrix_webhook_url
    if not url:
        raise HTTPException(
            status_code=422,
            detail="Webhook URL не настроен. Укажите X-Webhook-Url в Authorize или сохраните его на странице настроек.",
        )
    return url


def _resolve_whatsapp_webhook(
    header_url: str | None,
    crm_fallback: str | None = None,
    tenant_id: str = "default",
) -> str:
    """Header → DB whatsapp_webhook_url → DB bitrix_webhook_url → crm_fallback."""
    if header_url:
        return header_url
    ints = _get_integrations(tenant_id)
    url = ints.whatsapp_webhook_url or ints.bitrix_webhook_url or crm_fallback
    if not url:
        raise HTTPException(
            status_code=422,
            detail="WhatsApp Webhook URL не настроен. Укажите X-Whatsapp-Webhook-Url в Authorize или сохраните его на странице настроек.",
        )
    return url


def _active_bitrix_oauth_token(tenant_id: str) -> BitrixOAuthToken | None:
    token = _bitrix_oauth_repo().get_by_tenant(tenant_id)
    if token and token.status == "active":
        return token
    return None


def _parse_bitrix_oauth_scopes(scope: str) -> set[str]:
    return {
        item.strip().lower()
        for item in re.split(r"[,\s]+", scope or "")
        if item.strip()
    }


def _missing_bitrix_oauth_scopes(scope: str) -> list[str]:
    granted = _parse_bitrix_oauth_scopes(scope)
    return [item for item in _REQUIRED_BITRIX_OAUTH_SCOPES if item not in granted]


def _bitrix_oauth_scope_error(missing_scopes: list[str]) -> str:
    return "Недостаточно прав Bitrix: отсутствует " + ", ".join(missing_scopes)


def _bitrix_oauth_status(token: BitrixOAuthToken | None) -> dict[str, Any]:
    if token is None:
        return {
            "configured": False,
            "required_scopes": list(_REQUIRED_BITRIX_OAUTH_SCOPES),
            "missing_scopes": list(_REQUIRED_BITRIX_OAUTH_SCOPES),
            "has_required_scopes": False,
        }
    status = token.to_status_dict()
    missing = _missing_bitrix_oauth_scopes(token.scope)
    status.update(
        {
            "required_scopes": list(_REQUIRED_BITRIX_OAUTH_SCOPES),
            "missing_scopes": missing,
            "has_required_scopes": not missing,
        }
    )
    if missing:
        status["configuration_error"] = _bitrix_oauth_scope_error(missing)
    return status


def _ensure_bitrix_oauth_required_scopes(token: BitrixOAuthToken) -> None:
    missing = _missing_bitrix_oauth_scopes(token.scope)
    if not missing:
        return
    raise HTTPException(
        status_code=422,
        detail={
            "message": _bitrix_oauth_scope_error(missing),
            "missing_scopes": missing,
            "required_scopes": list(_REQUIRED_BITRIX_OAUTH_SCOPES),
            "bitrix_domain": token.bitrix_domain,
        },
    )


def _bitrix_oauth_client(
    tenant_id: str,
    *,
    call_delay: float = 0.0,
    page_delay: float = 0.0,
    trace: AuditTraceRecorder | None = None,
    trace_name: str = "bitrix.oauth",
) -> BitrixOAuthClient:
    return BitrixOAuthClient(
        tenant_id,
        _bitrix_oauth_repo(),
        call_delay=call_delay,
        page_delay=page_delay,
        trace=trace,
        trace_name=trace_name,
    )


def _resolve_bitrix_gateway(
    header_url: str | None,
    tenant_id: str = "default",
    *,
    call_delay: float = 0.0,
    page_delay: float = 0.0,
    trace: AuditTraceRecorder | None = None,
    trace_name: str = "bitrix",
) -> Any:
    """Resolve CRM Bitrix gateway: request webhook -> OAuth -> stored webhook."""
    if header_url:
        return BitrixClient(
            header_url,
            call_delay=call_delay,
            page_delay=page_delay,
            trace=trace,
            trace_name=trace_name,
        )
    oauth_token = _active_bitrix_oauth_token(tenant_id)
    if oauth_token:
        _ensure_bitrix_oauth_required_scopes(oauth_token)
        return _bitrix_oauth_client(
            tenant_id,
            call_delay=call_delay,
            page_delay=page_delay,
            trace=trace,
            trace_name=f"{trace_name}.oauth" if not trace_name.endswith(".oauth") else trace_name,
        )
    webhook_url = _get_integrations(tenant_id).bitrix_webhook_url
    if webhook_url:
        return BitrixClient(
            webhook_url,
            call_delay=call_delay,
            page_delay=page_delay,
            trace=trace,
            trace_name=trace_name,
        )
    raise HTTPException(
        status_code=422,
        detail=(
            "Bitrix integration is not configured. Connect Bitrix24 via OAuth "
            "or configure a Bitrix webhook for this tenant."
        ),
    )


def _portal_base_from_bitrix_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    domain = (parsed.netloc or parsed.path).split("/", 1)[0].strip()
    if not domain:
        return ""
    return f"https://{_normalize_bitrix_domain(domain)}"


def _resolve_portal_base_url(
    portal_base_url: str | None,
    tenant_id: str,
    crm_webhook_url: str | None = None,
) -> str:
    """Resolve the Bitrix portal used for CRM links for the current tenant."""
    explicit = _none(portal_base_url)
    if explicit:
        return _portal_base_from_bitrix_url(explicit)

    oauth_token = _active_bitrix_oauth_token(tenant_id)
    if oauth_token and oauth_token.bitrix_domain:
        return f"https://{_normalize_bitrix_domain(oauth_token.bitrix_domain)}"

    integrations = _get_integrations(tenant_id)
    webhook_url = _none(crm_webhook_url) or integrations.bitrix_webhook_url
    if webhook_url:
        return _portal_base_from_bitrix_url(webhook_url)

    return ""


def _resolve_whatsapp_gateway(
    header_url: str | None,
    tenant_id: str = "default",
    *,
    crm_fallback: str | None = None,
    call_delay: float = 0.0,
    page_delay: float = 0.0,
    trace: AuditTraceRecorder | None = None,
    trace_name: str = "bitrix.whatsapp",
) -> Any:
    """Resolve WhatsApp/Open Lines gateway: request webhook -> stored WhatsApp webhook -> OAuth -> CRM webhook."""
    if header_url:
        return BitrixClient(
            header_url,
            call_delay=call_delay,
            page_delay=page_delay,
            trace=trace,
            trace_name=trace_name,
        )
    ints = _get_integrations(tenant_id)
    if ints.whatsapp_webhook_url:
        return BitrixClient(
            ints.whatsapp_webhook_url,
            call_delay=call_delay,
            page_delay=page_delay,
            trace=trace,
            trace_name=trace_name,
        )
    oauth_token = _active_bitrix_oauth_token(tenant_id)
    if oauth_token:
        _ensure_bitrix_oauth_required_scopes(oauth_token)
        return _bitrix_oauth_client(
            tenant_id,
            call_delay=call_delay,
            page_delay=page_delay,
            trace=trace,
            trace_name=f"{trace_name}.oauth" if not trace_name.endswith(".oauth") else trace_name,
        )
    fallback_url = ints.bitrix_webhook_url or crm_fallback
    if fallback_url:
        return BitrixClient(
            fallback_url,
            call_delay=call_delay,
            page_delay=page_delay,
            trace=trace,
            trace_name=trace_name,
        )
    raise HTTPException(
        status_code=422,
        detail=(
            "Bitrix WhatsApp integration is not configured. Connect Bitrix24 via OAuth "
            "or configure a WhatsApp/CRM webhook for this tenant."
        ),
    )


def _global_openai_key() -> str:
    return (
        os.environ.get("OPENAI_API_KEY", "").strip()
        or os.environ.get("AI_AUDITOR_OPENAI_API_KEY", "").strip()
    )


def _integrations_status(integrations: Integrations) -> dict[str, bool]:
    status = integrations.to_status_dict()
    if _global_openai_key():
        status["openai_api_key_configured"] = True
    return status


def _resolve_openai_key(header_key: str | None, tenant_id: str = "default") -> str:
    """Header takes priority; falls back to tenant DB key and then server env."""
    key = (
        (header_key or "").strip()
        or _get_integrations(tenant_id).openai_api_key
        or _global_openai_key()
    )
    if not key:
        raise HTTPException(
            status_code=422,
            detail=(
                "OpenAI API Key не настроен. Укажите X-OpenAI-Api-Key в Authorize, "
                "сохраните его на странице настроек или задайте OPENAI_API_KEY на сервере."
            ),
        )
    return key


def _require_setup_token(header_token: str | None) -> None:
    expected = os.environ.get("SETUP_INTEGRATIONS_TOKEN", "").strip()
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="SETUP_INTEGRATIONS_TOKEN is not configured on the backend.",
        )
    if header_token != expected:
        raise HTTPException(status_code=403, detail="Invalid setup token.")


def _normalize_bitrix_domain(portal: str) -> str:
    value = (portal or "").strip()
    if not value:
        raise HTTPException(status_code=422, detail="Bitrix portal domain is required.")
    parsed = urlparse(value if "://" in value else f"https://{value}")
    domain = (parsed.netloc or parsed.path).split("/", 1)[0].strip().lower()
    if not domain or not _BITRIX_DOMAIN_RE.fullmatch(domain):
        raise HTTPException(status_code=422, detail="Invalid Bitrix portal domain.")
    return domain


def _safe_relative_return_url(value: str | None) -> str:
    url = (value or "").strip() or _bitrix_oauth_default_return_url()
    if not url:
        return ""
    if not url.startswith("/") or url.startswith("//"):
        raise HTTPException(status_code=422, detail="OAuth return_url must be a relative URL.")
    return url


def _create_bitrix_oauth_state(portal: str, return_url: str = "", tenant_id: str = "") -> str:
    payload = {
        "portal": portal,
        "return_url": return_url,
        "iat": int(time.time()),
        "nonce": secrets.token_urlsafe(16),
    }
    if tenant_id:
        _validate_tenant_id(tenant_id)
        payload["tenant_id"] = tenant_id
    body = _b64_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(_auth_secret().encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
    return f"{body}.{_b64_encode(signature)}"


def _decode_bitrix_oauth_state(state: str | None) -> dict[str, Any]:
    if not state:
        raise HTTPException(status_code=400, detail="OAuth state is required.")
    try:
        body, signature = state.split(".", 1)
        expected = hmac.new(_auth_secret().encode("utf-8"), body.encode("ascii"), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64_encode(expected), signature):
            raise HTTPException(status_code=400, detail="Invalid OAuth state.")
        payload = json.loads(_b64_decode(body).decode("utf-8"))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid OAuth state.") from exc

    issued_at = int(payload.get("iat") or 0)
    if issued_at <= 0 or issued_at + _bitrix_oauth_state_ttl_seconds() < int(time.time()):
        raise HTTPException(status_code=400, detail="OAuth state has expired.")
    return payload


def _append_query_params(url: str, params: dict[str, str]) -> str:
    split = urlsplit(url)
    query = dict(parse_qsl(split.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))


_BITRIX_CONNECT_CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"


def _normalize_bitrix_connect_code(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", value or "").upper()


def _format_bitrix_connect_code(value: str) -> str:
    normalized = _normalize_bitrix_connect_code(value)
    return "-".join(normalized[i : i + 4] for i in range(0, len(normalized), 4))


def _new_bitrix_connect_code() -> str:
    repo = _bitrix_connect_session_repo()
    for _ in range(10):
        code = "".join(secrets.choice(_BITRIX_CONNECT_CODE_ALPHABET) for _ in range(12))
        if repo.get_by_code(code) is None:
            return code
    raise HTTPException(status_code=503, detail="Could not allocate Bitrix connection code.")


def _create_bitrix_connect_session(
    *,
    tenant_id: str,
    portal: str,
    return_url: str,
) -> BitrixConnectSession:
    session = BitrixConnectSession(
        connection_code=_new_bitrix_connect_code(),
        tenant_id=tenant_id,
        bitrix_domain=_normalize_bitrix_domain(portal),
        return_url=_safe_relative_return_url(return_url),
        expires_at=int(time.time()) + _bitrix_connect_session_ttl_seconds(),
        status="pending",
    )
    _bitrix_connect_session_repo().save(session)
    return session


def _active_bitrix_connect_session(connection_code: str) -> BitrixConnectSession | None:
    code = _normalize_bitrix_connect_code(connection_code)
    if not code:
        return None
    session = _bitrix_connect_session_repo().get_by_code(code)
    if session is None or session.status != "pending":
        return None
    if session.expires_at <= int(time.time()):
        return None
    return session


def _public_api_url(request: Request, path: str) -> str:
    base = _public_base_url()
    if base:
        return f"{base}{path}"
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",", 1)[0].strip()
    forwarded_host = request.headers.get("x-forwarded-host", "").split(",", 1)[0].strip()
    scheme = forwarded_proto or request.url.scheme
    host = forwarded_host or request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}{path}"


def _build_bitrix_oauth_authorize_url(
    *,
    portal: str,
    return_url: str,
    tenant_id: str,
) -> dict[str, str]:
    client_id = _bitrix_oauth_client_id()
    if not client_id:
        raise HTTPException(status_code=503, detail="BITRIX_OAUTH_CLIENT_ID is not configured.")
    domain = _normalize_bitrix_domain(portal)
    safe_return_url = _safe_relative_return_url(return_url)
    state = _create_bitrix_oauth_state(domain, safe_return_url, tenant_id=tenant_id)
    authorize_url = f"https://{domain}/oauth/authorize/?" + urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "state": state,
        }
    )
    return {
        "authorize_url": authorize_url,
        "portal": domain,
        "return_url": safe_return_url,
    }


async def _bitrix_request_payload(request: Request) -> dict[str, Any]:
    content_type = request.headers.get("content-type", "").lower()
    if "application/json" in content_type:
        try:
            data = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON payload.") from exc
        if not isinstance(data, dict):
            raise HTTPException(status_code=422, detail="Bitrix payload must be an object.")
        return data

    form = await request.form()
    data: dict[str, Any] = {}
    for key, value in form.multi_items():
        str_value = str(value)
        match = re.fullmatch(r"([A-Za-z0-9_]+)\[([A-Za-z0-9_]+)\]", str(key))
        if match:
            group, nested_key = match.groups()
            nested = data.setdefault(group, {})
            if isinstance(nested, dict):
                nested[nested_key] = str_value
        else:
            data[str(key)] = str_value
    return data


def _extract_bitrix_auth_payload(payload: dict[str, Any]) -> dict[str, Any]:
    auth = payload.get("auth")
    if isinstance(auth, dict):
        merged = {
            key: payload[key]
            for key in (
                "DOMAIN",
                "PROTOCOL",
                "member_id",
                "scope",
                "application_token",
            )
            if key in payload
        }
        merged.update(auth)
        return merged
    if any(key in payload for key in ("AUTH_ID", "REFRESH_ID", "access_token", "refresh_token")):
        return payload
    raise HTTPException(status_code=422, detail="Bitrix auth payload is missing.")


def _tenant_id_from_bitrix_member_id(member_id: str) -> str:
    tenant_id = re.sub(r"[^A-Za-z0-9_-]+", "-", member_id.strip()).strip("-_")[:64]
    if not tenant_id:
        raise HTTPException(status_code=422, detail="Bitrix member_id is invalid.")
    _validate_tenant_id(tenant_id)
    return tenant_id


def _oauth_expires_at(auth: dict[str, Any]) -> int:
    expires = auth.get("expires")
    if expires not in (None, ""):
        return int(expires)
    expires_in = auth.get("expires_in") or auth.get("AUTH_EXPIRES")
    if expires_in not in (None, ""):
        return int(time.time()) + int(expires_in)
    return 0


def _client_endpoint_from_auth(auth: dict[str, Any], domain: str) -> str:
    endpoint = str(auth.get("client_endpoint") or "").strip()
    if endpoint:
        return endpoint if endpoint.endswith("/") else f"{endpoint}/"
    protocol = str(auth.get("PROTOCOL") or "1").strip()
    scheme = "http" if protocol == "0" else "https"
    return f"{scheme}://{domain}/rest/"


def _domain_from_auth(auth: dict[str, Any], fallback_domain: str = "") -> str:
    raw_domain = str(auth.get("DOMAIN") or auth.get("domain") or fallback_domain or "").strip()
    if raw_domain and not raw_domain.startswith("oauth."):
        return _normalize_bitrix_domain(raw_domain)
    endpoint = str(auth.get("client_endpoint") or "").strip()
    if endpoint:
        parsed = urlparse(endpoint)
        if parsed.netloc:
            return _normalize_bitrix_domain(parsed.netloc)
    return _normalize_bitrix_domain(fallback_domain)


def _verify_bitrix_application_token(auth: dict[str, Any]) -> None:
    expected = os.environ.get("BITRIX_APPLICATION_TOKEN", "").strip()
    if not expected:
        return
    actual = str(auth.get("application_token") or "").strip()
    if not hmac.compare_digest(actual, expected):
        raise HTTPException(status_code=403, detail="Invalid Bitrix application token.")


def _resolve_bitrix_oauth_scope(auth: dict[str, Any], fallback_scope: str = "") -> str:
    scope = str(auth.get("scope") or "").strip()
    fallback = str(fallback_scope or "").strip()
    if fallback and (not scope or scope.lower() == "app"):
        return fallback
    return scope or fallback


def _save_bitrix_oauth_token(
    auth: dict[str, Any],
    *,
    fallback_domain: str = "",
    fallback_scope: str = "",
    tenant_id: str = "",
) -> BitrixOAuthToken:
    access_token = str(auth.get("access_token") or auth.get("AUTH_ID") or "").strip()
    refresh_token = str(auth.get("refresh_token") or auth.get("REFRESH_ID") or "").strip()
    member_id = str(auth.get("member_id") or "").strip()
    if not access_token or not refresh_token or not member_id:
        raise HTTPException(
            status_code=422,
            detail="Bitrix OAuth payload must include access_token, refresh_token, and member_id.",
        )

    domain = _domain_from_auth(auth, fallback_domain=fallback_domain)
    repo = _bitrix_oauth_repo()
    existing = repo.get_by_member_id(member_id)
    requested_tenant_id = tenant_id.strip()
    resolved_tenant_id = (
        requested_tenant_id
        or (existing.tenant_id if existing else "")
        or _tenant_id_from_bitrix_member_id(member_id)
    )
    _validate_tenant_id(resolved_tenant_id)
    if requested_tenant_id or existing:
        _tenant_repo().ensure(resolved_tenant_id)
    else:
        _tenant_repo().save(Tenant(id=resolved_tenant_id, name=domain or resolved_tenant_id))

    if existing and existing.tenant_id != resolved_tenant_id:
        repo.delete_by_tenant(existing.tenant_id)

    token = BitrixOAuthToken(
        tenant_id=resolved_tenant_id,
        bitrix_member_id=member_id,
        bitrix_domain=domain,
        client_endpoint=_client_endpoint_from_auth(auth, domain),
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=_oauth_expires_at(auth),
        scope=_resolve_bitrix_oauth_scope(auth, fallback_scope=fallback_scope),
        status="active",
    )
    repo.save(token)
    return token


def _request_bitrix_oauth_token(params: dict[str, str]) -> dict[str, Any]:
    try:
        response = requests.get(
            _bitrix_oauth_token_endpoint(),
            params=params,
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
    except requests.HTTPError as exc:
        status_code = exc.response.status_code if exc.response is not None else None
        body = exc.response.text if exc.response is not None else None
        raise HTTPException(
            status_code=502,
            detail={
                "message": "Bitrix OAuth token exchange failed.",
                "status_code": status_code,
                "response_body": body,
            },
        ) from exc
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=f"Bitrix OAuth token exchange failed: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Bitrix OAuth token response is not valid JSON.") from exc

    if not isinstance(data, dict):
        raise HTTPException(status_code=502, detail="Bitrix OAuth token response must be an object.")
    if data.get("error"):
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Bitrix OAuth authorization failed.",
                "error": data.get("error"),
                "error_description": data.get("error_description"),
            },
        )
    return data


def _tee() -> tuple[TeeJsonSink, InMemoryJsonSink]:
    mem = InMemoryJsonSink()
    return TeeJsonSink(primary=FileSystemJsonWriter(), secondary=mem), mem


def _run_service(fn: Any, mem: InMemoryJsonSink) -> dict[str, Any]:
    try:
        fn()
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DomainError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"status": "ok", "data": mem.data}


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def _parse_datetime(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_stale_timestamp(value: object) -> bool:
    parsed = _parse_datetime(value)
    if parsed is None:
        return False
    age_seconds = (datetime.now(tz=timezone.utc) - parsed).total_seconds()
    return age_seconds > _job_stale_seconds()


def _job_reference_time(job: dict[str, Any]) -> object:
    return (
        job.get("started_at")
        or job.get("queued_at")
        or job.get("created_at")
        or job.get("updated_at")
    )


def _stale_job_error(job_kind: str) -> str:
    minutes = round(_job_stale_seconds() / 60)
    return (
        f"{job_kind} did not finish within {minutes} minutes. "
        "It was marked as failed so a new report can be started."
    )


def _maybe_expire_memory_job(
    job: dict[str, Any],
    *,
    job_kind: str,
    set_job: Any,
) -> dict[str, Any]:
    if str(job.get("status") or "").lower() not in {"queued", "running", "started"}:
        return job
    if not _is_stale_timestamp(_job_reference_time(job)):
        return job

    error = _stale_job_error(job_kind)
    set_job(
        str(job.get("job_id") or ""),
        status="error",
        completed_at=_now_iso(),
        error=error,
        error_type="StaleJobTimeout",
    )
    expired = {
        **job,
        "status": "error",
        "completed_at": _now_iso(),
        "error": error,
        "error_type": "StaleJobTimeout",
    }
    logger.warning("Marked stale %s job as error: %s", job_kind, job.get("job_id"))
    return expired


def _maybe_expire_persisted_run(
    run: AnalysisRun,
    *,
    job_kind: str,
    set_job: Any,
) -> dict[str, Any]:
    if run.status.lower() not in {"queued", "running", "started"}:
        return run.to_dict()
    if not _is_stale_timestamp(run.created_at):
        return run.to_dict()

    error = _stale_job_error(job_kind)
    set_job(
        run.run_id,
        tenant_id=run.tenant_id,
        output_dir=run.output_dir,
        status="error",
        completed_at=_now_iso(),
        error=error,
        error_type="StaleJobTimeout",
    )
    result = run.to_dict()
    result.update(
        {
            "status": "error",
            "completed_at": _now_iso(),
            "error": error,
            "error_type": "StaleJobTimeout",
        }
    )
    logger.warning("Marked stale persisted %s run as error: %s", job_kind, run.run_id)
    return result


def _clean_form_list(values: list[str] | None) -> list[str] | None:
    clean = [item for item in (values or []) if _none(item)]
    return clean or None


def _set_executive_report_job(job_id: str, **updates: Any) -> None:
    with _EXECUTIVE_REPORT_JOBS_LOCK:
        job = _EXECUTIVE_REPORT_JOBS.setdefault(job_id, {"job_id": job_id})
        job.update(updates)
        job["updated_at"] = _now_iso()
    if "status" in updates:
        try:
            _runs_repo().update_status(
                run_id=job_id,
                status=updates["status"],
                completed_at=updates.get("completed_at"),
                error=updates.get("error"),
            )
        except Exception:
            logger.warning("Failed to persist run status to database: %s", job_id)


def _get_executive_report_job(job_id: str) -> dict[str, Any] | None:
    with _EXECUTIVE_REPORT_JOBS_LOCK:
        job = _EXECUTIVE_REPORT_JOBS.get(job_id)
        return dict(job) if job else None


def _set_sales_analytics_job(job_id: str, **updates: Any) -> None:
    with _SALES_ANALYTICS_JOBS_LOCK:
        job = _SALES_ANALYTICS_JOBS.setdefault(job_id, {"job_id": job_id})
        job.update(updates)
        job["updated_at"] = _now_iso()
    if "status" in updates:
        try:
            _runs_repo().update_status(
                run_id=job_id,
                status=updates["status"],
                completed_at=updates.get("completed_at"),
                error=updates.get("error"),
            )
        except Exception:
            logger.warning("Failed to persist sales analytics run status: %s", job_id)


def _get_sales_analytics_job(job_id: str) -> dict[str, Any] | None:
    with _SALES_ANALYTICS_JOBS_LOCK:
        job = _SALES_ANALYTICS_JOBS.get(job_id)
        return dict(job) if job else None


def _set_sales_audit_job(job_id: str, **updates: Any) -> None:
    progress_payload = updates.pop("progress", None)
    progress = _normalise_progress(progress_payload) if progress_payload is not None else None
    with _SALES_AUDIT_JOBS_LOCK:
        job = _SALES_AUDIT_JOBS.setdefault(job_id, {"job_id": job_id})
        if progress is not None:
            job["progress"] = progress
            job.update(_progress_flat_fields(progress))
        job.update(updates)
        job["updated_at"] = _now_iso()
    if progress is not None:
        try:
            _runs_repo().update_progress(
                run_id=job_id,
                stage=progress["stage"],
                label=progress["label"],
                current=progress["current"],
                total=progress["total"],
                percent=progress["percent"],
                message=progress["message"],
                eta_seconds=progress["eta_seconds"],
                updated_at=progress["updated_at"],
            )
        except Exception:
            logger.warning("Failed to persist sales audit run progress: %s", job_id)
    if "status" in updates:
        try:
            _runs_repo().update_status(
                run_id=job_id,
                status=updates["status"],
                completed_at=updates.get("completed_at"),
                error=updates.get("error"),
            )
        except Exception:
            logger.warning("Failed to persist sales audit run status: %s", job_id)


def _get_sales_audit_job(job_id: str) -> dict[str, Any] | None:
    with _SALES_AUDIT_JOBS_LOCK:
        job = _SALES_AUDIT_JOBS.get(job_id)
        return dict(job) if job else None


def _load_json_if_exists(path: Path) -> Any | None:
    if not path.exists() or not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _redact_error_message(message: object, *secrets: str | None) -> str:
    text = str(message)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[redacted]")
    return text


class _SalesAuditProgressReporter:
    def __init__(self, job_id: str) -> None:
        self._job_id = job_id
        self._started_at = time.monotonic()
        self._last_percent = 0.0

    def __call__(self, event: dict[str, Any]) -> None:
        raw_percent = _coerce_float(event.get("percent"), default=self._last_percent)
        if raw_percent >= 100:
            percent = 100.0
        else:
            percent = max(self._last_percent, min(99.0, raw_percent))
        self._last_percent = percent
        eta_seconds = event.get("eta_seconds")
        if eta_seconds is None:
            eta_seconds = self._estimate_eta(percent)

        label = str(event.get("stage_label") or event.get("label") or event.get("stage") or "")
        message = str(event.get("message") or label or "Analysis is running")
        _set_sales_audit_job(
            self._job_id,
            progress={
                "stage": str(event.get("stage") or "running"),
                "label": label,
                "current": _coerce_int(event.get("current")),
                "total": _coerce_int(event.get("total")),
                "percent": round(percent, 1),
                "message": message,
                "eta_seconds": eta_seconds,
                "updated_at": _now_iso(),
            },
        )

    def complete(self) -> None:
        self(
            {
                "stage": "completed",
                "stage_label": "Отчёт готов",
                "current": 1,
                "total": 1,
                "percent": 100,
                "message": "Отчёт готов",
                "eta_seconds": 0,
            }
        )

    def fail(self) -> None:
        self(
            {
                "stage": "error",
                "stage_label": "Ошибка",
                "current": 0,
                "total": 1,
                "percent": self._last_percent,
                "message": "Анализ завершился ошибкой",
            }
        )

    def _estimate_eta(self, percent: float) -> int | None:
        if percent <= 0:
            return None
        if percent >= 100:
            return 0
        elapsed = max(0.0, time.monotonic() - self._started_at)
        estimated_total = elapsed / (percent / 100)
        return max(0, int(round(estimated_total - elapsed)))


def _coerce_int(value: object, default: int = 0) -> int:
    try:
        return int(value if value is not None else default)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value if value is not None else default)
    except (TypeError, ValueError):
        return default


def _normalise_progress(progress: Any) -> dict[str, Any]:
    payload = progress if isinstance(progress, dict) else {}
    eta = payload.get("eta_seconds")
    return {
        "stage": str(payload.get("stage") or ""),
        "label": str(payload.get("label") or ""),
        "current": max(0, _coerce_int(payload.get("current"))),
        "total": max(0, _coerce_int(payload.get("total"))),
        "percent": max(0.0, min(100.0, _coerce_float(payload.get("percent")))),
        "message": str(payload.get("message") or ""),
        "eta_seconds": None if eta is None else max(0, _coerce_int(eta)),
        "updated_at": str(payload.get("updated_at") or _now_iso()),
    }


def _progress_flat_fields(progress: dict[str, Any]) -> dict[str, Any]:
    return {
        "progress_stage": progress["stage"],
        "progress_label": progress["label"],
        "progress_current": progress["current"],
        "progress_total": progress["total"],
        "progress_percent": progress["percent"],
        "progress_message": progress["message"],
        "eta_seconds": progress["eta_seconds"],
        "progress_updated_at": progress["updated_at"],
    }


def _execute_executive_pipeline(
    *,
    tenant_id: str,
    request: RunExecutivePipelineRequest,
    crm_webhook_url: str | None,
    whatsapp_webhook_url: str | None,
    openai_key: str,
    sink: Any,
) -> None:
    RunExecutivePipelineService(
        crm_gateway=_resolve_bitrix_gateway(
            crm_webhook_url,
            tenant_id,
            call_delay=0.2,
            page_delay=0.2,
            trace_name="bitrix.crm",
        ),
        whatsapp_gateway=_resolve_whatsapp_gateway(
            whatsapp_webhook_url,
            tenant_id,
            crm_fallback=crm_webhook_url,
            call_delay=0.2,
            page_delay=0.2,
            trace_name="bitrix.whatsapp",
        ),
        responses_gateway=OpenAiResponsesClient(openai_key),
        transcription_gateway=OpenAiTranscriptionClient(openai_key),
        file_downloader=RequestsFileDownloader(),
        sink=sink,
    ).execute(request)


def _run_executive_report_background_job(
    *,
    job_id: str,
    tenant_id: str,
    request: RunExecutivePipelineRequest,
    crm_webhook_url: str | None,
    whatsapp_webhook_url: str | None,
    openai_key: str,
) -> None:
    _set_executive_report_job(job_id, status="running", started_at=_now_iso())
    try:
        _execute_executive_pipeline(
            tenant_id=tenant_id,
            request=request,
            crm_webhook_url=crm_webhook_url,
            whatsapp_webhook_url=whatsapp_webhook_url,
            openai_key=openai_key,
            sink=FileSystemJsonWriter(),
        )
        report_path = request.executive_report_dir / "executive-report.json"
        summary_path = request.executive_report_dir / "pipeline-summary.json"
        _set_executive_report_job(
            job_id,
            status="completed",
            completed_at=_now_iso(),
            report_path=str(report_path),
            summary_path=str(summary_path),
            executive_report=_load_json_if_exists(report_path),
            pipeline_summary=_load_json_if_exists(summary_path),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Executive report job failed: %s", job_id)
        _set_executive_report_job(
            job_id,
            status="error",
            completed_at=_now_iso(),
            error=_redact_error_message(exc, crm_webhook_url, whatsapp_webhook_url, openai_key),
            error_type=type(exc).__name__,
        )


def _sales_analytics_report(tenant_id: str, run_id: str) -> dict[str, Any]:
    report = _sales_repo().build_report(tenant_id=tenant_id, run_id=run_id)
    return {
        **report,
        "storage": "postgres",
        "summary": {
            "meta": report.get("meta") or {},
            "deal_dashboard": report.get("deal_dashboard") or {},
            "task_status": report.get("task_status") or {},
            "lead_status": report.get("lead_status") or {},
            "revenue_summary": report.get("revenue_summary") or {},
            "failure_reasons": report.get("failure_reasons") or {},
        },
    }


def _sales_audit_history_run(
    row: dict[str, Any],
    tenant_id: str,
    run: AnalysisRun | None = None,
) -> dict[str, Any]:
    run_id = str(row.get("run_id") or "")
    summary = row.get("summary") or {}
    scope = summary.get("scope") or {}
    dashboard = (summary.get("deal_dashboard") or {}).get("department") or {}
    task_status = (summary.get("task_status") or {}).get("department") or {}
    rating = summary.get("integral_rating") or {}
    created_at = (
        run.created_at if run else None
    ) or summary.get("generated_at") or row.get("updated_at") or ""
    completed_at = (
        run.completed_at if run else None
    ) or row.get("updated_at") or summary.get("generated_at") or ""
    filters = {
        "period_from": scope.get("date_from") or (run.date_from if run else "") or "",
        "period_to": scope.get("date_to") or (run.date_to if run else "") or "",
        "category_ids": scope.get("category_ids") or (run.category_ids if run else []) or [],
        "responsible_id": scope.get("responsible_id") or "",
        "responsible_ids": scope.get("responsible_ids") or (run.responsible_ids if run else []) or [],
        "channels": ["call", "whatsapp"],
    }
    return {
        "id": run_id,
        "run_id": run_id,
        "tenant_id": run.tenant_id if run else tenant_id,
        "title": "Sales audit report",
        "created_at": created_at,
        "completed_at": completed_at,
        "updated_at": row.get("updated_at") or "",
        "source": "sales_audit_report",
        "scope_label": "AI + Postgres sales audit",
        "filters": filters,
        "status": run.status if run else "completed",
        "report_url": f"/sales-audit/report?run_id={run_id}",
        "metric_snapshot": {
            "score_10": rating.get("score_10"),
            "score_pct": rating.get("score_pct"),
            "total_deals": dashboard.get("total_deals"),
            "in_work_deals": dashboard.get("in_work_count"),
            "won_deals": dashboard.get("won_count"),
            "lost_deals": dashboard.get("failed_count"),
            "deals_without_tasks": task_status.get("without_open_tasks"),
            "deals_with_overdue_tasks": task_status.get("with_overdue_tasks"),
        },
    }


def _get_sales_audit_report_payload(tenant_id: str, run_id: str | None = None) -> tuple[str, dict[str, Any]]:
    sales_repo = _sales_repo()
    resolved_run_id = _none(run_id)
    if not resolved_run_id:
        reports = sales_repo.list_sales_audit_reports(tenant_id=tenant_id, limit=1)
        if not reports:
            raise HTTPException(
                status_code=404,
                detail=f"No completed sales audit runs found for tenant '{tenant_id}'.",
            )
        resolved_run_id = str(reports[0].get("run_id") or "")
    report = sales_repo.get_sales_audit_report(tenant_id=tenant_id, run_id=resolved_run_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"Sales audit report not found: {resolved_run_id}")
    return resolved_run_id, _prepare_sales_audit_report_for_frontend(tenant_id, report)


def _prepare_sales_audit_report_for_frontend(tenant_id: str, report: dict[str, Any]) -> dict[str, Any]:
    report = enrich_frontend_manager_names(report)
    report = filter_frontend_sales_audit_in_work_sections(report)
    portal_base_url = ""
    sources = report.get("sales_audit_sources") if isinstance(report, dict) else {}
    if isinstance(sources, dict):
        stored_portal = _none(sources.get("portal_base_url"))
        if stored_portal:
            resolved_stored_portal = _portal_base_from_bitrix_url(stored_portal)
            stored_host = (urlparse(resolved_stored_portal).hostname or "").lower()
            if stored_host != "sapaplast.bitrix24.kz":
                portal_base_url = resolved_stored_portal
    if not portal_base_url:
        portal_base_url = _resolve_portal_base_url("", tenant_id)
    return enrich_frontend_deal_urls(report, portal_base_url)


def _execute_sales_analytics_pipeline(
    *,
    tenant_id: str,
    run_id: str,
    crm_webhook_url: str | None,
    date_from: str,
    date_to: str,
    include_pipeline_reports: bool,
    include_tasks: bool,
    include_leads: bool,
    include_revenue: bool,
    category_ids: list[str] | None = None,
    responsible_ids: list[str] | None = None,
    limit: int = 0,
) -> dict[str, Any]:
    report = ExportSalesAnalyticsService(
        gateway=_resolve_bitrix_gateway(
            crm_webhook_url,
            tenant_id,
            call_delay=0.2,
            page_delay=0.2,
            trace_name="bitrix.sales_analytics",
        ),
        repository=_sales_repo(),
    ).execute(
        ExportSalesAnalyticsRequest(
            tenant_id=tenant_id,
            run_id=run_id,
            date_from=date_from,
            date_to=date_to,
            category_ids=category_ids,
            responsible_ids=responsible_ids,
            include_tasks=include_tasks,
            include_leads=include_leads,
            include_revenue=include_revenue,
            limit=limit,
        )
    )
    report["storage"] = "postgres"
    report["options"] = {
        "include_pipeline_reports": include_pipeline_reports,
        "include_tasks": include_tasks,
        "include_leads": include_leads,
        "include_revenue": include_revenue,
        "note": "Analytics snapshots are stored in Postgres; legacy file reports are not generated by this endpoint.",
    }
    return report


def _run_sales_analytics_background_job(
    *,
    job_id: str,
    tenant_id: str,
    crm_webhook_url: str | None,
    date_from: str,
    date_to: str,
    include_pipeline_reports: bool,
    include_tasks: bool,
    include_leads: bool,
    include_revenue: bool,
    category_ids: list[str] | None = None,
    responsible_ids: list[str] | None = None,
    limit: int = 0,
) -> None:
    _set_sales_analytics_job(job_id, status="running", started_at=_now_iso())
    try:
        report = _execute_sales_analytics_pipeline(
            tenant_id=tenant_id,
            run_id=job_id,
            crm_webhook_url=crm_webhook_url,
            date_from=date_from,
            date_to=date_to,
            include_pipeline_reports=include_pipeline_reports,
            include_tasks=include_tasks,
            include_leads=include_leads,
            include_revenue=include_revenue,
            category_ids=category_ids,
            responsible_ids=responsible_ids,
            limit=limit,
        )
        _set_sales_analytics_job(
            job_id,
            status="completed",
            completed_at=_now_iso(),
            report=report,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Sales analytics job failed: %s", job_id)
        _set_sales_analytics_job(
            job_id,
            status="error",
            completed_at=_now_iso(),
            error=_redact_error_message(exc, crm_webhook_url),
            error_type=type(exc).__name__,
        )


def _execute_sales_audit_pipeline(
    *,
    tenant_id: str,
    run_id: str,
    crm_webhook_url: str | None,
    whatsapp_webhook_url: str | None,
    openai_key: str,
    base_dir: Path,
    date_from: str,
    date_to: str,
    category_ids: list[str] | None,
    responsible_ids: list[str] | None,
    deal_ids: list[str] | None,
    limit: int,
    model: str,
    transcription_model: str,
    average_ticket_kzt: float | None,
    expected_conversion_pct: float | None,
    portal_base_url: str,
    max_reanimation_cards: int,
    include_whatsapp_audio: bool,
    include_tasks: bool,
    include_leads: bool,
    include_revenue: bool,
    reset_outputs: bool,
    progress_callback: Any | None = None,
) -> dict[str, Any]:
    executive_dir = base_dir / "executive-report"
    sales_quality_dir = base_dir / "sales-quality"
    whatsapp_dir = base_dir / "whatsapp-timeline"
    call_scan_dir = base_dir / "call-records-scan"
    recordings_dir = base_dir / "recordings"
    final_dir = base_dir / "sales-audit"

    request = RunExecutivePipelineRequest(
        sales_quality_dir=sales_quality_dir,
        executive_report_dir=executive_dir,
        whatsapp_dir=whatsapp_dir,
        call_scan_dir=call_scan_dir,
        recordings_dir=recordings_dir,
        date_from=date_from,
        date_to=date_to,
        category_ids=category_ids,
        responsible_ids=responsible_ids,
        deal_ids=deal_ids,
        limit=limit,
        model=model,
        transcription_model=transcription_model,
        average_ticket_kzt=average_ticket_kzt,
        expected_conversion_pct=expected_conversion_pct,
        portal_base_url=portal_base_url,
        max_reanimation_cards=max_reanimation_cards,
        include_whatsapp_audio=include_whatsapp_audio,
        reset_outputs=reset_outputs,
        progress_callback=progress_callback,
    )
    _execute_executive_pipeline(
        tenant_id=tenant_id,
        request=request,
        crm_webhook_url=crm_webhook_url,
        whatsapp_webhook_url=whatsapp_webhook_url,
        openai_key=openai_key,
        sink=FileSystemJsonWriter(),
    )

    if progress_callback:
        progress_callback(
            {
                "stage": "sales_analytics",
                "stage_label": "Расчёт CRM-метрик",
                "current": 0,
                "total": 1,
                "percent": 92,
                "message": "Считаем CRM-метрики и задачи в Postgres",
            }
        )
    sales_report = _execute_sales_analytics_pipeline(
        tenant_id=tenant_id,
        run_id=run_id,
        crm_webhook_url=crm_webhook_url,
        date_from=date_from,
        date_to=date_to,
        include_pipeline_reports=False,
        include_tasks=include_tasks,
        include_leads=include_leads,
        include_revenue=include_revenue,
        category_ids=category_ids,
        responsible_ids=responsible_ids,
        limit=limit,
    )
    if progress_callback:
        progress_callback(
            {
                "stage": "sales_analytics",
                "stage_label": "Расчёт CRM-метрик",
                "current": 1,
                "total": 1,
                "percent": 98,
                "message": "CRM-метрики рассчитаны",
            }
        )
    executive_report = _load_json_if_exists(executive_dir / "executive-report.json") or {}
    if progress_callback:
        progress_callback(
            {
                "stage": "final_report",
                "stage_label": "Финальная сборка",
                "current": 0,
                "total": 1,
                "percent": 98,
                "message": "Собираем финальный отчёт",
            }
        )
    scope_deals = _load_json_if_exists(executive_dir / "scope-deals.json")
    final_report = build_sales_audit_report(
        executive_report=executive_report,
        sales_report=sales_report,
        output_dir=final_dir,
        average_ticket_kzt=average_ticket_kzt,
        expected_conversion_pct=expected_conversion_pct,
        sales_quality_dir=sales_quality_dir,
        scope_deals=scope_deals if isinstance(scope_deals, list) else [],
        portal_base_url=portal_base_url,
    )
    _sales_repo().save_sales_audit_report(
        tenant_id=tenant_id,
        run_id=run_id,
        report=final_report,
    )
    if progress_callback:
        progress_callback(
            {
                "stage": "final_report",
                "stage_label": "Финальная сборка",
                "current": 1,
                "total": 1,
                "percent": 99,
                "message": "Финальный отчёт сохранён",
            }
        )
    return {
        "status": "completed",
        "job_id": run_id,
        "tenant_id": tenant_id,
        "storage": "postgres",
        "output_dir": str(final_dir),
        "executive_output_dir": str(executive_dir),
        "report": final_report,
        "sales_report": sales_report,
    }


def _run_sales_audit_background_job(
    *,
    job_id: str,
    run_id: str | None = None,
    tenant_id: str,
    crm_webhook_url: str | None,
    whatsapp_webhook_url: str | None,
    openai_key: str,
    base_dir: Path,
    date_from: str,
    date_to: str,
    category_ids: list[str] | None,
    responsible_ids: list[str] | None,
    deal_ids: list[str] | None,
    limit: int,
    model: str,
    transcription_model: str,
    average_ticket_kzt: float | None,
    expected_conversion_pct: float | None,
    portal_base_url: str,
    max_reanimation_cards: int,
    include_whatsapp_audio: bool,
    include_tasks: bool,
    include_leads: bool,
    include_revenue: bool,
    reset_outputs: bool,
) -> None:
    del run_id
    _set_sales_audit_job(job_id, status="running", started_at=_now_iso())
    progress = _SalesAuditProgressReporter(job_id)
    try:
        result = _execute_sales_audit_pipeline(
            tenant_id=tenant_id,
            run_id=job_id,
            crm_webhook_url=crm_webhook_url,
            whatsapp_webhook_url=whatsapp_webhook_url,
            openai_key=openai_key,
            base_dir=base_dir,
            date_from=date_from,
            date_to=date_to,
            category_ids=category_ids,
            responsible_ids=responsible_ids,
            deal_ids=deal_ids,
            limit=limit,
            model=model,
            transcription_model=transcription_model,
            average_ticket_kzt=average_ticket_kzt,
            expected_conversion_pct=expected_conversion_pct,
            portal_base_url=portal_base_url,
            max_reanimation_cards=max_reanimation_cards,
            include_whatsapp_audio=include_whatsapp_audio,
            include_tasks=include_tasks,
            include_leads=include_leads,
            include_revenue=include_revenue,
            reset_outputs=reset_outputs,
            progress_callback=progress,
        )
        progress.complete()
        _set_sales_audit_job(
            job_id,
            status="completed",
            completed_at=_now_iso(),
            output_dir=str(base_dir / "sales-audit"),
            report=result.get("report"),
            executive_report=result.get("report"),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("Sales audit job failed: %s", job_id)
        progress.fail()
        _set_sales_audit_job(
            job_id,
            status="error",
            completed_at=_now_iso(),
            error=_redact_error_message(exc, crm_webhook_url, whatsapp_webhook_url, openai_key),
            error_type=type(exc).__name__,
        )


# ---------------------------------------------------------------------------
# Authentication middleware
# ---------------------------------------------------------------------------


@app.middleware("http")
async def _auth_middleware(request: Request, call_next: Any) -> JSONResponse:
    token_value = _bearer_token(request.headers.get("authorization"))
    user: User | None = None
    if token_value:
        try:
            user = _decode_access_token(token_value)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    elif _auth_required() and request.method != "OPTIONS" and not _public_auth_path(request.url.path):
        return JSONResponse(status_code=401, content={"detail": "Authentication required."})

    context_token = _AUTH_CONTEXT.set(user)
    try:
        return await call_next(request)
    finally:
        _AUTH_CONTEXT.reset(context_token)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Auth endpoints
# ---------------------------------------------------------------------------


class _LoginPayload(BaseModel):
    username: str
    password: str


class _RegisterPayload(BaseModel):
    name: str = ""
    phone: str
    email: str
    password: str


class _UserPayload(BaseModel):
    username: str
    password: str
    tenant_id: str = "default"
    role: str = "client"
    active: bool = True


def _normalize_username(username: str) -> str:
    value = username.strip().lower()
    if not _USERNAME_RE.fullmatch(value):
        raise HTTPException(
            status_code=422,
            detail="Username must be 3-128 characters: letters, digits, dot, underscore, plus, @, hyphen.",
        )
    return value


def _normalize_registration_email(email: str) -> str:
    value = (email or "").strip().lower()
    if len(value) > 128 or not _EMAIL_RE.fullmatch(value):
        raise HTTPException(status_code=422, detail="Email must be a valid email address.")
    return _normalize_username(value)


def _normalize_registration_name(name: str) -> str:
    value = (name or "").strip()
    if len(value) > 128:
        raise HTTPException(status_code=422, detail="Name must be 128 characters or fewer.")
    return value


def _normalize_registration_phone(phone: str) -> str:
    value = (phone or "").strip()
    digit_count = sum(1 for char in value if char.isdigit())
    if not value:
        raise HTTPException(status_code=422, detail="Phone is required.")
    if digit_count < 5 or not _PHONE_RE.fullmatch(value):
        raise HTTPException(status_code=422, detail="Phone must contain 5-32 digits or common phone symbols.")
    return value


def _validate_registration_password(password: str) -> None:
    if not password or not password.strip():
        raise HTTPException(status_code=422, detail="Password cannot be empty.")


def _tenant_id_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug[:45].strip("-") or "client"


def _new_registration_tenant_id(email: str) -> str:
    source = email.split("@", 1)[0] or "client"
    base = _tenant_id_slug(source)
    tenants = _tenant_repo()
    for _ in range(10):
        tenant_id = f"{base}-{secrets.token_hex(4)}"
        if tenants.get(tenant_id) is None:
            return tenant_id
    raise HTTPException(status_code=503, detail="Could not allocate tenant id.")


def _normalize_role(role: str) -> str:
    value = (role or "client").strip().lower()
    if value not in _ROLE_VALUES:
        raise HTTPException(status_code=422, detail="Role must be 'admin' or 'client'.")
    return value


def _user_from_payload(payload: _UserPayload) -> User:
    username = _normalize_username(payload.username)
    tenant_id = payload.tenant_id.strip() or "default"
    _validate_tenant_id(tenant_id)
    _tenant_repo().ensure(tenant_id)
    return User(
        username=username,
        tenant_id=tenant_id,
        role=_normalize_role(payload.role),
        password_hash=_hash_password(payload.password),
        active=bool(payload.active),
    )


@app.get("/api/auth/status", tags=["Auth"])
def get_auth_status() -> dict[str, Any]:
    return {
        "auth_required": _auth_required(),
        "has_users": _user_repo().count() > 0,
    }


@app.post("/api/auth/login", tags=["Auth"])
def login(payload: _LoginPayload) -> dict[str, Any]:
    username = _normalize_username(payload.username)
    user = _user_repo().get(username)
    if not user or not user.active or not _verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    return {
        "access_token": _create_access_token(user),
        "token_type": "bearer",
        "expires_in": _token_ttl_seconds(),
        "user": user.to_public_dict(),
    }


@app.post("/api/auth/register", tags=["Auth"], status_code=201)
def register_client(payload: _RegisterPayload) -> dict[str, Any]:
    email = _normalize_registration_email(payload.email)
    phone = _normalize_registration_phone(payload.phone)
    name = _normalize_registration_name(payload.name)
    _validate_registration_password(payload.password)

    users = _user_repo()
    registrations = _client_registration_repo()
    if users.get(email) is not None or registrations.get_by_email(email) is not None:
        raise HTTPException(status_code=409, detail="User with this email already exists.")

    tenant_id = _new_registration_tenant_id(email)
    tenant_name = name or email
    _tenant_repo().save(Tenant(id=tenant_id, name=tenant_name))

    user = User(
        username=email,
        tenant_id=tenant_id,
        role="client",
        password_hash=_hash_password(payload.password),
        active=True,
    )
    users.save(user)

    registration = ClientRegistration(
        email=email,
        tenant_id=tenant_id,
        phone=phone,
        name=name,
    )
    registrations.save(registration)

    return {
        "status": "ok",
        "access_token": _create_access_token(user),
        "token_type": "bearer",
        "expires_in": _token_ttl_seconds(),
        "user": user.to_public_dict(),
        "registration": registration.to_public_dict(),
    }


@app.get("/api/auth/me", tags=["Auth"])
def get_current_user(
    authorization: str | None = Security(_authorization_header),
) -> dict[str, Any]:
    del authorization
    user = _require_user()
    return {"user": user.to_public_dict()}


@app.post("/api/auth/bootstrap", tags=["Auth"])
def bootstrap_first_admin(
    payload: _UserPayload,
    setup_token: str | None = Security(_setup_token_header),
) -> dict[str, Any]:
    """Create the first admin user using X-Setup-Token."""
    _require_setup_token(setup_token)
    if _user_repo().count() > 0:
        raise HTTPException(status_code=409, detail="Users already exist.")
    user = _user_from_payload(_UserPayload(
        username=payload.username,
        password=payload.password,
        tenant_id=payload.tenant_id,
        role="admin",
        active=True,
    ))
    _user_repo().save(user)
    return {"status": "ok", "user": user.to_public_dict()}


@app.get("/api/users", tags=["Auth"])
def list_users(
    authorization: str | None = Security(_authorization_header),
) -> dict[str, Any]:
    del authorization
    _require_admin_or_dev()
    return {"users": [user.to_public_dict() for user in _user_repo().list_all()]}


@app.post("/api/users", tags=["Auth"])
def create_user(
    payload: _UserPayload,
    authorization: str | None = Security(_authorization_header),
) -> dict[str, Any]:
    del authorization
    _require_admin_or_dev()
    user = _user_from_payload(payload)
    _user_repo().save(user)
    return {"status": "ok", "user": user.to_public_dict()}


# ---------------------------------------------------------------------------
# Bitrix24 OAuth installation endpoints
# ---------------------------------------------------------------------------


class _BitrixConnectStartPayload(BaseModel):
    portal: str
    return_url: str = ""


def _bitrix_head_ok() -> Response:
    return Response(status_code=200)


@app.head("/api/bitrix/oauth/callback", tags=["Bitrix OAuth"])
def bitrix_oauth_callback_head() -> Response:
    return _bitrix_head_ok()


@app.head("/api/bitrix/install", tags=["Bitrix OAuth"])
def bitrix_install_head() -> Response:
    return _bitrix_head_ok()


@app.head("/api/bitrix/settings", tags=["Bitrix OAuth"])
def bitrix_settings_head() -> Response:
    return _bitrix_head_ok()


@app.head("/api/bitrix/settings/save", tags=["Bitrix OAuth"])
def bitrix_settings_save_head() -> Response:
    return _bitrix_head_ok()


@app.head("/api/bitrix/uninstall", tags=["Bitrix OAuth"])
def bitrix_uninstall_head() -> Response:
    return _bitrix_head_ok()


def _extract_bitrix_settings_data(payload: dict[str, Any]) -> dict[str, str]:
    data = payload.get("data")
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items()}


def _bitrix_settings_error(field: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={
            "status": "error",
            "errors": [{"field": field, "message": message}],
        },
    )


def _bitrix_settings_form_config(
    request: Request,
    *,
    code_value: str = "",
) -> dict[str, Any]:
    client_id = _bitrix_oauth_client_id()
    if not client_id:
        raise HTTPException(status_code=503, detail="BITRIX_OAUTH_CLIENT_ID is not configured.")
    return {
        "title": "AISales Auditor",
        "version": "1",
        "steps": [
            {
                "id": "connect",
                "title": "Connect AISales Auditor",
                "description": (
                    "Paste the connection code from AISales Auditor to link this "
                    "Bitrix24 portal to the correct tenant."
                ),
                "fields": [
                    {
                        "id": "connection-code",
                        "name": "connection_code",
                        "type": "input",
                        "label": "Connection code",
                        "placeholder": "XXXX-XXXX-XXXX",
                        "value": code_value,
                    }
                ],
            }
        ],
        "form": {
            "id": "aisales-auditor-bitrix-connect",
            "action": _public_api_url(request, "/api/bitrix/settings/save"),
            "clientId": client_id,
            "redirect": _bitrix_oauth_settings_redirect(),
            "saveCaption": "Connect",
            "cancelCaption": "Later",
        },
    }


@app.post("/api/bitrix/settings", tags=["Bitrix OAuth"])
async def bitrix_settings(request: Request) -> dict[str, Any]:
    """Return Bitrix REST-only setup wizard config for marketplace installs."""
    payload = await _bitrix_request_payload(request)
    auth = _extract_bitrix_auth_payload(payload)
    _verify_bitrix_application_token(auth)
    data = _extract_bitrix_settings_data(payload)

    # Preserve the installation token under member_id until the user links it
    # with an AISales tenant-specific connection code.
    try:
        _save_bitrix_oauth_token(auth)
    except HTTPException:
        pass

    return _bitrix_settings_form_config(
        request,
        code_value=_format_bitrix_connect_code(data.get("connection_code", "")),
    )


@app.post("/api/bitrix/settings/save", tags=["Bitrix OAuth"])
async def bitrix_settings_save(request: Request) -> Any:
    """Bind a Bitrix REST-only install to the tenant that created a connection code."""
    payload = await _bitrix_request_payload(request)
    auth = _extract_bitrix_auth_payload(payload)
    _verify_bitrix_application_token(auth)
    data = _extract_bitrix_settings_data(payload)
    code = _normalize_bitrix_connect_code(data.get("connection_code", ""))
    if not code:
        return _bitrix_settings_error("connection_code", "Connection code is required.")

    session = _active_bitrix_connect_session(code)
    if session is None:
        return _bitrix_settings_error("connection_code", "Connection code is invalid or expired.")

    token = _save_bitrix_oauth_token(
        auth,
        fallback_domain=session.bitrix_domain,
        tenant_id=session.tenant_id,
    )
    _bitrix_connect_session_repo().mark_used(session.connection_code)
    return {
        "status": "success",
        "tenant_id": token.tenant_id,
        "bitrix_oauth": _bitrix_oauth_status(token),
    }


@app.post("/api/bitrix/connect/start", tags=["Bitrix OAuth"])
def start_bitrix_connect(
    payload: _BitrixConnectStartPayload,
    authorization: str | None = Security(_authorization_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Return a Bitrix OAuth authorization URL for frontend onboarding."""
    del authorization
    _require_user()
    tenant_id = _resolve_tenant_id(x_tenant_id)
    oauth = _build_bitrix_oauth_authorize_url(
        portal=payload.portal,
        return_url=payload.return_url,
        tenant_id=tenant_id,
    )
    session = _create_bitrix_connect_session(
        tenant_id=tenant_id,
        portal=payload.portal,
        return_url=payload.return_url,
    )
    bitrix_oauth = _bitrix_oauth_repo().get_by_tenant(tenant_id)
    return {
        "status": "ok",
        "tenant_id": tenant_id,
        **oauth,
        "connection_code": _format_bitrix_connect_code(session.connection_code),
        "connection_expires_at": session.expires_at,
        "bitrix_oauth": _bitrix_oauth_status(bitrix_oauth),
    }


@app.get("/api/bitrix/oauth/start", tags=["Bitrix OAuth"])
def start_bitrix_oauth(
    portal: str = Query(..., description="Bitrix24 portal domain, e.g. client.bitrix24.kz"),
    return_url: str = Query("", description="Relative frontend URL to return to after callback"),
    authorization: str | None = Security(_authorization_header),
    x_tenant_id: str | None = Header(None),
) -> RedirectResponse:
    del authorization
    _require_user()
    tenant_id = _resolve_tenant_id(x_tenant_id)
    oauth = _build_bitrix_oauth_authorize_url(
        portal=portal,
        return_url=return_url,
        tenant_id=tenant_id,
    )
    return RedirectResponse(oauth["authorize_url"], status_code=307)


@app.get("/api/bitrix/oauth/callback", tags=["Bitrix OAuth"], response_model=None)
def bitrix_oauth_callback(
    code: str | None = Query(None),
    state: str | None = Query(None),
    domain: str | None = Query(None),
    scope: str | None = Query(None),
    error: str | None = Query(None),
    error_description: str | None = Query(None),
) -> Any:
    if error:
        raise HTTPException(
            status_code=400,
            detail={"error": error, "error_description": error_description or ""},
        )
    if not code:
        raise HTTPException(status_code=422, detail="OAuth code is required.")

    state_payload = _decode_bitrix_oauth_state(state)
    callback_domain = _normalize_bitrix_domain(domain or state_payload.get("portal") or "")
    client_id = _bitrix_oauth_client_id()
    client_secret = _bitrix_oauth_client_secret()
    if not client_id or not client_secret:
        raise HTTPException(status_code=503, detail="Bitrix OAuth client credentials are not configured.")

    token_payload = _request_bitrix_oauth_token(
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
        }
    )
    token = _save_bitrix_oauth_token(
        token_payload,
        fallback_domain=callback_domain,
        fallback_scope=scope or "",
        tenant_id=str(state_payload.get("tenant_id") or ""),
    )
    body = {
        "status": "ok",
        "tenant_id": token.tenant_id,
        "bitrix_oauth": _bitrix_oauth_status(token),
    }

    return_url = str(state_payload.get("return_url") or "")
    if return_url:
        return RedirectResponse(
            _append_query_params(
                return_url,
                {
                    "bitrix_oauth": "connected",
                    "tenant_id": token.tenant_id,
                },
            ),
            status_code=307,
        )
    return body


@app.post("/api/bitrix/install", tags=["Bitrix OAuth"])
async def bitrix_install_callback(request: Request) -> dict[str, Any]:
    payload = await _bitrix_request_payload(request)
    auth = _extract_bitrix_auth_payload(payload)
    _verify_bitrix_application_token(auth)
    token = _save_bitrix_oauth_token(auth)
    return {
        "status": "ok",
        "tenant_id": token.tenant_id,
        "bitrix_oauth": _bitrix_oauth_status(token),
    }


@app.post("/api/bitrix/uninstall", tags=["Bitrix OAuth"])
async def bitrix_uninstall_callback(request: Request) -> dict[str, Any]:
    payload = await _bitrix_request_payload(request)
    auth = _extract_bitrix_auth_payload(payload)
    _verify_bitrix_application_token(auth)
    member_id = str(auth.get("member_id") or "").strip()
    if not member_id:
        raise HTTPException(status_code=422, detail="Bitrix member_id is required.")

    repo = _bitrix_oauth_repo()
    token = repo.get_by_member_id(member_id)
    if token is None:
        return {"status": "ok", "tenant_id": "", "bitrix_oauth": _bitrix_oauth_status(None)}
    repo.update_status(token.tenant_id, "revoked")
    revoked = repo.get_by_tenant(token.tenant_id)
    return {
        "status": "ok",
        "tenant_id": token.tenant_id,
        "bitrix_oauth": _bitrix_oauth_status(revoked),
    }


# ---------------------------------------------------------------------------
# Executive Report endpoints
# ---------------------------------------------------------------------------


@app.get("/executive-report/latest", tags=["Executive Report"])
def get_latest_executive_report(
    report_path: str = Query(
        "",
        description=(
            "Path to executive-report.json. "
            "If empty, the latest completed run for the tenant is used."
        ),
    ),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    tid = _resolve_tenant_id(x_tenant_id)
    resolved_path: str = report_path
    if not resolved_path:
        runs = _runs_repo().list_by_tenant(tid)
        completed = [r for r in runs if r.status == "completed"]
        if not completed:
            raise HTTPException(
                status_code=404,
                detail=f"No completed runs found for tenant '{tid}'.",
            )
        resolved_path = str(Path(completed[0].output_dir) / "executive-report.json")

    path = Path(resolved_path)
    if report_path:
        tenant_root = (Path("storage") / "tenants" / tid).resolve()
        resolved_report_path = path.resolve()
        if not resolved_report_path.is_relative_to(tenant_root):
            raise HTTPException(
                status_code=403,
                detail="report_path must point inside the current tenant storage.",
            )
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Report not found: {path}")
    if not path.is_file():
        raise HTTPException(status_code=422, detail=f"Report path is not a file: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid JSON report: {path}") from exc


@app.post("/executive-report/build", tags=["Executive Report"])
def build_executive_report(
    sales_quality_dir: str = Form("export/sales-quality", description="Directory with sales-quality report.json and features"),
    output_dir: str = Form("export/executive-report", description="Output directory"),
    scope: str = Form("analyzed", description="analyzed or bitrix"),
    date_from: Optional[str] = Form(None, description="Start date for Bitrix scope"),
    date_to: Optional[str] = Form(None, description="End date for Bitrix scope"),
    category_id: Optional[List[str]] = Form(None, description="Deal category IDs"),
    responsible_id: Optional[List[str]] = Form(None, description="ASSIGNED_BY_ID; may be repeated"),
    deal_id: Optional[List[str]] = Form(None, description="Specific deal IDs"),
    limit: int = Form(0, description="Max deals, 0 = all"),
    average_ticket_kzt: Optional[float] = Form(None, description="Average ticket for lost revenue formula"),
    expected_conversion_pct: Optional[float] = Form(None, description="Expected conversion percent for lost revenue formula"),
    portal_base_url: str = Form("", description="Bitrix portal URL for CRM links; empty = current tenant Bitrix"),
    max_reanimation_cards: int = Form(100, description="Max failed deal cards"),
    webhook_url: str | None = Security(_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Build the executive report from sales-quality outputs and Bitrix CRM."""
    tid = _resolve_tenant_id(x_tenant_id)
    clean_categories = [item for item in (category_id or []) if _none(item)] or None
    clean_responsible = [item for item in (responsible_id or []) if _none(item)] or None
    clean_deals = [item for item in (deal_id or []) if _none(item)] or None
    resolved_portal_base_url = _resolve_portal_base_url(portal_base_url, tid, webhook_url)
    sink, mem = _tee()
    return _run_service(
        lambda: BuildExecutiveReportService(
            gateway=_resolve_bitrix_gateway(
                webhook_url,
                tid,
                call_delay=0.2,
                trace_name="bitrix.executive_report",
            ),
            sink=sink,
        ).execute(
            BuildExecutiveReportRequest(
                output_dir=Path(output_dir),
                sales_quality_dir=Path(sales_quality_dir),
                scope=scope,
                date_from=_none(date_from),
                date_to=_none(date_to),
                category_ids=clean_categories,
                responsible_id=clean_responsible[0] if clean_responsible else None,
                responsible_ids=clean_responsible,
                deal_ids=clean_deals,
                limit=limit,
                average_ticket_kzt=average_ticket_kzt,
                expected_conversion_pct=expected_conversion_pct,
                portal_base_url=resolved_portal_base_url,
                max_reanimation_cards=max_reanimation_cards,
            )
        ),
        mem,
    )


@app.post("/executive-report/run", tags=["Executive Report"])
def run_executive_report_pipeline(
    background_tasks: BackgroundTasks,
    sales_quality_dir: str = Form("", description="Directory for sales-quality outputs (empty = per-tenant/run path)"),
    output_dir: str = Form("", description="Executive report output directory (empty = per-tenant/run path)"),
    whatsapp_dir: str = Form("", description="WhatsApp export directory (empty = per-tenant/run path)"),
    call_scan_dir: str = Form("", description="Call scan directory (empty = per-tenant/run path)"),
    recordings_dir: str = Form("", description="Call recordings directory (empty = per-tenant/run path)"),
    date_from: Optional[str] = Form(None, description="Start date"),
    date_to: Optional[str] = Form(None, description="End date"),
    category_id: Optional[List[str]] = Form(None, description="Deal category IDs"),
    responsible_id: Optional[List[str]] = Form(None, description="ASSIGNED_BY_ID; may be repeated"),
    deal_id: Optional[List[str]] = Form(None, description="Specific deal IDs"),
    limit: int = Form(0, description="Max CRM deals, 0 = all"),
    model: str = Form("gpt-4o-mini", description="OpenAI model for sales-quality analysis"),
    transcription_model: str = Form("gpt-4o-transcribe", description="OpenAI transcription model"),
    average_ticket_kzt: Optional[float] = Form(None, description="Average ticket for lost revenue formula"),
    expected_conversion_pct: Optional[float] = Form(None, description="Expected conversion percent"),
    portal_base_url: str = Form("", description="Bitrix portal URL for CRM links; empty = current tenant Bitrix"),
    max_reanimation_cards: int = Form(100, description="Max failed deal cards"),
    reset_outputs: bool = Form(True, description="Clear output directories before running"),
    include_whatsapp_audio: bool = Form(False, description="Download and transcribe WhatsApp audio messages"),
    wait: bool = Form(False, description="Run synchronously and wait for completion"),
    crm_webhook_url: str | None = Security(_webhook_header),
    whatsapp_webhook_url: str | None = Security(_whatsapp_webhook_header),
    openai_key: str | None = Security(_openai_key_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Run source refresh, sales-quality analysis, and executive report in one scope."""
    tid = _resolve_tenant_id(x_tenant_id)
    _resolve_bitrix_gateway(crm_webhook_url, tid)
    _resolve_whatsapp_gateway(whatsapp_webhook_url, tid, crm_fallback=crm_webhook_url)
    key = _resolve_openai_key(openai_key, tid)
    clean_categories = _clean_form_list(category_id)
    clean_responsible = _clean_form_list(responsible_id)
    clean_deals = _clean_form_list(deal_id)
    resolved_portal_base_url = _resolve_portal_base_url(portal_base_url, tid, crm_webhook_url)

    job_id = uuid.uuid4().hex
    base = _tenant_storage(tid, job_id)

    resolved_output = Path(output_dir) if output_dir else base / "executive-report"
    resolved_sq = Path(sales_quality_dir) if sales_quality_dir else base / "sales-quality"
    resolved_wa = Path(whatsapp_dir) if whatsapp_dir else base / "whatsapp-timeline"
    resolved_calls = Path(call_scan_dir) if call_scan_dir else base / "call-records-scan"
    resolved_recordings = Path(recordings_dir) if recordings_dir else base / "recordings"

    request = RunExecutivePipelineRequest(
        sales_quality_dir=resolved_sq,
        executive_report_dir=resolved_output,
        whatsapp_dir=resolved_wa,
        call_scan_dir=resolved_calls,
        recordings_dir=resolved_recordings,
        date_from=_none(date_from),
        date_to=_none(date_to),
        category_ids=clean_categories,
        responsible_ids=clean_responsible,
        deal_ids=clean_deals,
        limit=limit,
        model=model,
        transcription_model=transcription_model,
        average_ticket_kzt=average_ticket_kzt,
        expected_conversion_pct=expected_conversion_pct,
        portal_base_url=resolved_portal_base_url,
        max_reanimation_cards=max_reanimation_cards,
        include_whatsapp_audio=include_whatsapp_audio,
        reset_outputs=reset_outputs,
    )

    if wait:
        sink, mem = _tee()
        result = _run_service(
            lambda: _execute_executive_pipeline(
                tenant_id=tid,
                request=request,
                crm_webhook_url=crm_webhook_url,
                whatsapp_webhook_url=whatsapp_webhook_url,
                openai_key=key,
                sink=sink,
            ),
            mem,
        )
        report_path = resolved_output / "executive-report.json"
        if report_path.exists():
            result["executive_report"] = json.loads(report_path.read_text(encoding="utf-8"))
        return result

    _set_executive_report_job(
        job_id,
        tenant_id=tid,
        status="queued",
        queued_at=_now_iso(),
        output_dir=str(resolved_output),
        scope={
            "date_from": request.date_from,
            "date_to": request.date_to,
            "category_ids": request.category_ids or [],
            "responsible_ids": request.responsible_ids or [],
            "deal_ids": request.deal_ids or [],
            "limit": request.limit,
            "include_whatsapp_audio": request.include_whatsapp_audio,
        },
    )
    try:
        _runs_repo().create(AnalysisRun(
            run_id=job_id,
            tenant_id=tid,
            status="queued",
            date_from=request.date_from,
            date_to=request.date_to,
            category_ids=request.category_ids or [],
            responsible_ids=request.responsible_ids or [],
            output_dir=str(resolved_output),
        ))
    except Exception:
        logger.warning("Failed to persist new run to database: %s", job_id)

    background_tasks.add_task(
        _run_executive_report_background_job,
        job_id=job_id,
        tenant_id=tid,
        request=request,
        crm_webhook_url=crm_webhook_url,
        whatsapp_webhook_url=whatsapp_webhook_url,
        openai_key=key,
    )
    return {
        "status": "started",
        "job_id": job_id,
        "tenant_id": tid,
        "output_dir": str(resolved_output),
        "status_url": f"/executive-report/jobs/{job_id}",
    }


@app.get("/executive-report/jobs/{job_id}", tags=["Executive Report"])
def get_executive_report_job(
    job_id: str,
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Return status for a background executive report run."""
    tid = _resolve_tenant_id(x_tenant_id)
    job = _get_executive_report_job(job_id)
    if not job:
        # Fall back to persisted runs from previous server sessions.
        run = _runs_repo().get(job_id)
        if not run:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        if run.tenant_id != tid:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        return _maybe_expire_persisted_run(
            run,
            job_kind="executive report",
            set_job=_set_executive_report_job,
        )
    if job.get("tenant_id") and job.get("tenant_id") != tid:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    return _maybe_expire_memory_job(
        job,
        job_kind="executive report",
        set_job=_set_executive_report_job,
    )


# ---------------------------------------------------------------------------
# App state, tenants, and settings — persisted in the configured database
# ---------------------------------------------------------------------------


@app.get("/api/app-state", tags=["Settings"])
def get_app_state(x_tenant_id: str | None = Header(None)) -> dict[str, Any]:
    """Returns current app state including business profile and integrations status."""
    tid = _resolve_tenant_id(x_tenant_id)
    profile = _profile_repo(tid).get()
    integrations = _get_integrations(tid)
    bitrix_oauth = _bitrix_oauth_repo().get_by_tenant(tid)
    return {
        "tenant_id": tid,
        "setup": {
            "business_profile": profile.to_dict() if profile else {},
            "integrations": _integrations_status(integrations),
            "bitrix_oauth": _bitrix_oauth_status(bitrix_oauth),
        },
    }


class _BusinessProfilePayload(BaseModel):
    company_name: str = ""
    website_url: str = ""
    instagram_url: str = ""
    price_list: str = ""
    average_ticket_kzt: float | None = None
    monthly_sales_plan_kzt: float | None = None
    advantages: str = ""
    promotions: str = ""


@app.post("/api/setup-profile", tags=["Settings"])
def setup_profile(
    payload: _BusinessProfilePayload,
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Save business profile to the configured database and return updated app state."""
    tid = _resolve_tenant_id(x_tenant_id)
    profile = BusinessProfile.from_dict(payload.model_dump())
    _profile_repo(tid).save(profile)
    integrations = _get_integrations(tid)
    bitrix_oauth = _bitrix_oauth_repo().get_by_tenant(tid)
    return {
        "app_state": {
            "tenant_id": tid,
            "setup": {
                "business_profile": profile.to_dict(),
                "integrations": _integrations_status(integrations),
                "bitrix_oauth": _bitrix_oauth_status(bitrix_oauth),
            },
        }
    }


class _IntegrationsPayload(BaseModel):
    bitrix_webhook_url: str = ""
    whatsapp_webhook_url: str = ""
    openai_api_key: str = ""


@app.get("/api/integrations", tags=["Settings"])
def get_integrations(x_tenant_id: str | None = Header(None)) -> dict[str, Any]:
    """Returns current integration configuration status (no raw secrets)."""
    tid = _resolve_tenant_id(x_tenant_id)
    ints = _get_integrations(tid)
    bitrix_oauth = _bitrix_oauth_repo().get_by_tenant(tid)
    return {
        "tenant_id": tid,
        "integrations": _integrations_status(ints),
        "bitrix_oauth": _bitrix_oauth_status(bitrix_oauth),
    }


@app.post("/api/setup-integrations", tags=["Settings"])
def setup_integrations(
    payload: _IntegrationsPayload,
    x_tenant_id: str | None = Header(None),
    setup_token: str | None = Security(_setup_token_header),
) -> dict[str, Any]:
    """Save Bitrix webhook URLs and OpenAI API key to the configured database."""
    _require_setup_token(setup_token)
    tid = _resolve_tenant_id(x_tenant_id)
    current = _get_integrations(tid)
    incoming = Integrations.from_dict(payload.model_dump())
    ints = Integrations(
        bitrix_webhook_url=incoming.bitrix_webhook_url or current.bitrix_webhook_url,
        whatsapp_webhook_url=incoming.whatsapp_webhook_url or current.whatsapp_webhook_url,
        openai_api_key=incoming.openai_api_key or current.openai_api_key,
    )
    _integrations_repo(tid).save(ints)
    bitrix_oauth = _bitrix_oauth_repo().get_by_tenant(tid)
    return {
        "status": "ok",
        "tenant_id": tid,
        "integrations": _integrations_status(ints),
        "bitrix_oauth": _bitrix_oauth_status(bitrix_oauth),
    }


# ---------------------------------------------------------------------------
# Tenant CRUD
# ---------------------------------------------------------------------------


class _TenantPayload(BaseModel):
    id: str
    name: str = ""


@app.get("/api/tenants", tags=["Settings"])
def list_tenants(
    authorization: str | None = Security(_authorization_header),
) -> dict[str, Any]:
    """List all tenants."""
    del authorization
    _require_admin_or_dev()
    tenants = _tenant_repo().list_all()
    return {"tenants": [t.to_dict() for t in tenants]}


@app.post("/api/tenants", tags=["Settings"])
def create_tenant(
    payload: _TenantPayload,
    authorization: str | None = Security(_authorization_header),
) -> dict[str, Any]:
    """Create or update a tenant."""
    del authorization
    _require_admin_or_dev()
    tid = payload.id.strip()
    if not tid:
        raise HTTPException(status_code=422, detail="Tenant ID cannot be empty.")
    _validate_tenant_id(tid)
    tenant = Tenant(id=tid, name=payload.name or tid)
    _tenant_repo().save(tenant)
    return {"status": "ok", "tenant": tenant.to_dict()}


@app.get("/api/tenants/{tenant_id}", tags=["Settings"])
def get_tenant(
    tenant_id: str,
    authorization: str | None = Security(_authorization_header),
) -> dict[str, Any]:
    """Get a single tenant by ID."""
    del authorization
    _ensure_tenant_access(tenant_id)
    tenant = _tenant_repo().get(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant not found: {tenant_id}")
    return {"tenant": tenant.to_dict()}


# ---------------------------------------------------------------------------
# Analysis runs
# ---------------------------------------------------------------------------


@app.get("/api/analysis-runs", tags=["Settings"])
def list_analysis_runs(x_tenant_id: str | None = Header(None)) -> dict[str, Any]:
    """List all analysis runs for the current tenant (newest first)."""
    tid = _resolve_tenant_id(x_tenant_id)
    runs = _runs_repo().list_by_tenant(tid)
    return {"tenant_id": tid, "runs": [r.to_dict() for r in runs]}


# ---------------------------------------------------------------------------
# Catalog endpoints — for UI dropdowns (funnels, managers)
# ---------------------------------------------------------------------------


@app.post("/sales-analytics/run", tags=["Sales Analytics"])
def run_sales_analytics(
    background_tasks: BackgroundTasks,
    date_from: str = Form(..., description="Start date, e.g. 2026-04-01"),
    date_to: str = Form(..., description="End date, e.g. 2026-05-03"),
    output_dir: str = Form("", description="Legacy field; analytics are stored in Postgres"),
    category_id: Optional[List[str]] = Form(None, description="Deal category IDs"),
    responsible_id: Optional[List[str]] = Form(None, description="ASSIGNED_BY_ID; may be repeated"),
    limit: int = Form(0, description="Max CRM deals per source query, 0 = all"),
    include_pipeline_reports: bool = Form(True, description="Build per-pipeline reports"),
    include_tasks: bool = Form(True, description="Export tasks and task coverage"),
    include_leads: bool = Form(True, description="Export leads and lead loss report"),
    include_revenue: bool = Form(True, description="Export invoices, sale orders, and payments"),
    wait: bool = Form(False, description="Run synchronously and return report"),
    webhook_url: str | None = Security(_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Run the SQL analytics snapshot pipeline used by the management reports."""
    tid = _resolve_tenant_id(x_tenant_id)
    _resolve_bitrix_gateway(webhook_url, tid)
    resolved_from = _none(date_from)
    resolved_to = _none(date_to)
    if not resolved_from or not resolved_to:
        raise HTTPException(status_code=422, detail="date_from and date_to are required.")
    clean_categories = _clean_form_list(category_id)
    clean_responsible = _clean_form_list(responsible_id)
    _sales_repo()

    job_id = uuid.uuid4().hex
    resolved_output = (
        Path(output_dir)
        if _none(output_dir)
        else _tenant_storage(tid, job_id) / "sales-analytics"
    )
    try:
        _runs_repo().create(AnalysisRun(
            run_id=job_id,
            tenant_id=tid,
            status="running" if wait else "queued",
            date_from=resolved_from,
            date_to=resolved_to,
            output_dir=str(resolved_output),
        ))
    except Exception:
        logger.warning("Failed to persist sales analytics run to database: %s", job_id)

    if wait:
        try:
            report = _execute_sales_analytics_pipeline(
                tenant_id=tid,
                run_id=job_id,
                crm_webhook_url=webhook_url,
                date_from=resolved_from,
                date_to=resolved_to,
                include_pipeline_reports=include_pipeline_reports,
                include_tasks=include_tasks,
                include_leads=include_leads,
                include_revenue=include_revenue,
                category_ids=clean_categories,
                responsible_ids=clean_responsible,
                limit=limit,
            )
            _runs_repo().update_status(job_id, "completed", completed_at=_now_iso())
            return {
                "status": "completed",
                "job_id": job_id,
                "tenant_id": tid,
                "storage": "postgres",
                "output_dir": str(resolved_output),
                "report": report,
            }
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            error = _redact_error_message(exc, webhook_url)
            _runs_repo().update_status(job_id, "error", completed_at=_now_iso(), error=error)
            raise HTTPException(status_code=502, detail=error) from exc

    _set_sales_analytics_job(
        job_id,
        tenant_id=tid,
        status="queued",
        queued_at=_now_iso(),
        output_dir=str(resolved_output),
        scope={
            "date_from": resolved_from,
            "date_to": resolved_to,
            "category_ids": clean_categories or [],
            "responsible_ids": clean_responsible or [],
            "include_pipeline_reports": include_pipeline_reports,
            "include_tasks": include_tasks,
            "include_leads": include_leads,
            "include_revenue": include_revenue,
            "storage": "postgres",
        },
    )
    background_tasks.add_task(
        _run_sales_analytics_background_job,
        job_id=job_id,
        tenant_id=tid,
        crm_webhook_url=webhook_url,
        date_from=resolved_from,
        date_to=resolved_to,
        include_pipeline_reports=include_pipeline_reports,
        include_tasks=include_tasks,
        include_leads=include_leads,
        include_revenue=include_revenue,
        category_ids=clean_categories,
        responsible_ids=clean_responsible,
        limit=limit,
    )
    return {
        "status": "started",
        "job_id": job_id,
        "tenant_id": tid,
        "storage": "postgres",
        "output_dir": str(resolved_output),
        "status_url": f"/sales-analytics/jobs/{job_id}",
        "report_url": f"/sales-analytics/report?run_id={job_id}",
    }


@app.get("/sales-analytics/jobs/{job_id}", tags=["Sales Analytics"])
def get_sales_analytics_job(
    job_id: str,
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Return status for a background SQL analytics run."""
    tid = _resolve_tenant_id(x_tenant_id)
    _sales_repo()
    job = _get_sales_analytics_job(job_id)
    if not job:
        run = _runs_repo().get(job_id)
        if not run or run.tenant_id != tid:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        stale_result = _maybe_expire_persisted_run(
            run,
            job_kind="sales analytics",
            set_job=_set_sales_analytics_job,
        )
        if stale_result.get("status") == "error":
            return stale_result
        result = run.to_dict()
        if run.status == "completed":
            result["report"] = _sales_analytics_report(tid, job_id)
        return result
    if job.get("tenant_id") and job.get("tenant_id") != tid:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    return _maybe_expire_memory_job(
        job,
        job_kind="sales analytics",
        set_job=_set_sales_analytics_job,
    )


@app.get("/sales-analytics/report", tags=["Sales Analytics"])
def get_sales_analytics_report(
    run_id: str = Query("", description="Analysis run ID"),
    output_dir: str = Query("", description="Legacy field; ignored for Postgres reports"),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Read Postgres reports produced by /sales-analytics/run."""
    tid = _resolve_tenant_id(x_tenant_id)
    _sales_repo()
    del output_dir
    if _none(run_id):
        run = _runs_repo().get(run_id)
        if not run or run.tenant_id != tid:
            raise HTTPException(status_code=404, detail=f"Run not found: {run_id}")
        return _sales_analytics_report(tid, run_id)

    runs = _runs_repo().list_by_tenant(tid)
    completed = [
        run for run in runs
        if run.status == "completed" and "sales-analytics" in (run.output_dir or "")
    ]
    if completed:
        return _sales_analytics_report(tid, completed[0].run_id)
    raise HTTPException(
        status_code=404,
        detail=f"No completed sales analytics runs found for tenant '{tid}'.",
    )


@app.post("/sales-audit/run", tags=["Sales Audit"])
def run_sales_audit(
    background_tasks: BackgroundTasks,
    output_dir: str = Form("", description="Output directory mirror; analytics are stored in Postgres"),
    date_from: str = Form(..., description="Start date"),
    date_to: str = Form(..., description="End date"),
    category_id: Optional[List[str]] = Form(None, description="Deal category IDs"),
    responsible_id: Optional[List[str]] = Form(None, description="ASSIGNED_BY_ID; may be repeated"),
    deal_id: Optional[List[str]] = Form(None, description="Specific deal IDs"),
    limit: int = Form(0, description="Max CRM deals per source query, 0 = all"),
    model: str = Form("gpt-4o-mini", description="OpenAI model for sales-quality analysis"),
    transcription_model: str = Form("gpt-4o-transcribe", description="OpenAI transcription model"),
    average_ticket_kzt: Optional[float] = Form(None, description="Average ticket for missed revenue formula"),
    expected_conversion_pct: Optional[float] = Form(None, description="Expected conversion percent"),
    portal_base_url: str = Form("", description="Bitrix portal URL for CRM links; empty = current tenant Bitrix"),
    max_reanimation_cards: int = Form(100, description="Max failed deal cards"),
    reset_outputs: bool = Form(True, description="Clear output directories before running"),
    include_whatsapp_audio: bool = Form(False, description="Download and transcribe WhatsApp audio messages"),
    include_tasks: bool = Form(True, description="Export CRM-linked tasks into Postgres"),
    include_leads: bool = Form(True, description="Export leads into Postgres"),
    include_revenue: bool = Form(True, description="Export sale orders, payments, and invoices into Postgres"),
    wait: bool = Form(False, description="Run synchronously and return report"),
    crm_webhook_url: str | None = Security(_webhook_header),
    whatsapp_webhook_url: str | None = Security(_whatsapp_webhook_header),
    openai_key: str | None = Security(_openai_key_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Run the unified AI + Postgres sales audit report."""
    tid = _resolve_tenant_id(x_tenant_id)
    _resolve_bitrix_gateway(crm_webhook_url, tid)
    _resolve_whatsapp_gateway(whatsapp_webhook_url, tid, crm_fallback=crm_webhook_url)
    key = _resolve_openai_key(openai_key, tid)
    resolved_from = _none(date_from)
    resolved_to = _none(date_to)
    if not resolved_from or not resolved_to:
        raise HTTPException(status_code=422, detail="date_from and date_to are required.")

    clean_categories = _clean_form_list(category_id)
    clean_responsible = _clean_form_list(responsible_id)
    clean_deals = _clean_form_list(deal_id)
    _sales_repo()
    profile = _profile_repo(tid).get()
    resolved_average_ticket = (
        average_ticket_kzt
        if average_ticket_kzt is not None
        else (profile.average_ticket_kzt if profile else None)
    )
    resolved_portal_base_url = _resolve_portal_base_url(portal_base_url, tid, crm_webhook_url)

    job_id = uuid.uuid4().hex
    base_dir = Path(output_dir) if _none(output_dir) else _tenant_storage(tid, job_id)
    final_dir = base_dir / "sales-audit"
    try:
        _runs_repo().create(AnalysisRun(
            run_id=job_id,
            tenant_id=tid,
            status="running" if wait else "queued",
            date_from=resolved_from,
            date_to=resolved_to,
            category_ids=clean_categories or [],
            responsible_ids=clean_responsible or [],
            output_dir=str(final_dir),
        ))
    except Exception:
        logger.warning("Failed to persist sales audit run to database: %s", job_id)

    common_kwargs = {
        "tenant_id": tid,
        "run_id": job_id,
        "crm_webhook_url": crm_webhook_url,
        "whatsapp_webhook_url": whatsapp_webhook_url,
        "openai_key": key,
        "base_dir": base_dir,
        "date_from": resolved_from,
        "date_to": resolved_to,
        "category_ids": clean_categories,
        "responsible_ids": clean_responsible,
        "deal_ids": clean_deals,
        "limit": limit,
        "model": model,
        "transcription_model": transcription_model,
        "average_ticket_kzt": resolved_average_ticket,
        "expected_conversion_pct": expected_conversion_pct,
        "portal_base_url": resolved_portal_base_url,
        "max_reanimation_cards": max_reanimation_cards,
        "include_whatsapp_audio": include_whatsapp_audio,
        "include_tasks": include_tasks,
        "include_leads": include_leads,
        "include_revenue": include_revenue,
        "reset_outputs": reset_outputs,
    }

    if wait:
        progress = _SalesAuditProgressReporter(job_id)
        _set_sales_audit_job(
            job_id,
            tenant_id=tid,
            status="running",
            started_at=_now_iso(),
            output_dir=str(final_dir),
        )
        try:
            result = _execute_sales_audit_pipeline(
                **common_kwargs,
                progress_callback=progress,
            )
            progress.complete()
            _set_sales_audit_job(
                job_id,
                status="completed",
                completed_at=_now_iso(),
                output_dir=str(final_dir),
                report=result.get("report"),
                executive_report=result.get("report"),
            )
            return {
                "status": "completed",
                "job_id": job_id,
                "tenant_id": tid,
                "storage": "postgres",
                "output_dir": str(final_dir),
                "report": result.get("report"),
                "executive_report": result.get("report"),
            }
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            progress.fail()
            error = _redact_error_message(exc, crm_webhook_url, whatsapp_webhook_url, key)
            _set_sales_audit_job(
                job_id,
                status="error",
                completed_at=_now_iso(),
                error=error,
                error_type=type(exc).__name__,
            )
            raise HTTPException(status_code=502, detail=error) from exc

    _set_sales_audit_job(
        job_id,
        tenant_id=tid,
        status="queued",
        queued_at=_now_iso(),
        output_dir=str(final_dir),
        progress={
            "stage": "queued",
            "label": "В очереди",
            "current": 0,
            "total": 1,
            "percent": 0,
            "message": "Анализ поставлен в очередь",
            "eta_seconds": None,
            "updated_at": _now_iso(),
        },
        scope={
            "date_from": resolved_from,
            "date_to": resolved_to,
            "category_ids": clean_categories or [],
            "responsible_ids": clean_responsible or [],
            "deal_ids": clean_deals or [],
            "include_tasks": include_tasks,
            "include_leads": include_leads,
            "include_revenue": include_revenue,
            "storage": "postgres",
        },
    )
    background_tasks.add_task(
        _run_sales_audit_background_job,
        job_id=job_id,
        **common_kwargs,
    )
    return {
        "status": "started",
        "job_id": job_id,
        "tenant_id": tid,
        "storage": "postgres",
        "output_dir": str(final_dir),
        "status_url": f"/sales-audit/jobs/{job_id}",
        "report_url": f"/sales-audit/report?run_id={job_id}",
    }


@app.get("/sales-audit/jobs/{job_id}", tags=["Sales Audit"])
def get_sales_audit_job(
    job_id: str,
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Return status for a unified sales audit run."""
    tid = _resolve_tenant_id(x_tenant_id)
    _sales_repo()
    job = _get_sales_audit_job(job_id)
    if job:
        if job.get("tenant_id") and job.get("tenant_id") != tid:
            raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
        return _maybe_expire_memory_job(
            job,
            job_kind="sales audit",
            set_job=_set_sales_audit_job,
        )
    run = _runs_repo().get(job_id)
    if not run or run.tenant_id != tid:
        raise HTTPException(status_code=404, detail=f"Job not found: {job_id}")
    stale_result = _maybe_expire_persisted_run(
        run,
        job_kind="sales audit",
        set_job=_set_sales_audit_job,
    )
    if stale_result.get("status") == "error":
        return stale_result
    result = run.to_dict()
    if run.status == "completed":
        report = _sales_repo().get_sales_audit_report(tenant_id=tid, run_id=job_id)
        if report:
            report = _prepare_sales_audit_report_for_frontend(tid, report)
            result["report"] = report
            result["executive_report"] = report
    return result


@app.get("/sales-audit/report", tags=["Sales Audit"])
def get_sales_audit_report(
    run_id: str = Query("", description="Analysis run ID; empty = latest completed sales audit"),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Return the final unified report JSON."""
    tid = _resolve_tenant_id(x_tenant_id)
    resolved_run_id, report = _get_sales_audit_report_payload(tid, run_id)
    return {
        **report,
        "run_id": resolved_run_id,
        "tenant_id": tid,
    }


@app.get("/sales-audit/interactions", tags=["Sales Audit"])
def get_sales_audit_interactions(
    run_id: str = Query("", description="Analysis run ID; empty = latest completed sales audit"),
    channel: str = Query("", description="Optional channel: whatsapp or call"),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Return flattened interaction rows for calls and WhatsApp dashboard tables."""
    tid = _resolve_tenant_id(x_tenant_id)
    resolved_run_id, report = _get_sales_audit_report_payload(tid, run_id)
    rows = report.get("interaction_index") or []
    normalized_channel = str(channel or "").strip().lower()
    if normalized_channel:
        rows = [
            row
            for row in rows
            if str((row or {}).get("channel") or "").lower() == normalized_channel
        ]
    return {
        "tenant_id": tid,
        "run_id": resolved_run_id,
        "channel": normalized_channel or "all",
        "interactions": rows,
        "total": len(rows),
    }


@app.get("/sales-audit/urgent-alerts", tags=["Sales Audit"])
def get_sales_audit_urgent_alerts(
    run_id: str = Query("", description="Analysis run ID; empty = latest completed sales audit"),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Return active deals that require urgent manager attention."""
    tid = _resolve_tenant_id(x_tenant_id)
    resolved_run_id, report = _get_sales_audit_report_payload(tid, run_id)
    rows = report.get("urgent_alerts") or []
    return {
        "tenant_id": tid,
        "run_id": resolved_run_id,
        "alerts": rows,
        "rows": rows,
        "total": len(rows),
    }


@app.get("/sales-audit/history", tags=["Sales Audit"])
def get_sales_audit_history(
    limit: int = Query(50, ge=1, le=200, description="Max completed reports to return"),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Return completed sales audit reports for the current tenant, newest first."""
    tid = _resolve_tenant_id(x_tenant_id)
    repo = _sales_repo()
    reports = repo.list_sales_audit_reports(tenant_id=tid, limit=limit)
    runs_by_id = {run.run_id: run for run in _runs_repo().list_by_tenant(tid)}
    runs = [
        _sales_audit_history_run(row, tid, runs_by_id.get(str(row.get("run_id") or "")))
        for row in reports
    ]
    return {
        "tenant_id": tid,
        "latest_run_id": runs[0]["id"] if runs else None,
        "runs": runs,
        "summary": {
            "total_runs": len(runs),
            "latest_run_id": runs[0]["id"] if runs else None,
            "source": "postgres:sales_audit_reports",
        },
    }


@app.post("/sales-audit/history/{run_id}/hide", tags=["Sales Audit"])
def hide_sales_audit_history_run(
    run_id: str,
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Hide a completed sales audit report from tenant history without deleting raw data."""
    tid = _resolve_tenant_id(x_tenant_id)
    if not _sales_repo().hide_sales_audit_report(tenant_id=tid, run_id=run_id):
        raise HTTPException(status_code=404, detail=f"Sales audit report not found: {run_id}")
    return {
        "status": "ok",
        "tenant_id": tid,
        "run_id": run_id,
        "hidden": True,
    }


@app.get(
    "/catalog/funnels",
    summary="Список воронок продаж",
    tags=["Catalog"],
)
def get_funnels(
    webhook_url: str | None = Security(_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Возвращает список воронок (crm.dealcategory.list) для выбора в UI."""
    tid = _resolve_tenant_id(x_tenant_id)
    try:
        gateway = _resolve_bitrix_gateway(webhook_url, tid, trace_name="bitrix.catalog")
        funnels = GetCatalogService(gateway=gateway).get_funnels()
    except DomainError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"funnels": funnels}


@app.get(
    "/catalog/managers",
    summary="Список менеджеров",
    tags=["Catalog"],
)
def get_managers(
    webhook_url: str | None = Security(_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Возвращает список пользователей портала (user.get) для выбора менеджера."""
    tid = _resolve_tenant_id(x_tenant_id)
    try:
        gateway = _resolve_bitrix_gateway(webhook_url, tid, trace_name="bitrix.catalog")
        managers = GetCatalogService(gateway=gateway).get_managers()
    except DomainError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"managers": managers}


@app.get(
    "/catalog/funnels-with-managers",
    summary="Воронки с менеджерами",
    tags=["Catalog"],
)
def get_funnels_with_managers(
    date_from: Optional[str] = Query(
        None,
        description="Дата начала (ISO 8601); "
        "ограничивает "
        "сделки для поиска "
        "менеджеров",
    ),
    date_to: Optional[str] = Query(
        None,
        description="Дата конца (ISO 8601); "
        "ограничивает "
        "сделки для поиска "
        "менеджеров",
    ),
    active_only: bool = Query(
        False,
        description="Возвращать "
        "только активных "
        "менеджеров",
    ),
    webhook_url: str | None = Security(_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Возвращает воронки и менеджеров по сделкам в каждой воронке."""
    tid = _resolve_tenant_id(x_tenant_id)
    try:
        gateway = _resolve_bitrix_gateway(webhook_url, tid, trace_name="bitrix.catalog")
        funnels = GetCatalogService(gateway=gateway).get_funnels_with_managers(
            date_from=_none(date_from),
            date_to=_none(date_to),
            active_only=active_only,
        )
    except DomainError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return {"funnels": funnels}


@app.get(
    "/audit/preview",
    summary="Предварительный расчёт аудита",
    tags=["Audit"],
)
def preview_audit(
    funnel_id: Optional[List[str]] = Query(None, description="ID воронок (можно несколько: ?funnel_id=2&funnel_id=4)"),
    date_from: Optional[str] = Query(None, description="Дата начала (ISO 8601)"),
    date_to: Optional[str] = Query(None, description="Дата конца (ISO 8601)"),
    responsible_id: Optional[str] = Query(None, description="ID ответственного по сделке (ASSIGNED_BY_ID; пусто = весь отдел)"),
    webhook_url: str | None = Security(_whatsapp_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Считает сколько обращений, сотрудников и сделок попадёт в аудит **без** запуска экспорта."""
    tid = _resolve_tenant_id(x_tenant_id)
    try:
        gateway = _resolve_whatsapp_gateway(webhook_url, tid, trace_name="bitrix.audit_preview")
        preview = GetCatalogService(gateway=gateway).get_audit_preview(
            funnel_ids=funnel_id or None,
            date_from=_none(date_from),
            date_to=_none(date_to),
            responsible_id=_none(responsible_id),
        )
    except DomainError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return preview


# ---------------------------------------------------------------------------
# AI Audit — full pipeline in one call
# ---------------------------------------------------------------------------


@app.post(
    "/audit/run",
    summary="Запуск AI аудита",
    tags=["Audit"],
)
def run_audit(
    funnel_id: Optional[List[str]] = Form(None, description="ID воронок (можно несколько полей с одним именем)"),
    date_from: Optional[str] = Form(None, description="Дата начала анализа (ISO 8601)"),
    date_to: Optional[str] = Form(None, description="Дата конца анализа (ISO 8601)"),
    responsible_id: Optional[str] = Form(None, description="ID ответственного по сделке (ASSIGNED_BY_ID; пусто = весь отдел)"),
    limit: int = Form(0, description="Лимит сделок (0 = все)"),
    model: str = Form("gpt-4o-mini", description="OpenAI модель для извлечения фич"),
    recommendations_model: str = Form("gpt-4o", description="OpenAI модель для рекомендаций"),
    source_label: Optional[str] = Form(None, description="Метка источника в отчёте"),
    output_dir: str = Form("export/audit", description="Базовая папка вывода"),
    crm_webhook_url: str | None = Security(_webhook_header),
    whatsapp_webhook_url: str | None = Security(_whatsapp_webhook_header),
    openai_key: str | None = Security(_openai_key_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Полный AI-аудит: WhatsApp-переписки → фичи → агрегат → рекомендации."""
    tid = _resolve_tenant_id(x_tenant_id)
    crm_available = bool(
        crm_webhook_url
        or _active_bitrix_oauth_token(tid)
        or _get_integrations(tid).bitrix_webhook_url
    )
    key = _resolve_openai_key(openai_key, tid)

    clean_funnels = [f for f in (funnel_id or []) if _none(f)] or None
    resolved_responsible = _none(responsible_id)

    funnel_slug = ("funnels_" + "_".join(clean_funnels)) if clean_funnels else "all_funnels"
    resolved_output = Path(output_dir) / funnel_slug
    trace_path = resolved_output / "audit-run.trace.json"

    _CALL_DELAY = 0.2

    sink, mem = _tee()
    trace = AuditTraceRecorder(
        trace_path,
        run_name="audit.run",
        request_details={
            "funnel_ids": clean_funnels or [],
            "date_from": _none(date_from),
            "date_to": _none(date_to),
            "responsible_id": resolved_responsible,
            "limit": limit,
            "model": model,
            "recommendations_model": recommendations_model,
            "source_label": _none(source_label) or "",
            "output_dir": resolved_output,
            "call_audit_enabled": crm_available,
        },
    )
    traced_sink = TracedJsonSink(sink, trace)
    request_payload = RunAuditRequest(
        output_dir=resolved_output,
        funnel_ids=clean_funnels,
        date_from=_none(date_from),
        date_to=_none(date_to),
        responsible_id=resolved_responsible,
        limit=limit,
        model=model,
        recommendations_model=recommendations_model,
        source_label=_none(source_label) or "",
    )
    try:
        RunAuditService(
            bitrix_gateway=_resolve_whatsapp_gateway(
                whatsapp_webhook_url,
                tid,
                crm_fallback=crm_webhook_url,
                call_delay=_CALL_DELAY,
                trace=trace,
                trace_name="bitrix.whatsapp",
            ),
            responses_gateway=OpenAiResponsesClient(
                key,
                trace=trace,
                trace_name="openai.responses",
            ),
            sink=traced_sink,
            call_gateway=_resolve_bitrix_gateway(
                crm_webhook_url,
                tid,
                call_delay=_CALL_DELAY,
                trace=trace,
                trace_name="bitrix.crm",
            ) if crm_available else None,
            transcription_gateway=OpenAiTranscriptionClient(
                key,
                trace=trace,
                trace_name="openai.transcription",
            ) if crm_available else None,
            file_downloader=RequestsFileDownloader(
                trace=trace,
                trace_name="recording.download",
            ) if crm_available else None,
            trace=trace,
        ).execute(request_payload)
    except (FileNotFoundError, ValueError) as exc:
        trace.finish(status="error", error=exc)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DomainError as exc:
        trace.finish(status="error", error=exc)
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except Exception as exc:
        trace.finish(status="error", error=exc)
        raise
    trace.finish(status="ok")
    return {
        "status": "ok",
        "data": mem.data,
        "meta": {
            "trace_file": trace_path.as_posix(),
        },
    }


@app.post("/crm/export")
def export_crm(
    date_from: Optional[str] = Form(None, description="Дата начала (ISO 8601)"),
    date_to: Optional[str] = Form(None, description="Дата конца (ISO 8601)"),
    skip_users: bool = Form(False, description="Пропустить экспорт пользователей"),
    skip_activities: bool = Form(False, description="Пропустить экспорт активностей"),
    limit: Optional[int] = Form(None, description="Максимальное число сделок (пусто = все)"),
    webhook_url: str | None = Security(_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Экспорт CRM-снапшота → ``export/``."""
    tid = _resolve_tenant_id(x_tenant_id)
    sink, mem = _tee()
    return _run_service(
        lambda: CrmExportService(
            gateway=_resolve_bitrix_gateway(webhook_url, tid),
            sink=sink,
        ).execute(
            CrmExportRequest(
                output_dir=Path("export"),
                date_from=_none(date_from), date_to=_none(date_to),
                skip_users=skip_users, skip_activities=skip_activities,
                limit=limit,
            )
        ),
        mem,
    )


@app.post("/call-records/scan")
def scan_call_records(
    date_from: Optional[str] = Form(None, description="Дата начала (ISO 8601)"),
    date_to: Optional[str] = Form(None, description="Дата конца (ISO 8601)"),
    limit: int = Form(20, description="Максимальное число записей"),
    responsible_id: Optional[str] = Form(None, description="ID менеджера (пусто = все)"),
    webhook_url: str | None = Security(_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Сканирование записей звонков → ``export/call-records-scan/``."""
    tid = _resolve_tenant_id(x_tenant_id)
    sink, mem = _tee()
    return _run_service(
        lambda: CallRecordsScanService(
            gateway=_resolve_bitrix_gateway(webhook_url, tid),
            sink=sink,
        ).execute(
            CallRecordsScanRequest(
                output_dir=Path("export/call-records-scan"), limit=limit,
                date_from=_none(date_from), date_to=_none(date_to),
                responsible_id=_none(responsible_id),
            )
        ),
        mem,
    )


@app.post("/recordings/download")
def download_recordings(
    source_json: str = Form(
        "export/call-records-scan/recording-candidates.json",
        description="Путь к recording-candidates.json",
    ),
    output_dir: str = Form("export/recordings", description="Папка для аудиофайлов"),
    skip_existing: bool = Form(False, description="Пропускать уже скачанные файлы"),
) -> dict[str, Any]:
    """Скачивание записей звонков на диск → ``export/recordings/``."""
    sink, mem = _tee()
    return _run_service(
        lambda: DownloadRecordingsService(
            downloader=RequestsFileDownloader(), sink=sink,
        ).execute(
            DownloadRecordingsRequest(
                source_json_path=Path(source_json),
                output_dir=Path(output_dir),
                skip_existing=skip_existing,
            )
        ),
        mem,
    )


@app.post(
    "/crm/stage-history",
    summary="История переходов по стадиям",
    tags=["CRM"],
)
def export_stage_history(
    date_from: Optional[str] = Form(None, description="Дата начала (ISO 8601)"),
    date_to: Optional[str] = Form(None, description="Дата конца (ISO 8601)"),
    funnel_id: Optional[List[str]] = Form(None, description="ID воронок"),
    deal_ids: Optional[List[str]] = Form(None, description="ID конкретных сделок"),
    responsible_id: Optional[str] = Form(None, description="ID ответственного менеджера"),
    whatsapp_only: bool = Form(False, description="Только WhatsApp-сделки"),
    limit: int = Form(0, description="Максимум сделок (0 = все)"),
    skip_existing: bool = Form(False, description="Пропускать уже экспортированные"),
    output_dir: str = Form("export/stage-history", description="Папка вывода"),
    page_delay: float = Form(0.0, description="Пауза между страницами (сек)"),
    webhook_url: str | None = Security(_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Экспортирует историю переходов по стадиям воронки для каждой сделки."""
    tid = _resolve_tenant_id(x_tenant_id)
    clean_funnels = [f for f in (funnel_id or []) if _none(f)] or None
    sink, mem = _tee()
    return _run_service(
        lambda: StageHistoryService(
            gateway=_resolve_bitrix_gateway(webhook_url, tid, page_delay=page_delay),
            sink=sink,
        ).execute(
            StageHistoryRequest(
                output_dir=Path(output_dir),
                category_ids=clean_funnels,
                deal_ids=deal_ids,
                date_from=_none(date_from),
                date_to=_none(date_to),
                responsible_id=_none(responsible_id),
                whatsapp_only=whatsapp_only,
                limit=limit,
                skip_existing=skip_existing,
            )
        ),
        mem,
    )


@app.post("/whatsapp/export")
def export_whatsapp(
    date_from: Optional[str] = Form(None, description="Дата начала (ISO 8601)"),
    date_to: Optional[str] = Form(None, description="Дата конца (ISO 8601)"),
    limit: int = Form(100, description="Максимальное число сделок"),
    deal_ids: Optional[List[str]] = Form(None, description="ID сделок (напр. 51056)"),
    funnel_id: Optional[List[str]] = Form(None, description="ID воронок (можно несколько)"),
    responsible_id: Optional[str] = Form(None, description="ID менеджера (ASSIGNED_BY_ID)"),
    exclude_system_messages: bool = Form(False, description="Исключить системные сообщения"),
    page_delay: float = Form(0.3, description="Пауза между страницами (сек)"),
    webhook_url: str | None = Security(_whatsapp_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Экспорт WhatsApp через Open Lines API → ``export/whatsapp-timeline/``."""
    tid = _resolve_tenant_id(x_tenant_id)
    clean_funnels = [f for f in (funnel_id or []) if _none(f)] or None
    sink, mem = _tee()
    return _run_service(
        lambda: WhatsAppExportService(
            gateway=_resolve_whatsapp_gateway(webhook_url, tid, page_delay=page_delay),
            sink=sink,
        ).execute(
            WhatsAppExportRequest(
                output_dir=Path("export/whatsapp-timeline"), limit=limit,
                date_from=_none(date_from), date_to=_none(date_to),
                deal_ids=deal_ids, skip_existing=False,
                include_system_messages=not exclude_system_messages,
                category_ids=clean_funnels,
                responsible_id=_none(responsible_id),
            )
        ),
        mem,
    )


@app.post("/whatsapp-timeline/export")
def export_whatsapp_timeline(
    date_from: Optional[str] = Form(None, description="Дата начала (ISO 8601)"),
    date_to: Optional[str] = Form(None, description="Дата конца (ISO 8601)"),
    limit: int = Form(100, description="Максимальное число сделок"),
    deal_ids: Optional[List[str]] = Form(None, description="ID сделок (напр. 51056)"),
    funnel_id: Optional[List[str]] = Form(None, description="ID воронок (можно несколько)"),
    responsible_id: Optional[str] = Form(None, description="ID менеджера (ASSIGNED_BY_ID)"),
    skip_existing: bool = Form(False, description="Пропускать уже экспортированные сделки"),
    page_delay: float = Form(0.0, description="Пауза между страницами (сек)"),
    output_dir: str = Form("export/whatsapp-timeline", description="Папка вывода"),
    webhook_url: str | None = Security(_whatsapp_webhook_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Экспорт WhatsApp через timeline-комментарии (Wazzup-маркеры) → ``export/whatsapp-timeline/``."""
    tid = _resolve_tenant_id(x_tenant_id)
    clean_funnels = [f for f in (funnel_id or []) if _none(f)] or None
    sink, mem = _tee()
    return _run_service(
        lambda: WhatsAppTimelineExportService(
            gateway=_resolve_whatsapp_gateway(webhook_url, tid, page_delay=page_delay),
            sink=sink,
        ).execute(
            WhatsAppTimelineExportRequest(
                output_dir=Path(output_dir), limit=limit,
                date_from=_none(date_from), date_to=_none(date_to),
                deal_ids=deal_ids, skip_existing=skip_existing,
                category_ids=clean_funnels,
                responsible_id=_none(responsible_id),
            )
        ),
        mem,
    )


# ---------------------------------------------------------------------------
# OpenAI pipeline endpoints
# ---------------------------------------------------------------------------


@app.post("/transcribe/recordings")
def transcribe_recordings(
    manifest_path: str = Form(
        "export/recordings/manifest.json",
        description="Путь к manifest.json из /recordings/download",
    ),
    output_dir: str = Form("export/transcripts", description="Папка для транскриптов"),
    model: str = Form("gpt-4o-transcribe", description="Модель Whisper"),
    language: Optional[str] = Form(None, description="Код языка, напр. ru"),
    prompt: Optional[str] = Form(None, description="Подсказка для транскрипции"),
    limit: int = Form(0, description="Максимум файлов (0 = все)"),
    skip_existing: bool = Form(False, description="Пропускать уже транскрибированные"),
    openai_key: str | None = Security(_openai_key_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Транскрипция аудиозаписей через OpenAI Whisper → ``export/transcripts/``."""
    tid = _resolve_tenant_id(x_tenant_id)
    key = _resolve_openai_key(openai_key, tid)
    sink, mem = _tee()
    return _run_service(
        lambda: TranscribeRecordingsService(
            gateway=OpenAiTranscriptionClient(key), sink=sink,
        ).execute(
            TranscribeRecordingsRequest(
                manifest_path=Path(manifest_path),
                output_dir=Path(output_dir),
                model=model, language=language, prompt=prompt,
                limit=limit, skip_existing=skip_existing,
            )
        ),
        mem,
    )


@app.post("/call-features/extract")
def extract_call_features(
    transcript_manifest: str = Form(
        "export/transcripts/manifest.json",
        description="Путь к manifest.json из /transcribe/recordings",
    ),
    call_metadata: str = Form(
        "export/call-records-scan/recording-candidates.json",
        description="Путь к recording-candidates.json (метаданные звонков)",
    ),
    activity_metadata: str = Form(
        "export/call-records-scan/activities.source.json",
        description="Путь к activities.source.json (направление звонка)",
    ),
    output_dir: str = Form("export/call-features", description="Папка для фич"),
    model: str = Form("gpt-4o-mini", description="OpenAI модель"),
    limit: int = Form(0, description="Максимум записей (0 = все)"),
    skip_existing: bool = Form(False, description="Пропускать уже обработанные"),
    openai_key: str | None = Security(_openai_key_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Извлечение фич из транскриптов звонков через OpenAI → ``export/call-features/``."""
    tid = _resolve_tenant_id(x_tenant_id)
    key = _resolve_openai_key(openai_key, tid)
    sink, mem = _tee()
    return _run_service(
        lambda: ExtractCallFeaturesService(
            gateway=OpenAiResponsesClient(key), sink=sink,
        ).execute(
            ExtractCallFeaturesRequest(
                transcript_manifest_path=Path(transcript_manifest),
                output_dir=Path(output_dir),
                call_metadata_path=Path(call_metadata) if call_metadata else None,
                activity_metadata_path=Path(activity_metadata) if activity_metadata else None,
                model=model, limit=limit, skip_existing=skip_existing,
            )
        ),
        mem,
    )


@app.post("/analytics/aggregate")
def aggregate_features(
    features_dir: str = Form(
        "export/call-features/features",
        description="Папка с feature JSON-файлами (звонки или WhatsApp)",
    ),
    output_dir: str = Form(
        "export/call-analytics",
        description="Папка для агрегата",
    ),
    limit: int = Form(0, description="Максимум файлов (0 = все)"),
) -> dict[str, Any]:
    """Агрегация feature-файлов в статистику по отделу продаж."""
    sink, mem = _tee()
    return _run_service(
        lambda: AggregateFeatureService(sink=sink).execute(
            AggregateFeatureRequest(
                features_dir=Path(features_dir),
                output_dir=Path(output_dir),
                limit=limit,
            )
        ),
        mem,
    )


@app.post("/analytics/recommendations")
def generate_recommendations(
    aggregate_path: str = Form(
        "export/call-analytics/aggregate.json",
        description="Путь к aggregate.json из /analytics/aggregate",
    ),
    output_dir: str = Form(
        "export/call-analytics",
        description="Папка для рекомендаций",
    ),
    model: str = Form("gpt-4o", description="OpenAI модель (рекомендуется gpt-4o)"),
    source_label: str = Form("", description="Метка источника (напр. 'звонки апрель 2024')"),
    openai_key: str | None = Security(_openai_key_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Генерация рекомендаций по всему отделу продаж на основе агрегированной статистики."""
    tid = _resolve_tenant_id(x_tenant_id)
    key = _resolve_openai_key(openai_key, tid)
    sink, mem = _tee()
    return _run_service(
        lambda: GenerateRecommendationsService(
            gateway=OpenAiResponsesClient(key), sink=sink,
        ).execute(
            GenerateRecommendationsRequest(
                aggregate_path=Path(aggregate_path),
                output_dir=Path(output_dir),
                model=model,
                source_label=_none(source_label),
            )
        ),
        mem,
    )


@app.post("/whatsapp-features/extract")
def extract_whatsapp_features(
    conversation_report: str = Form(
        "export/whatsapp-timeline/report.json",
        description="Путь к report.json из /whatsapp/export или /whatsapp-timeline/export",
    ),
    conversation_dir: str = Form(
        "export/whatsapp-timeline/conversations",
        description="Резервная папка с JSON-файлами переписок",
    ),
    output_dir: str = Form("export/whatsapp-features", description="Папка для фич"),
    model: str = Form("gpt-4o-mini", description="OpenAI модель"),
    limit: int = Form(0, description="Максимум переписок (0 = все)"),
    skip_existing: bool = Form(False, description="Пропускать уже обработанные"),
    openai_key: str | None = Security(_openai_key_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Извлечение фич из WhatsApp-переписок через OpenAI → ``export/whatsapp-features/``."""
    tid = _resolve_tenant_id(x_tenant_id)
    key = _resolve_openai_key(openai_key, tid)
    sink, mem = _tee()
    return _run_service(
        lambda: ExtractWhatsAppFeaturesService(
            gateway=OpenAiResponsesClient(key), sink=sink,
        ).execute(
            ExtractWhatsAppFeaturesRequest(
                output_dir=Path(output_dir),
                conversation_report_path=Path(conversation_report),
                conversation_dir=Path(conversation_dir),
                model=model, limit=limit, skip_existing=skip_existing,
            )
        ),
        mem,
    )


@app.post("/sales-quality/analyze")
def analyze_sales_quality(
    call_transcript_manifest: str = Form(
        "export/recordings/transcripts/transcripts_manifest.json",
        description="Path to call transcripts manifest; use '-' to skip calls",
    ),
    call_metadata: str = Form(
        "export/call-records-scan/recording-candidates.json",
        description="Path to recording-candidates.json; use '-' if unavailable",
    ),
    activity_metadata: str = Form(
        "export/call-records-scan/activities.source.json",
        description="Path to call activities.source.json; use '-' if unavailable",
    ),
    whatsapp_conversation_dir: str = Form(
        "export/whatsapp-timeline/conversations_filtered",
        description="Directory with filtered WhatsApp conversations; use '-' to skip WhatsApp",
    ),
    users_path: str = Form("", description="Optional users.json for manager names"),
    output_dir: str = Form("export/sales-quality", description="Output directory"),
    model: str = Form("gpt-4o-mini", description="OpenAI model"),
    limit: int = Form(0, description="Max interactions (0 = all)"),
    skip_existing: bool = Form(False, description="Skip already processed interactions"),
    slow_response_threshold_sec: int = Form(
        900,
        description="Slow first-response threshold in seconds",
    ),
    max_chars_per_item: int = Form(
        24000,
        description="Max interaction text chars sent to OpenAI",
    ),
    openai_key: str | None = Security(_openai_key_header),
    x_tenant_id: str | None = Header(None),
) -> dict[str, Any]:
    """Analyze sales-quality signals across calls and WhatsApp."""
    tid = _resolve_tenant_id(x_tenant_id)
    key = _resolve_openai_key(openai_key, tid)
    sink, mem = _tee()
    return _run_service(
        lambda: AnalyzeSalesQualityService(
            gateway=OpenAiResponsesClient(key),
            sink=sink,
        ).execute(
            AnalyzeSalesQualityRequest(
                output_dir=Path(output_dir),
                call_transcript_manifest_path=Path(call_transcript_manifest)
                if _none(call_transcript_manifest) not in ("-", None)
                else None,
                call_metadata_path=Path(call_metadata)
                if _none(call_metadata) not in ("-", None)
                else None,
                activity_metadata_path=Path(activity_metadata)
                if _none(activity_metadata) not in ("-", None)
                else None,
                whatsapp_conversation_dir=Path(whatsapp_conversation_dir)
                if _none(whatsapp_conversation_dir) not in ("-", None)
                else None,
                users_path=Path(users_path) if _none(users_path) else None,
                model=model,
                limit=limit,
                skip_existing=skip_existing,
                slow_response_threshold_sec=slow_response_threshold_sec,
                max_chars_per_item=max_chars_per_item,
            )
        ),
        mem,
    )
