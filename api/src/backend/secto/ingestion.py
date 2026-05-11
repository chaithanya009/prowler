import base64
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

import requests
from azure.identity import CertificateCredential, ClientSecretCredential
from django.db import models

from api.db_utils import rls_transaction
from api.models import Provider

from .detectors import detect_session_hijacking
from .models import (
    M365AuditLog,
    M365SignInLog,
    M365UnifiedAuditLog,
    OktaSystemLog,
    SectoLogCursor,
)

GRAPH_BASE_URL = "https://graph.microsoft.com/beta"
GRAPH_AUDIT_PATH = "auditLogs/directoryAudits"
GRAPH_SIGNIN_PATH = "auditLogs/signIns"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"
O365_BASE_URL = "https://manage.office.com/api/v1.0"
O365_CONTENT_TYPES = (
    "Audit.AzureActiveDirectory",
    "Audit.Exchange",
    "Audit.SharePoint",
    "Audit.General",
)
O365_SCOPE = "https://manage.office.com/.default"
OKTA_SYSTEM_LOG_PATH = "/api/v1/logs"
INITIAL_LOOKBACK = timedelta(hours=24)
CURSOR_OVERLAP = timedelta(minutes=10)
GRAPH_PAGE_SIZE = 200
OKTA_PAGE_SIZE = 1000
NON_PREMIUM_SIGNIN_ERROR = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"


@dataclass(frozen=True)
class ProviderState:
    secret: Mapping[str, str]
    signin_start: datetime
    audit_start: datetime
    unified_audit_start: datetime


@dataclass(frozen=True)
class OktaProviderState:
    api_token: str
    org_url: str
    system_start: datetime


def pull_m365_logs(
    tenant_id: str,
    provider_id: str,
    now: datetime | None = None,
) -> dict[str, int]:
    now = now or datetime.now(timezone.utc)
    state = _load_provider_state(tenant_id, provider_id, now)

    signin_records = _fetch_graph_records(
        state.secret,
        GRAPH_SIGNIN_PATH,
        "createdDateTime",
        state.signin_start,
        now,
    )
    audit_records = _fetch_graph_records(
        state.secret,
        GRAPH_AUDIT_PATH,
        "activityDateTime",
        state.audit_start,
        now,
    )
    unified_audit_records = _fetch_unified_audit_records(
        state.secret,
        state.unified_audit_start,
        now,
    )

    signin_events = _store_logs(
        tenant_id,
        M365SignInLog,
        [
            log
            for record in signin_records
            if (log := _build_signin_log(tenant_id, provider_id, record)) is not None
        ],
    )
    audit_events = _store_logs(
        tenant_id,
        M365AuditLog,
        [
            log
            for record in audit_records
            if (log := _build_audit_log(tenant_id, provider_id, record)) is not None
        ],
    )
    unified_audit_events = _store_logs(
        tenant_id,
        M365UnifiedAuditLog,
        [
            log
            for record in unified_audit_records
            if (log := _build_unified_audit_log(tenant_id, provider_id, record))
            is not None
        ],
    )

    with rls_transaction(tenant_id):
        SectoLogCursor.objects.update_or_create(
            tenant_id=tenant_id,
            provider_id=provider_id,
            defaults={
                "signin_cursor_at": now,
                "audit_cursor_at": now,
                "unified_audit_cursor_at": now,
            },
        )

    threats = detect_session_hijacking(
        tenant_id=tenant_id,
        provider_id=provider_id,
        now=now,
    )
    return {
        "signin_events": signin_events,
        "audit_events": audit_events,
        "unified_audit_events": unified_audit_events,
        "threats": len(threats),
    }


def pull_okta_logs(
    tenant_id: str,
    provider_id: str,
    now: datetime | None = None,
) -> dict[str, int]:
    now = now or datetime.now(timezone.utc)
    state = _load_okta_provider_state(tenant_id, provider_id, now)

    records = _fetch_okta_system_logs(
        state.api_token,
        state.org_url,
        state.system_start,
        now,
    )
    system_events = _store_logs(
        tenant_id,
        OktaSystemLog,
        [
            log
            for record in records
            if (log := _build_okta_system_log(tenant_id, provider_id, record))
            is not None
        ],
    )

    with rls_transaction(tenant_id):
        SectoLogCursor.objects.update_or_create(
            tenant_id=tenant_id,
            provider_id=provider_id,
            defaults={"okta_system_cursor_at": now},
        )

    return {"system_events": system_events}


def _load_provider_state(
    tenant_id: str,
    provider_id: str,
    now: datetime,
) -> ProviderState:
    with rls_transaction(tenant_id):
        provider = Provider.objects.select_related("secret").get(
            tenant_id=tenant_id,
            id=provider_id,
        )
        assert provider.provider == Provider.ProviderChoices.M365.value

        cursor = SectoLogCursor.objects.filter(
            tenant_id=tenant_id,
            provider=provider,
        ).first()
        assert provider.secret
        return ProviderState(
            secret=provider.secret.secret,
            signin_start=_cursor_start(
                cursor.signin_cursor_at if cursor else None, now
            ),
            audit_start=_cursor_start(cursor.audit_cursor_at if cursor else None, now),
            unified_audit_start=_cursor_start(
                cursor.unified_audit_cursor_at if cursor else None,
                now,
            ),
        )


def _load_okta_provider_state(
    tenant_id: str,
    provider_id: str,
    now: datetime,
) -> OktaProviderState:
    with rls_transaction(tenant_id):
        provider = Provider.objects.select_related("secret").get(
            tenant_id=tenant_id,
            id=provider_id,
        )
        assert provider.provider == Provider.ProviderChoices.OKTA.value

        cursor = SectoLogCursor.objects.filter(
            tenant_id=tenant_id,
            provider=provider,
        ).first()
        assert provider.secret
        return OktaProviderState(
            api_token=provider.secret.secret["api_token"],
            org_url=f"https://{provider.uid}",
            system_start=_cursor_start(
                cursor.okta_system_cursor_at if cursor else None, now
            ),
        )


def _cursor_start(value: datetime | None, now: datetime) -> datetime:
    if value is None:
        return now - INITIAL_LOOKBACK
    return value - CURSOR_OVERLAP


def _fetch_graph_records(
    secret: Mapping[str, str],
    path: str,
    timestamp_field: str,
    start_time: datetime,
    end_time: datetime,
) -> list[Mapping[str, Any]]:
    token = _build_credential(secret).get_token(GRAPH_SCOPE).token
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    params: dict[str, Any] = {
        "$top": GRAPH_PAGE_SIZE,
        "$filter": (
            f"{timestamp_field} gt {_format_graph_datetime(start_time)} "
            f"and {timestamp_field} le {_format_graph_datetime(end_time)}"
        ),
    }
    url = f"{GRAPH_BASE_URL}/{path}"
    records = []

    while url:
        response = requests.get(url, headers=headers, params=params, timeout=60)
        try:
            response.raise_for_status()
        except requests.HTTPError:
            if (
                path == GRAPH_SIGNIN_PATH
                and _response_error_code(response) == NON_PREMIUM_SIGNIN_ERROR
            ):
                return records
            raise
        body = response.json()
        records.extend(body.get("value", []))
        url = body.get("@odata.nextLink")
        params = {}

    return records


def _fetch_okta_system_logs(
    api_token: str,
    org_url: str,
    start_time: datetime,
    end_time: datetime,
) -> list[Mapping[str, Any]]:
    url = f"{org_url}{OKTA_SYSTEM_LOG_PATH}"
    headers = {
        "Authorization": f"SSWS {api_token}",
        "Accept": "application/json",
    }
    params: dict[str, Any] = {
        "since": _format_graph_datetime(start_time),
        "until": _format_graph_datetime(end_time),
        "sortOrder": "ASCENDING",
        "limit": OKTA_PAGE_SIZE,
    }
    records = []

    while url:
        response = requests.get(url, headers=headers, params=params, timeout=60)
        response.raise_for_status()
        records.extend(
            record for record in response.json() if isinstance(record, Mapping)
        )
        next_link = response.links.get("next", {})
        url = next_link.get("url")
        params = {}

    return records


def _response_error_code(response: requests.Response) -> str | None:
    try:
        body = response.json()
    except ValueError:
        return None

    error = body.get("error")
    if not isinstance(error, Mapping):
        return None
    code = error.get("code")
    if not isinstance(code, str):
        return None
    return code


def _fetch_unified_audit_records(
    secret: Mapping[str, str],
    start_time: datetime,
    end_time: datetime,
) -> list[Mapping[str, Any]]:
    token = _build_credential(secret).get_token(O365_SCOPE).token
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    records = []

    for content_type in O365_CONTENT_TYPES:
        _ensure_o365_subscription(secret, headers, content_type)
        records.extend(
            _fetch_o365_content_records(
                secret, headers, content_type, start_time, end_time
            )
        )

    return records


def _ensure_o365_subscription(
    secret: Mapping[str, str],
    headers: Mapping[str, str],
    content_type: str,
) -> None:
    url = f"{O365_BASE_URL}/{secret['tenant_id']}/activity/feed/subscriptions"
    response = requests.get(
        f"{url}/list",
        headers=headers,
        params={"contentType": content_type},
        timeout=60,
    )
    response.raise_for_status()
    if response.json():
        return

    response = requests.post(
        f"{url}/start",
        headers=headers,
        params={"contentType": content_type},
        timeout=60,
    )
    response.raise_for_status()


def _fetch_o365_content_records(
    secret: Mapping[str, str],
    headers: Mapping[str, str],
    content_type: str,
    start_time: datetime,
    end_time: datetime,
) -> list[Mapping[str, Any]]:
    response = requests.get(
        f"{O365_BASE_URL}/{secret['tenant_id']}/activity/feed/subscriptions/content",
        headers=headers,
        params={
            "contentType": content_type,
            "startTime": _format_o365_datetime(start_time),
            "endTime": _format_o365_datetime(end_time),
        },
        timeout=60,
    )
    response.raise_for_status()

    records = []
    for content in response.json():
        content_uri = content.get("contentUri")
        if not content_uri:
            continue

        response = requests.get(content_uri, headers=headers, timeout=60)
        response.raise_for_status()
        records.extend(_decode_o365_content(response))

    return records


def _decode_o365_content(response: requests.Response) -> list[Mapping[str, Any]]:
    try:
        payload = response.json()
    except ValueError:
        payload = [
            item
            for line in response.text.splitlines()
            for item in json.loads(line or "[]")
        ]

    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Mapping)]
    if isinstance(payload, Mapping):
        return [payload]
    return []


def _store_logs(
    tenant_id: str,
    model: type[models.Model],
    logs: list[models.Model],
) -> int:
    if not logs:
        return 0

    with rls_transaction(tenant_id):
        model.objects.bulk_create(
            logs,
            batch_size=500,
            ignore_conflicts=True,
        )
    return len(logs)


def _build_credential(secret: Mapping[str, str]):
    tenant_id = secret["tenant_id"]
    client_id = secret["client_id"]

    if secret.get("certificate_content"):
        return CertificateCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            certificate_data=base64.b64decode(secret["certificate_content"]),
        )

    return ClientSecretCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        client_secret=secret["client_secret"],
    )


def _build_signin_log(
    tenant_id: str,
    provider_id: str,
    record: Mapping[str, Any],
) -> M365SignInLog | None:
    source_id = record.get("id")
    timestamp = _parse_datetime(record.get("createdDateTime"))
    if not source_id or timestamp is None:
        return None

    return M365SignInLog(
        tenant_id=tenant_id,
        provider_id=provider_id,
        source_id=source_id,
        timestamp=timestamp,
        app_id=record.get("appId") or "",
        app_display_name=record.get("appDisplayName") or "",
        client_app_used=record.get("clientAppUsed") or "",
        is_interactive=bool(record.get("isInteractive")),
        session_id=record.get("sessionId") or "",
        status=record.get("status") or {},
        location=record.get("location") or {},
        ip_address=_normalize_ip(record.get("ipAddress")),
        user_id=record.get("userId") or "",
        user_display_name=record.get("userDisplayName") or "",
        user_principal_name=record.get("userPrincipalName") or "",
        raw_event=dict(record),
    )


def _build_audit_log(
    tenant_id: str,
    provider_id: str,
    record: Mapping[str, Any],
) -> M365AuditLog | None:
    source_id = record.get("id")
    timestamp = _parse_datetime(record.get("activityDateTime"))
    if not source_id or timestamp is None:
        return None

    return M365AuditLog(
        tenant_id=tenant_id,
        provider_id=provider_id,
        source_id=source_id,
        timestamp=timestamp,
        activity_display_name=record.get("activityDisplayName") or "",
        category=record.get("category") or "",
        operation_type=record.get("operationType") or "",
        result=record.get("result") or "",
        initiated_by=record.get("initiatedBy") or {},
        target_resources=record.get("targetResources") or [],
        raw_event=dict(record),
    )


def _build_unified_audit_log(
    tenant_id: str,
    provider_id: str,
    record: Mapping[str, Any],
) -> M365UnifiedAuditLog | None:
    source_id = record.get("Id")
    timestamp = _parse_datetime(record.get("CreationTime"))
    if not source_id or timestamp is None:
        return None

    return M365UnifiedAuditLog(
        tenant_id=tenant_id,
        provider_id=provider_id,
        source_id=source_id,
        timestamp=timestamp,
        record_type=_to_int(record.get("RecordType")),
        operation=record.get("Operation") or "",
        workload=record.get("Workload") or "",
        user_id=record.get("UserId") or "",
        user_principal_name=record.get("UserPrincipalName") or "",
        client_ip=_normalize_ip(record.get("ClientIP")),
        object_id=record.get("ObjectId") or "",
        raw_event=dict(record),
    )


def _build_okta_system_log(
    tenant_id: str,
    provider_id: str,
    record: Mapping[str, Any],
) -> OktaSystemLog | None:
    source_id = record.get("uuid")
    timestamp = _parse_datetime(record.get("published"))
    event_type = record.get("eventType")
    if not source_id or timestamp is None or not event_type:
        return None

    actor = _mapping(record.get("actor"))
    client = _mapping(record.get("client"))
    user_agent = _mapping(client.get("userAgent"))

    return OktaSystemLog(
        tenant_id=tenant_id,
        provider_id=provider_id,
        source_id=source_id,
        timestamp=timestamp,
        event_type=event_type,
        display_message=record.get("displayMessage") or "",
        severity=record.get("severity") or "",
        outcome=_mapping(record.get("outcome")),
        actor_id=actor.get("id") or "",
        actor_alternate_id=actor.get("alternateId") or "",
        actor_display_name=actor.get("displayName") or "",
        client_ip=_normalize_ip(client.get("ipAddress")),
        user_agent=user_agent.get("rawUserAgent") or "",
        targets=record.get("target") or [],
        raw_event=dict(record),
    )


def _mapping(value: Any) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return value
    return {}


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.astimezone(timezone.utc)


def _format_graph_datetime(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _format_o365_datetime(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "")
    )


def _normalize_ip(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _to_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
