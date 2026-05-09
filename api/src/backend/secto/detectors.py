from collections import defaultdict
from datetime import datetime, timedelta, timezone

from api.db_utils import rls_transaction

from .models import M365SignInLog, SectoThreat

OFFICE_HOME_APP_ID = "4765445b-32c6-49b0-83e6-1d93765276ca"
SESSION_HIJACKING_RULE_ID = "signin_session_cookie_hijacking"
SESSION_HIJACKING_LOOKBACK = timedelta(hours=24)


def detect_session_hijacking(
    tenant_id: str,
    provider_id: str,
    now: datetime | None = None,
) -> list[SectoThreat]:
    now = now or datetime.now(timezone.utc)
    window_start = now - SESSION_HIJACKING_LOOKBACK

    with rls_transaction(tenant_id):
        events = list(
            M365SignInLog.objects.filter(
                tenant_id=tenant_id,
                provider_id=provider_id,
                timestamp__gte=window_start,
                timestamp__lte=now,
                client_app_used="Browser",
            )
            .exclude(session_id="")
            .order_by("session_id", "timestamp")
        )

    sessions = defaultdict(list)
    for event in events:
        sessions[event.session_id].append(event)

    threats = []
    for session_events in sessions.values():
        threat = _detect_session_hijacking_for_session(
            tenant_id=tenant_id,
            provider_id=provider_id,
            events=session_events,
        )
        if threat:
            threats.append(threat)

    return threats


def _detect_session_hijacking_for_session(
    tenant_id: str,
    provider_id: str,
    events: list[M365SignInLog],
) -> SectoThreat | None:
    office_home = next(
        (
            event
            for event in events
            if event.app_id == OFFICE_HOME_APP_ID
            and event.is_interactive
            and _is_successful_signin(event)
        ),
        None,
    )
    if office_home is None:
        return None

    origin_country = _country(office_home)
    if not origin_country:
        return None

    suspicious_events = [
        event
        for event in events
        if event.timestamp > office_home.timestamp
        and event.app_id != OFFICE_HOME_APP_ID
        and _country(event)
        and _country(event) != origin_country
    ]
    if not suspicious_events:
        return None

    first_suspicious = suspicious_events[0]
    last_suspicious = suspicious_events[-1]
    user = first_suspicious.user_principal_name or first_suspicious.user_id
    countries = _unique(_country(event) for event in suspicious_events)
    source_ips = _unique(
        str(event.ip_address) if event.ip_address else "" for event in suspicious_events
    )
    applications = _unique(event.app_display_name for event in suspicious_events)

    defaults = {
        "title": "Microsoft 365 session cookie hijacking",
        "description": (
            "Office Home authentication was followed by browser access from a "
            "different country in the same Microsoft 365 session."
        ),
        "severity": SectoThreat.SeverityChoices.CRITICAL,
        "status": SectoThreat.StatusChoices.OPEN,
        "first_seen": office_home.timestamp,
        "last_seen": last_suspicious.timestamp,
        "affected_users": [user] if user else [],
        "source_ip_addresses": source_ips,
        "countries": countries,
        "related_events_count": len(suspicious_events) + 1,
        "evidence": {
            "origin_country": origin_country,
            "origin_ip": str(office_home.ip_address) if office_home.ip_address else "",
            "applications": applications,
            "event_ids": [str(office_home.id)]
            + [str(event.id) for event in suspicious_events],
        },
    }

    with rls_transaction(tenant_id):
        threat, _ = SectoThreat.objects.update_or_create(
            tenant_id=tenant_id,
            provider_id=provider_id,
            rule_id=SESSION_HIJACKING_RULE_ID,
            session_id=office_home.session_id,
            defaults=defaults,
        )
    return threat


def _country(event: M365SignInLog) -> str:
    location = event.location or {}
    country = location.get("countryOrRegion") or location.get("country")
    return country or ""


def _is_successful_signin(event: M365SignInLog) -> bool:
    status = event.status or {}
    return str(status.get("errorCode")) == "0"


def _unique(values) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
