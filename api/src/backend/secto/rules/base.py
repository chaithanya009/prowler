import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from django.db import connection

from api.db_utils import rls_transaction

from ..models import SectoThreat


VALID_PROVIDERS = {"m365", "okta"}
VALID_SEVERITIES = {choice.value for choice in SectoThreat.SeverityChoices}


@dataclass(frozen=True)
class RuleContext:
    tenant_id: str
    provider_id: str


@dataclass(frozen=True)
class RuleSpec:
    rule_id: str
    provider: str
    title: str
    description: str
    severity: str
    lookback_minutes: int
    dedup_window_minutes: int
    sql_path: Path

    @classmethod
    def from_metadata(cls, path: Path) -> "RuleSpec":
        data = json.loads(path.read_text())
        assert data["provider"] in VALID_PROVIDERS
        assert data["severity"] in VALID_SEVERITIES
        assert data["lookback_minutes"] > 0
        assert data["dedup_window_minutes"] > 0
        sql_path = path.parent / "rule.sql"
        assert sql_path.exists()

        return cls(
            rule_id=data["rule_id"],
            provider=data["provider"],
            title=data["title"],
            description=data["description"],
            severity=data["severity"],
            lookback_minutes=int(data["lookback_minutes"]),
            dedup_window_minutes=int(data["dedup_window_minutes"]),
            sql_path=sql_path,
        )


class SQLRule:
    def __init__(self, spec: RuleSpec, context: RuleContext):
        self.spec = spec
        self.context = context

    def execute(self) -> list[SectoThreat]:
        rows = self._query()
        return [self._upsert_threat(row) for row in rows]

    def _query(self) -> list[dict[str, Any]]:
        query = self.spec.sql_path.read_text()
        params = [
            self.context.tenant_id,
            self.context.provider_id,
            self.spec.lookback_minutes,
        ]

        with rls_transaction(self.context.tenant_id):
            with connection.cursor() as cursor:
                cursor.execute(query, params)
                columns = [column[0] for column in cursor.description]
                return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def _upsert_threat(self, row: dict[str, Any]) -> SectoThreat:
        alert_key = str(row["alert_key"])
        dedup_window_start = _time_bucket_start(
            row["first_seen"], self.spec.dedup_window_minutes
        )
        defaults = {
            "title": self.spec.title,
            "description": self.spec.description,
            "severity": self.spec.severity,
            "status": SectoThreat.StatusChoices.OPEN,
            "first_seen": row["first_seen"],
            "last_seen": row["last_seen"],
            "affected_users": _as_list(row.get("affected_users")),
            "source_ip_addresses": _as_list(row.get("source_ip_addresses")),
            "countries": _as_list(row.get("countries")),
            "related_events_count": row.get("related_events_count") or 0,
            "evidence": _as_dict(row.get("evidence")),
        }

        with rls_transaction(self.context.tenant_id):
            threat, _ = SectoThreat.objects.update_or_create(
                tenant_id=self.context.tenant_id,
                provider_id=self.context.provider_id,
                rule_id=self.spec.rule_id,
                alert_key=alert_key,
                dedup_window_start=dedup_window_start,
                defaults=defaults,
            )
        return threat


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, tuple):
        return [str(item) for item in value if item]
    if isinstance(value, str):
        return [value]
    raise AssertionError(f"Unexpected list value: {type(value).__name__}")


def _as_dict(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        return json.loads(value)
    raise AssertionError(f"Unexpected dict value: {type(value).__name__}")


def _time_bucket_start(value: datetime, minutes: int) -> datetime:
    assert value.tzinfo is not None
    seconds = minutes * 60
    timestamp = int(value.timestamp())
    return datetime.fromtimestamp(timestamp - timestamp % seconds, tz=value.tzinfo)
