from uuid import uuid4

from django.db import models

from api.models import Provider
from api.rls import RowLevelSecurityConstraint, RowLevelSecurityProtectedModel


class M365SignInLog(RowLevelSecurityProtectedModel):
    tenant = models.ForeignKey("api.Tenant", on_delete=models.CASCADE)
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="secto_m365_signin_logs",
        related_query_name="secto_m365_signin_log",
    )
    source_id = models.CharField(max_length=255)
    timestamp = models.DateTimeField()
    app_id = models.CharField(max_length=255, blank=True)
    app_display_name = models.CharField(max_length=255, blank=True)
    client_app_used = models.CharField(max_length=100, blank=True)
    is_interactive = models.BooleanField(default=False)
    session_id = models.CharField(max_length=255, blank=True)
    status = models.JSONField(default=dict, blank=True)
    location = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_id = models.CharField(max_length=255, blank=True)
    user_display_name = models.CharField(max_length=255, blank=True)
    user_principal_name = models.CharField(max_length=255, blank=True)
    raw_event = models.JSONField(default=dict, blank=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "secto_m365_signin_logs"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=["tenant_id", "provider", "source_id"],
                name="unique_secto_m365_signin_source",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "provider", "timestamp"],
                name="secto_signin_t_prov_ts",
            ),
            models.Index(
                fields=["tenant_id", "provider", "session_id", "timestamp"],
                name="secto_signin_session_ts",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "secto-m365-signin-logs"


class M365AuditLog(RowLevelSecurityProtectedModel):
    tenant = models.ForeignKey("api.Tenant", on_delete=models.CASCADE)
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="secto_m365_audit_logs",
        related_query_name="secto_m365_audit_log",
    )
    source_id = models.CharField(max_length=255)
    timestamp = models.DateTimeField()
    activity_display_name = models.CharField(max_length=500, blank=True)
    category = models.CharField(max_length=255, blank=True)
    operation_type = models.CharField(max_length=255, blank=True)
    result = models.CharField(max_length=100, blank=True)
    initiated_by = models.JSONField(default=dict, blank=True)
    target_resources = models.JSONField(default=list, blank=True)
    raw_event = models.JSONField(default=dict, blank=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "secto_m365_audit_logs"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=["tenant_id", "provider", "source_id"],
                name="unique_secto_m365_audit_source",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "provider", "timestamp"],
                name="secto_audit_t_prov_ts",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "secto-m365-audit-logs"


class M365UnifiedAuditLog(RowLevelSecurityProtectedModel):
    tenant = models.ForeignKey("api.Tenant", on_delete=models.CASCADE)
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="secto_m365_unified_audit_logs",
        related_query_name="secto_m365_unified_audit_log",
    )
    source_id = models.CharField(max_length=255)
    timestamp = models.DateTimeField()
    record_type = models.IntegerField(null=True, blank=True)
    operation = models.CharField(max_length=255, blank=True)
    workload = models.CharField(max_length=255, blank=True)
    user_id = models.CharField(max_length=500, blank=True)
    user_principal_name = models.CharField(max_length=500, blank=True)
    client_ip = models.GenericIPAddressField(null=True, blank=True)
    object_id = models.CharField(max_length=1000, blank=True)
    raw_event = models.JSONField(default=dict, blank=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "secto_m365_unified_audit_logs"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=["tenant_id", "provider", "source_id"],
                name="unique_secto_m365_unified_source",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "provider", "timestamp"],
                name="secto_unified_t_prov_ts",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "secto-m365-unified-audit-logs"


class SectoLogCursor(RowLevelSecurityProtectedModel):
    tenant = models.ForeignKey("api.Tenant", on_delete=models.CASCADE)
    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    provider = models.OneToOneField(
        Provider,
        on_delete=models.CASCADE,
        related_name="secto_log_cursor",
        related_query_name="secto_log_cursor",
    )
    signin_cursor_at = models.DateTimeField(null=True, blank=True)
    audit_cursor_at = models.DateTimeField(null=True, blank=True)
    unified_audit_cursor_at = models.DateTimeField(null=True, blank=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "secto_log_cursors"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ]

    class JSONAPIMeta:
        resource_name = "secto-log-cursors"


class SectoThreat(RowLevelSecurityProtectedModel):
    tenant = models.ForeignKey("api.Tenant", on_delete=models.CASCADE)

    class SeverityChoices(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"

    class StatusChoices(models.TextChoices):
        OPEN = "open", "Open"
        RESOLVED = "resolved", "Resolved"

    id = models.UUIDField(primary_key=True, default=uuid4, editable=False)
    inserted_at = models.DateTimeField(auto_now_add=True, editable=False)
    updated_at = models.DateTimeField(auto_now=True, editable=False)
    provider = models.ForeignKey(
        Provider,
        on_delete=models.CASCADE,
        related_name="secto_threats",
        related_query_name="secto_threat",
    )
    rule_id = models.CharField(max_length=255)
    title = models.CharField(max_length=255)
    description = models.TextField()
    severity = models.CharField(
        max_length=20,
        choices=SeverityChoices.choices,
        default=SeverityChoices.MEDIUM,
    )
    status = models.CharField(
        max_length=20,
        choices=StatusChoices.choices,
        default=StatusChoices.OPEN,
    )
    session_id = models.CharField(max_length=255)
    first_seen = models.DateTimeField()
    last_seen = models.DateTimeField()
    affected_users = models.JSONField(default=list, blank=True)
    source_ip_addresses = models.JSONField(default=list, blank=True)
    countries = models.JSONField(default=list, blank=True)
    related_events_count = models.PositiveIntegerField(default=0)
    evidence = models.JSONField(default=dict, blank=True)

    class Meta(RowLevelSecurityProtectedModel.Meta):
        db_table = "secto_threats"
        constraints = [
            RowLevelSecurityConstraint(
                field="tenant_id",
                name="rls_on_%(class)s",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
            models.UniqueConstraint(
                fields=["tenant_id", "provider", "rule_id", "session_id"],
                name="unique_secto_threat_session_rule",
            ),
        ]
        indexes = [
            models.Index(
                fields=["tenant_id", "provider", "last_seen"],
                name="secto_threat_provider_seen",
            ),
            models.Index(
                fields=["tenant_id", "rule_id", "status"],
                name="secto_threat_rule_status",
            ),
        ]

    class JSONAPIMeta:
        resource_name = "secto-threats"
