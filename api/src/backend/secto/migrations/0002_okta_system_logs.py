import api.rls
import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0090_attack_paths_cleanup_priority"),
        ("secto", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="OktaSystemLog",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("inserted_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("source_id", models.CharField(max_length=255)),
                ("timestamp", models.DateTimeField()),
                ("event_type", models.CharField(max_length=255)),
                ("display_message", models.CharField(blank=True, max_length=500)),
                ("severity", models.CharField(blank=True, max_length=50)),
                ("outcome", models.JSONField(blank=True, default=dict)),
                ("actor_id", models.CharField(blank=True, max_length=255)),
                ("actor_alternate_id", models.CharField(blank=True, max_length=500)),
                ("actor_display_name", models.CharField(blank=True, max_length=500)),
                ("client_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("user_agent", models.CharField(blank=True, max_length=1000)),
                ("targets", models.JSONField(blank=True, default=list)),
                ("raw_event", models.JSONField(blank=True, default=dict)),
                (
                    "provider",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="secto_okta_system_logs",
                        related_query_name="secto_okta_system_log",
                        to="api.provider",
                    ),
                ),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        to="api.tenant",
                    ),
                ),
            ],
            options={
                "db_table": "secto_okta_system_logs",
                "abstract": False,
                "indexes": [
                    models.Index(
                        fields=["tenant_id", "provider", "timestamp"],
                        name="secto_okta_t_prov_ts",
                    ),
                    models.Index(
                        fields=["tenant_id", "provider", "event_type", "timestamp"],
                        name="secto_okta_event_ts",
                    ),
                ],
            },
        ),
        migrations.AddField(
            model_name="sectologcursor",
            name="okta_system_cursor_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddConstraint(
            model_name="oktasystemlog",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_oktasystemlog",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="oktasystemlog",
            constraint=models.UniqueConstraint(
                fields=("tenant_id", "provider", "source_id"),
                name="unique_secto_okta_system_source",
            ),
        ),
    ]
