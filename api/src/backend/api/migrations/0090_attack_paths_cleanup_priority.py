from django.db import migrations

import api.db_utils

TASK_NAME = "attack-paths-cleanup-stale-scans"
PROVIDER_CHOICES = [
    ("aws", "AWS"),
    ("azure", "Azure"),
    ("gcp", "GCP"),
    ("kubernetes", "Kubernetes"),
    ("m365", "M365"),
    ("github", "GitHub"),
    ("mongodbatlas", "MongoDB Atlas"),
    ("iac", "IaC"),
    ("oraclecloud", "Oracle Cloud Infrastructure"),
    ("alibabacloud", "Alibaba Cloud"),
    ("cloudflare", "Cloudflare"),
    ("openstack", "OpenStack"),
    ("image", "Image"),
    ("googleworkspace", "Google Workspace"),
    ("vercel", "Vercel"),
    ("okta", "Okta"),
]


def set_cleanup_priority(apps, _schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name=TASK_NAME).update(priority=0)


def unset_cleanup_priority(apps, _schema_editor):
    PeriodicTask = apps.get_model("django_celery_beat", "PeriodicTask")
    PeriodicTask.objects.filter(name=TASK_NAME).update(priority=None)


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0089_backfill_finding_group_status_muted"),
    ]

    operations = [
        migrations.AlterField(
            model_name="provider",
            name="provider",
            field=api.db_utils.ProviderEnumField(
                choices=PROVIDER_CHOICES,
                default="aws",
            ),
        ),
        migrations.RunSQL(
            "ALTER TYPE provider ADD VALUE IF NOT EXISTS 'okta';",
            reverse_sql=migrations.RunSQL.noop,
        ),
        migrations.RunPython(set_cleanup_priority, unset_cleanup_priority),
    ]
