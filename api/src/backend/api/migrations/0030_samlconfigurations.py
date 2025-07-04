# Generated by Django 5.1.8 on 2025-05-15 09:54

import uuid

import django.db.models.deletion
from django.db import migrations, models

import api.rls


class Migration(migrations.Migration):
    dependencies = [
        ("api", "0029_findings_check_index_parent"),
    ]

    operations = [
        migrations.CreateModel(
            name="SAMLDomainIndex",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("email_domain", models.CharField(max_length=254, unique=True)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "saml_domain_index",
            },
        ),
        migrations.AddConstraint(
            model_name="samldomainindex",
            constraint=models.UniqueConstraint(
                fields=("email_domain", "tenant"),
                name="unique_resources_by_email_domain",
            ),
        ),
        migrations.AddConstraint(
            model_name="samldomainindex",
            constraint=api.rls.BaseSecurityConstraint(
                name="statements_on_samldomainindex",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.CreateModel(
            name="SAMLConfiguration",
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
                (
                    "email_domain",
                    models.CharField(
                        help_text="Email domain used to identify the tenant, e.g. prowlerdemo.com",
                        max_length=254,
                        unique=True,
                    ),
                ),
                (
                    "metadata_xml",
                    models.TextField(
                        help_text="Raw IdP metadata XML to configure SingleSignOnService, certificates, etc."
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "tenant",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE, to="api.tenant"
                    ),
                ),
            ],
            options={
                "db_table": "saml_configurations",
            },
        ),
        migrations.AddConstraint(
            model_name="samlconfiguration",
            constraint=api.rls.RowLevelSecurityConstraint(
                "tenant_id",
                name="rls_on_samlconfiguration",
                statements=["SELECT", "INSERT", "UPDATE", "DELETE"],
            ),
        ),
        migrations.AddConstraint(
            model_name="samlconfiguration",
            constraint=models.UniqueConstraint(
                fields=("tenant",), name="unique_samlconfig_per_tenant"
            ),
        ),
        migrations.AlterField(
            model_name="integration",
            name="integration_type",
            field=api.db_utils.IntegrationTypeEnumField(
                choices=[
                    ("amazon_s3", "Amazon S3"),
                    ("aws_security_hub", "AWS Security Hub"),
                    ("jira", "JIRA"),
                    ("slack", "Slack"),
                ]
            ),
        ),
    ]
