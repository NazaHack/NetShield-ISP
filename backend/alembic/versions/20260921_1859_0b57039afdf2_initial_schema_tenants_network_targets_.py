"""Initial schema: tenants, network targets, scans and scan results.

Establishes the ownership chain that every later migration builds on. A tenant
owns its network targets and its scans; a scan owns its results. Deleting a
tenant cascades through all of it, because retaining a former customer's network
map is a liability rather than an asset.

Two constraints in here carry the platform's isolation guarantee and must not be
removed without an equivalent replacement:

* ``uq_scans_id_tenant_id`` exists only so that ``scan_results`` can reference
  ``(id, tenant_id)`` as a pair.
* ``fk_scan_results_scan_id_tenant_id_scans`` makes a scan result whose tenant
  differs from its parent scan's tenant impossible to insert at all.

Revision ID: 0b57039afdf2
Revises:
Create Date: 2026-09-21 18:59:28.181950+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0b57039afdf2"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The PostgreSQL enum backing `scans.status`.
#:
#: Declared here with `create_type=False` so that its lifecycle is explicit in
#: both directions. Left implicit, Alembic creates the type as a side effect of
#: `create_table` but never drops it in `downgrade`, so the next `upgrade` fails
#: with "type scan_status already exists". A migration that cannot be rolled
#: back and reapplied is not a migration anyone can rely on.
scan_status_enum = postgresql.ENUM(
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    name="scan_status",
    create_type=False,
)


def upgrade() -> None:
    """Create the four core tables and the scan status enum."""
    scan_status_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "tenants",
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("code_name", sa.String(length=63), nullable=False),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "code_name ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'",
            name=op.f("ck_tenants_code_name_is_slug"),
        ),
        sa.CheckConstraint("length(btrim(name)) > 0", name=op.f("ck_tenants_name_not_blank")),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_tenants")),
    )
    op.create_index(op.f("ix_tenants_code_name"), "tenants", ["code_name"], unique=True)
    op.create_index(op.f("ix_tenants_created_at"), "tenants", ["created_at"], unique=False)
    op.create_table(
        "network_targets",
        sa.Column("label", sa.String(length=150), nullable=False),
        sa.Column("ip_address_or_cidr", sa.String(length=45), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "ip_address_or_cidr ~ '^[0-9a-fA-F:.]+/[0-9]{1,3}$'",
            name=op.f("ck_network_targets_ip_address_or_cidr_is_cidr"),
        ),
        sa.CheckConstraint(
            "length(btrim(label)) > 0", name=op.f("ck_network_targets_label_not_blank")
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_network_targets_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_network_targets")),
        sa.UniqueConstraint(
            "tenant_id",
            "ip_address_or_cidr",
            name="uq_network_targets_tenant_id_ip_address_or_cidr",
        ),
        sa.UniqueConstraint("tenant_id", "label", name="uq_network_targets_tenant_id_label"),
    )
    op.create_index(
        op.f("ix_network_targets_created_at"), "network_targets", ["created_at"], unique=False
    )
    op.create_index(
        op.f("ix_network_targets_ip_address_or_cidr"),
        "network_targets",
        ["ip_address_or_cidr"],
        unique=False,
    )
    op.create_index(
        op.f("ix_network_targets_tenant_id"), "network_targets", ["tenant_id"], unique=False
    )
    op.create_index(
        "ix_network_targets_tenant_id_created_at",
        "network_targets",
        ["tenant_id", "created_at"],
        unique=False,
    )
    op.create_table(
        "scans",
        sa.Column("status", scan_status_enum, server_default="PENDING", nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "(finished_at IS NULL) OR (status IN ('COMPLETED', 'FAILED'))",
            name=op.f("ck_scans_finished_at_only_when_terminal"),
        ),
        sa.CheckConstraint(
            "(finished_at IS NULL) OR (finished_at >= created_at)",
            name=op.f("ck_scans_finished_at_after_created_at"),
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_scans_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scans")),
        sa.UniqueConstraint("id", "tenant_id", name="uq_scans_id_tenant_id"),
    )
    op.create_index(op.f("ix_scans_created_at"), "scans", ["created_at"], unique=False)
    op.create_index(op.f("ix_scans_status"), "scans", ["status"], unique=False)
    op.create_index(op.f("ix_scans_tenant_id"), "scans", ["tenant_id"], unique=False)
    op.create_index(
        "ix_scans_tenant_id_created_at", "scans", ["tenant_id", "created_at"], unique=False
    )
    op.create_index(
        "ix_scans_tenant_id_status_created_at",
        "scans",
        ["tenant_id", "status", "created_at"],
        unique=False,
    )
    op.create_table(
        "scan_results",
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("host_ip", sa.String(length=45), nullable=False),
        sa.Column(
            "open_ports",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default="[]",
            nullable=False,
        ),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("id", sa.UUID(), server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "jsonb_typeof(open_ports) = 'array'", name=op.f("ck_scan_results_open_ports_is_array")
        ),
        sa.ForeignKeyConstraint(
            ["scan_id", "tenant_id"],
            ["scans.id", "scans.tenant_id"],
            name="fk_scan_results_scan_id_tenant_id_scans",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_scan_results")),
    )
    op.create_index(
        op.f("ix_scan_results_created_at"), "scan_results", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_scan_results_host_ip"), "scan_results", ["host_ip"], unique=False)
    op.create_index(
        "ix_scan_results_open_ports",
        "scan_results",
        ["open_ports"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(op.f("ix_scan_results_scan_id"), "scan_results", ["scan_id"], unique=False)
    op.create_index(op.f("ix_scan_results_tenant_id"), "scan_results", ["tenant_id"], unique=False)
    op.create_index(
        "ix_scan_results_tenant_id_created_at",
        "scan_results",
        ["tenant_id", "created_at"],
        unique=False,
    )
    op.create_index(
        "uq_scan_results_scan_id_host_ip", "scan_results", ["scan_id", "host_ip"], unique=True
    )


def downgrade() -> None:
    """Drop the four core tables and the scan status enum.

    Tables are dropped in reverse dependency order, and the enum type last:
    PostgreSQL refuses to drop a type that a live column still uses.
    """
    op.drop_index("uq_scan_results_scan_id_host_ip", table_name="scan_results")
    op.drop_index("ix_scan_results_tenant_id_created_at", table_name="scan_results")
    op.drop_index(op.f("ix_scan_results_tenant_id"), table_name="scan_results")
    op.drop_index(op.f("ix_scan_results_scan_id"), table_name="scan_results")
    op.drop_index("ix_scan_results_open_ports", table_name="scan_results", postgresql_using="gin")
    op.drop_index(op.f("ix_scan_results_host_ip"), table_name="scan_results")
    op.drop_index(op.f("ix_scan_results_created_at"), table_name="scan_results")
    op.drop_table("scan_results")
    op.drop_index("ix_scans_tenant_id_status_created_at", table_name="scans")
    op.drop_index("ix_scans_tenant_id_created_at", table_name="scans")
    op.drop_index(op.f("ix_scans_tenant_id"), table_name="scans")
    op.drop_index(op.f("ix_scans_status"), table_name="scans")
    op.drop_index(op.f("ix_scans_created_at"), table_name="scans")
    op.drop_table("scans")
    op.drop_index("ix_network_targets_tenant_id_created_at", table_name="network_targets")
    op.drop_index(op.f("ix_network_targets_tenant_id"), table_name="network_targets")
    op.drop_index(op.f("ix_network_targets_ip_address_or_cidr"), table_name="network_targets")
    op.drop_index(op.f("ix_network_targets_created_at"), table_name="network_targets")
    op.drop_table("network_targets")
    op.drop_index(op.f("ix_tenants_created_at"), table_name="tenants")
    op.drop_index(op.f("ix_tenants_code_name"), table_name="tenants")
    op.drop_table("tenants")

    scan_status_enum.drop(op.get_bind(), checkfirst=True)
