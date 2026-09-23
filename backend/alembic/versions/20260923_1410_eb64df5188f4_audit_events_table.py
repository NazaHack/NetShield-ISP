"""Persistent audit trail.

A durable, append-only record of security-relevant actions: sign-ins, account
and tenant changes, password resets and scan launches. Deliberately has no
foreign keys, so an event survives the deletion of the actor or tenant it names
and a delete elsewhere is never blocked by the trail

Revision ID: eb64df5188f4
Revises: c219627fe952
Create Date: 2026-09-23 14:10:07.797439+00:00

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "eb64df5188f4"
down_revision: str | None = "c219627fe952"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Create the audit_events table."""
    op.create_table(
        "audit_events",
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.UUID(), nullable=True),
        sa.Column("actor_email", sa.String(length=254), nullable=True),
        sa.Column("actor_role", sa.String(length=32), nullable=True),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column("tenant_code_name", sa.String(length=63), nullable=True),
        sa.Column("target", sa.String(length=255), nullable=True),
        sa.Column("detail", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("source_ip", sa.String(length=64), nullable=True),
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
        sa.PrimaryKeyConstraint("id", name=op.f("pk_audit_events")),
    )
    op.create_index(op.f("ix_audit_events_action"), "audit_events", ["action"], unique=False)
    op.create_index(
        "ix_audit_events_action_created_at", "audit_events", ["action", "created_at"], unique=False
    )
    op.create_index(
        op.f("ix_audit_events_created_at"), "audit_events", ["created_at"], unique=False
    )
    op.create_index(
        "ix_audit_events_tenant_id_created_at",
        "audit_events",
        ["tenant_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    """Drop the audit_events table."""
    op.drop_index("ix_audit_events_tenant_id_created_at", table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_created_at"), table_name="audit_events")
    op.drop_index("ix_audit_events_action_created_at", table_name="audit_events")
    op.drop_index(op.f("ix_audit_events_action"), table_name="audit_events")
    op.drop_table("audit_events")
