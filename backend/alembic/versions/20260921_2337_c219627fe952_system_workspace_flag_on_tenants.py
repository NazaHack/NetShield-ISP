"""Mark tenants the platform provisions for itself.

Ad-hoc scans, run without choosing a customer, still need an owner: every scan
and result in the platform belongs to a tenant, and carving out an exception
would mean rows the isolation rules do not cover. They are attributed to a
workspace the operator never creates, and this flag is what keeps that workspace
out of the customer list.

Existing rows default to false, so no customer is reclassified by this change

Revision ID: c219627fe952
Revises: 6bd2fc2a3f93
Create Date: 2026-09-21 23:37:48.734881+00:00

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c219627fe952"
down_revision: str | None = "6bd2fc2a3f93"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add the system-workspace flag."""
    op.add_column(
        "tenants", sa.Column("is_system", sa.Boolean(), server_default="false", nullable=False)
    )
    op.create_index(op.f("ix_tenants_is_system"), "tenants", ["is_system"], unique=False)


def downgrade() -> None:
    """Remove the system-workspace flag."""
    op.drop_index(op.f("ix_tenants_is_system"), table_name="tenants")
    op.drop_column("tenants", "is_system")
