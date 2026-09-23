"""User accounts, with platform administrator and tenant roles.

Introduces sign-in credentials. Until now the API authenticated service tokens
minted out of band; from here a token is issued to a named account.

The check constraint ``ck_users_role_matches_tenancy`` is load-bearing: it makes
an administrator with a tenant, or a tenant user without one, impossible to
insert. Either would be an identity the authorisation layer could not classify.

Revision ID: 6bd2fc2a3f93
Revises: 0b57039afdf2
Create Date: 2026-09-21 22:09:01.767765+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "6bd2fc2a3f93"
down_revision: str | None = "0b57039afdf2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

#: The PostgreSQL enum backing `users.role`.
#:
#: Declared with `create_type=False` so its lifecycle is explicit in both
#: directions. Left implicit, Alembic creates the type as a side effect of
#: `create_table` but never drops it in `downgrade`, so the next `upgrade` fails
#: with "type user_role already exists".
user_role_enum = postgresql.ENUM(
    "PLATFORM_ADMIN",
    "TENANT_USER",
    name="user_role",
    create_type=False,
)


def upgrade() -> None:
    """Create the users table and the role enum."""
    user_role_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "users",
        sa.Column("email", sa.String(length=254), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("role", user_role_enum, nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default="true", nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
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
            "(role = 'PLATFORM_ADMIN' AND tenant_id IS NULL) OR "
            "(role = 'TENANT_USER' AND tenant_id IS NOT NULL)",
            name=op.f("ck_users_role_matches_tenancy"),
        ),
        sa.CheckConstraint("email = lower(email)", name=op.f("ck_users_email_is_lowercase")),
        sa.CheckConstraint("length(btrim(email)) > 0", name=op.f("ck_users_email_not_blank")),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name=op.f("fk_users_tenant_id_tenants"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_users")),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index(op.f("ix_users_created_at"), "users", ["created_at"], unique=False)
    op.create_index(op.f("ix_users_email"), "users", ["email"], unique=False)
    op.create_index(op.f("ix_users_role"), "users", ["role"], unique=False)
    op.create_index(op.f("ix_users_tenant_id"), "users", ["tenant_id"], unique=False)
    op.create_index("ix_users_tenant_id_email", "users", ["tenant_id", "email"], unique=False)


def downgrade() -> None:
    """Drop the users table and the role enum.

    The enum is dropped last: PostgreSQL refuses to drop a type that a live
    column still uses.
    """
    op.drop_index("ix_users_tenant_id_email", table_name="users")
    op.drop_index(op.f("ix_users_tenant_id"), table_name="users")
    op.drop_index(op.f("ix_users_role"), table_name="users")
    op.drop_index(op.f("ix_users_email"), table_name="users")
    op.drop_index(op.f("ix_users_created_at"), table_name="users")
    op.drop_table("users")

    user_role_enum.drop(op.get_bind(), checkfirst=True)
