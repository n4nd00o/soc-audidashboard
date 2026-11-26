"""auth: session token hash, pending-MFA flag, TOTP replay guard

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-25 23:00:00.000000
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing sessions cannot be mapped to a token hash: drop them (users simply log in again).
    op.execute("DELETE FROM sessions")
    with op.batch_alter_table("sessions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("token_sha256", sa.String(length=64), nullable=False))
        batch_op.add_column(sa.Column("mfa_pending", sa.Boolean(), nullable=False))
        batch_op.create_index(batch_op.f("ix_sessions_token_sha256"), ["token_sha256"], unique=True)

    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.add_column(sa.Column("totp_last_step", sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("totp_last_step")

    with op.batch_alter_table("sessions", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_sessions_token_sha256"))
        batch_op.drop_column("mfa_pending")
        batch_op.drop_column("token_sha256")
