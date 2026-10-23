"""Add cpe_nodes to vulnerabilities and cpe to software.

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-23
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "vulnerabilities",
        sa.Column("cpe_nodes", sa.JSON(), nullable=True),
    )
    op.add_column(
        "software",
        sa.Column("cpe", sa.String(512), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("software", "cpe")
    op.drop_column("vulnerabilities", "cpe_nodes")
