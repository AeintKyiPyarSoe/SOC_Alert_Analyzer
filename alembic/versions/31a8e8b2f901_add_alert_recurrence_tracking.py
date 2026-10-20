"""Add alert recurrence tracking (occurrence_count, first_seen, last_seen)

Revision ID: 31a8e8b2f901
Revises: 22cb4fb86bb9
Create Date: 2026-10-21 00:30:00.000000

"""
from collections.abc import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '31a8e8b2f901'
down_revision: Union[str, Sequence[str], None] = '22cb4fb86bb9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema with recurrence fields."""
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column('occurrence_count', sa.Integer(), nullable=False, server_default=sa.text('1'))
        )
        batch_op.add_column(
            sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.create_index(batch_op.f('ix_alerts_first_seen'), ['first_seen'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerts_last_seen'), ['last_seen'], unique=False)
        batch_op.create_index('idx_alerts_dedup', ['event_type', 'source_type', 'source_ip', 'status', 'last_seen'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('alerts', schema=None) as batch_op:
        batch_op.drop_index('idx_alerts_dedup')
        batch_op.drop_index(batch_op.f('ix_alerts_last_seen'))
        batch_op.drop_index(batch_op.f('ix_alerts_first_seen'))
        batch_op.drop_column('last_seen')
        batch_op.drop_column('first_seen')
        batch_op.drop_column('occurrence_count')
