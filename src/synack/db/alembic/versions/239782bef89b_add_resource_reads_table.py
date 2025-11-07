"""add resource_reads table

Revision ID: 239782bef89b
Revises: 8b478a84c1a6
Create Date: 2025-11-07 06:52:54.727676

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '239782bef89b'
down_revision = '8b478a84c1a6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'resource_reads',
        sa.Column('slug', sa.VARCHAR(20), nullable=False),
        sa.Column('last_marked_read_at', sa.INTEGER, server_default='0'),
        sa.PrimaryKeyConstraint('slug'),
        sa.ForeignKeyConstraint(['slug'], ['targets.slug'])
    )


def downgrade():
    op.drop_table('resource_reads')
