"""Add version for optimistic concurrency of intelligence changes.

Revision ID: 0009_entity_version
"""
from alembic import op
import sqlalchemy as sa
revision = '0009_entity_version'
down_revision = '0008_provenance_events'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('intelligence_entities', sa.Column('version', sa.Integer(), nullable=False, server_default='1'))

def downgrade():
    with op.batch_alter_table('intelligence_entities') as batch:
        batch.drop_column('version')
