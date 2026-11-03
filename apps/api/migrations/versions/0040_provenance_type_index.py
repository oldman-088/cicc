"""Index entity-scoped provenance event type traversal.

Revision ID: 0040_provenance_type_index
"""
from alembic import op

revision = '0040_provenance_type_index'
down_revision = '0039_relationship_kind_index'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_provenance_entity_type_time_id', 'provenance_events',
                    ['tenant_id', 'entity_id', 'event_type', 'occurred_at', 'id'])


def downgrade():
    op.drop_index('ix_provenance_entity_type_time_id', table_name='provenance_events')
