"""Index case-scoped event-type history traversal.

Revision ID: 0036_case_event_type_index
"""
from alembic import op

revision = '0036_case_event_type_index'
down_revision = '0035_audit_event_target'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_investigation_events_scope_type_time_id', 'investigation_events',
                    ['tenant_id', 'investigation_id', 'event_type', 'occurred_at', 'id'])


def downgrade():
    op.drop_index('ix_investigation_events_scope_type_time_id', table_name='investigation_events')
