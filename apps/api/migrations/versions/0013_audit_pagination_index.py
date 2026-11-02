"""Index tenant audit history by event time and ID.

Revision ID: 0013_audit_pagination_index
"""
from alembic import op
revision = '0013_audit_pagination_index'
down_revision = '0012_cisa_sync_attempts'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('ix_audit_tenant_time_id', 'security_audit_events', ['tenant_id', 'occurred_at', 'id'])

def downgrade():
    op.drop_index('ix_audit_tenant_time_id', table_name='security_audit_events')
