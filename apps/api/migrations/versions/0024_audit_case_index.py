"""Index tenant case audit history for scoped traversal.

Revision ID: 0024_audit_case_index
"""
from alembic import op
revision = '0024_audit_case_index'
down_revision = '0023_audit_note_target'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('ix_audit_tenant_case_time_id','security_audit_events',['tenant_id','target_investigation_id','occurred_at','id'])

def downgrade():
    op.drop_index('ix_audit_tenant_case_time_id',table_name='security_audit_events')
