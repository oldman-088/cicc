"""Index scoped evidence audit traversal.

Revision ID: 0028_audit_evidence_index
"""
from alembic import op
revision = '0028_audit_evidence_index'
down_revision = '0027_audit_evidence_target'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('ix_audit_tenant_evidence_time_id','security_audit_events',['tenant_id','target_evidence_id','occurred_at','id'])

def downgrade():
    op.drop_index('ix_audit_tenant_evidence_time_id',table_name='security_audit_events')
