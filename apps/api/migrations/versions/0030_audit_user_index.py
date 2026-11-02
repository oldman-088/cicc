"""Index tenant-scoped user-target audit traversal.

Revision ID: 0030_audit_user_index
"""
from alembic import op
revision = '0030_audit_user_index'
down_revision = '0029_audit_entity_index'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('ix_audit_tenant_user_time_id','security_audit_events',['tenant_id','target_user_id','occurred_at','id'])

def downgrade():
    op.drop_index('ix_audit_tenant_user_time_id',table_name='security_audit_events')
