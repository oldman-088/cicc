"""Attach a tenant-scoped investigation target to security audit events.

Revision ID: 0018_audit_investigation_target
"""
from alembic import op
import sqlalchemy as sa
revision = '0018_audit_investigation_target'
down_revision = '0017_investigations'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_investigation_id', sa.Uuid(), nullable=True))
        batch.create_foreign_key('fk_audit_target_tenant_investigation', 'investigations', ['tenant_id','target_investigation_id'], ['tenant_id','id'])

def downgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('fk_audit_target_tenant_investigation', type_='foreignkey')
        batch.drop_column('target_investigation_id')
