"""Attach tenant-scoped target users to administrative audit events.

Revision ID: 0004_audit_target
"""
from alembic import op
import sqlalchemy as sa
revision = '0004_audit_target'
down_revision = '0003_audit_rate_limit'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_user_id', sa.Uuid(), nullable=True))
        batch.create_foreign_key('fk_audit_target_tenant_user', 'users', ['tenant_id', 'target_user_id'], ['tenant_id', 'id'])

def downgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('fk_audit_target_tenant_user', type_='foreignkey')
        batch.drop_column('target_user_id')
