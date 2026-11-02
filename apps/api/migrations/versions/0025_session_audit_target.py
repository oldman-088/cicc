"""Add an audit snapshot of the session UUID, without blocking session cleanup.

Revision ID: 0025_session_audit_target
"""
from alembic import op
import sqlalchemy as sa

revision = '0025_session_audit_target'
down_revision = '0024_audit_case_index'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_session_id', sa.Uuid(), nullable=True))
        batch.create_check_constraint('ck_audit_session_has_user', 'target_session_id IS NULL OR target_user_id IS NOT NULL')

def downgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('ck_audit_session_has_user', type_='check')
        batch.drop_column('target_session_id')
