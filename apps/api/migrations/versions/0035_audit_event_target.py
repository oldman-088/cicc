"""Constrain and index case-history event audit targets.

Revision ID: 0035_audit_event_target
"""
from alembic import op
import sqlalchemy as sa

revision = '0035_audit_event_target'
down_revision = '0034_cisa_attempt_index'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('investigation_events') as batch:
        batch.create_unique_constraint('uq_investigation_event_scope', ['tenant_id', 'investigation_id', 'id'])
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_investigation_event_id', sa.Uuid(), nullable=True))
        batch.create_foreign_key('fk_audit_event_scope', 'investigation_events',
            ['tenant_id', 'target_investigation_id', 'target_investigation_event_id'], ['tenant_id', 'investigation_id', 'id'])
        batch.create_check_constraint('ck_audit_event_has_case', 'target_investigation_event_id IS NULL OR target_investigation_id IS NOT NULL')
    op.create_index('ix_audit_tenant_event_time_id', 'security_audit_events', ['tenant_id', 'target_investigation_event_id', 'occurred_at', 'id'])


def downgrade():
    op.drop_index('ix_audit_tenant_event_time_id', table_name='security_audit_events')
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('ck_audit_event_has_case', type_='check')
        batch.drop_constraint('fk_audit_event_scope', type_='foreignkey')
        batch.drop_column('target_investigation_event_id')
    with op.batch_alter_table('investigation_events') as batch:
        batch.drop_constraint('uq_investigation_event_scope', type_='unique')
