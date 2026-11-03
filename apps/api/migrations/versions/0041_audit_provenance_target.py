"""Constrain and index tenant/entity-scoped provenance audit targets.

Revision ID: 0041_audit_provenance_target
"""
from alembic import op
import sqlalchemy as sa

revision = '0041_audit_provenance_target'
down_revision = '0040_provenance_type_index'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('provenance_events') as batch:
        batch.create_unique_constraint('uq_provenance_event_scope', ['tenant_id', 'entity_id', 'id'])
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_provenance_id', sa.Uuid(), nullable=True))
        batch.create_foreign_key('fk_audit_provenance_scope', 'provenance_events',
            ['tenant_id', 'target_entity_id', 'target_provenance_id'], ['tenant_id', 'entity_id', 'id'])
        batch.create_check_constraint('ck_audit_provenance_has_entity', 'target_provenance_id IS NULL OR target_entity_id IS NOT NULL')
    op.create_index('ix_audit_tenant_provenance_time_id', 'security_audit_events', ['tenant_id', 'target_provenance_id', 'occurred_at', 'id'])


def downgrade():
    op.drop_index('ix_audit_tenant_provenance_time_id', table_name='security_audit_events')
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('ck_audit_provenance_has_entity', type_='check')
        batch.drop_constraint('fk_audit_provenance_scope', type_='foreignkey')
        batch.drop_column('target_provenance_id')
    with op.batch_alter_table('provenance_events') as batch:
        batch.drop_constraint('uq_provenance_event_scope', type_='unique')
