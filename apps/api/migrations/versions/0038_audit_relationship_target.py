"""Enforce entity and relationship scoped audit targets for either endpoint.

Revision ID: 0038_audit_relationship_target
"""
from alembic import op
import sqlalchemy as sa

revision = '0038_audit_relationship_target'
down_revision = '0037_case_note_author_index'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('intelligence_relationships') as batch:
        batch.create_unique_constraint('uq_relationship_audit_scope', ['tenant_id', 'id', 'subject_id', 'object_id'])
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_relationship_id', sa.Uuid(), nullable=True))
        batch.add_column(sa.Column('relationship_subject_id', sa.Uuid(), nullable=True))
        batch.add_column(sa.Column('relationship_object_id', sa.Uuid(), nullable=True))
        batch.create_foreign_key('fk_audit_relationship_scope', 'intelligence_relationships',
            ['tenant_id', 'target_relationship_id', 'relationship_subject_id', 'relationship_object_id'],
            ['tenant_id', 'id', 'subject_id', 'object_id'])
        batch.create_check_constraint('ck_audit_relationship_endpoint',
            '(target_relationship_id IS NULL AND relationship_subject_id IS NULL AND relationship_object_id IS NULL) OR '
            '(target_relationship_id IS NOT NULL AND relationship_subject_id IS NOT NULL AND relationship_object_id IS NOT NULL '
            'AND target_entity_id IS NOT NULL AND (target_entity_id = relationship_subject_id OR target_entity_id = relationship_object_id))')
    op.create_index('ix_audit_tenant_relationship_time_id', 'security_audit_events', ['tenant_id', 'target_relationship_id', 'occurred_at', 'id'])


def downgrade():
    op.drop_index('ix_audit_tenant_relationship_time_id', table_name='security_audit_events')
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('ck_audit_relationship_endpoint', type_='check')
        batch.drop_constraint('fk_audit_relationship_scope', type_='foreignkey')
        batch.drop_column('relationship_object_id')
        batch.drop_column('relationship_subject_id')
        batch.drop_column('target_relationship_id')
    with op.batch_alter_table('intelligence_relationships') as batch:
        batch.drop_constraint('uq_relationship_audit_scope', type_='unique')
