"""Constrain evidence audit targets to the tenant and entity.

Revision ID: 0027_audit_evidence_target
"""
from alembic import op
import sqlalchemy as sa
revision = '0027_audit_evidence_target'
down_revision = '0026_entity_kind_index'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_evidence_id',sa.Uuid(),nullable=True))
        batch.create_check_constraint('ck_audit_evidence_has_entity','target_evidence_id IS NULL OR target_entity_id IS NOT NULL')
        batch.create_foreign_key('fk_audit_evidence_scope','evidence_references',
            ['tenant_id','target_entity_id','target_evidence_id'],['tenant_id','entity_id','id'])

def downgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('fk_audit_evidence_scope',type_='foreignkey')
        batch.drop_constraint('ck_audit_evidence_has_entity',type_='check')
        batch.drop_column('target_evidence_id')
