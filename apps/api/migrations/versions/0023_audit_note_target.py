"""Add tenant/case scoped note targets to security audit.

Revision ID: 0023_audit_note_target
"""
from alembic import op
import sqlalchemy as sa
revision = '0023_audit_note_target'
down_revision = '0022_investigation_notes'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('investigation_notes') as batch:
        batch.create_unique_constraint('uq_investigation_note_scope', ['tenant_id','investigation_id','id'])
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_note_id',sa.Uuid(),nullable=True))
        batch.create_foreign_key('fk_audit_target_note_scope','investigation_notes',['tenant_id','target_investigation_id','target_note_id'],['tenant_id','investigation_id','id'])
        batch.create_check_constraint('ck_audit_note_has_case','target_note_id IS NULL OR target_investigation_id IS NOT NULL')

def downgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('ck_audit_note_has_case',type_='check')
        batch.drop_constraint('fk_audit_target_note_scope',type_='foreignkey')
        batch.drop_column('target_note_id')
    with op.batch_alter_table('investigation_notes') as batch:
        batch.drop_constraint('uq_investigation_note_scope',type_='unique')
