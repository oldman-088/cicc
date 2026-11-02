"""Add experimental manual intelligence provenance and audit target.

Revision ID: 0006_entity_provenance
"""
from alembic import op
import sqlalchemy as sa
revision = '0006_entity_provenance'
down_revision = '0005_audit_roles'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('intelligence_entities') as batch:
        batch.add_column(sa.Column('confidence', sa.Integer(), nullable=True))
        batch.add_column(sa.Column('verification_status', sa.String(32), nullable=False, server_default='unverified'))
        batch.add_column(sa.Column('created_by', sa.Uuid(), nullable=True))
        batch.create_check_constraint('ck_entity_confidence', 'confidence IS NULL OR (confidence >= 0 AND confidence <= 100)')
        batch.create_foreign_key('fk_entity_creator_tenant_user', 'users', ['tenant_id', 'created_by'], ['tenant_id', 'id'])
    with op.batch_alter_table('security_audit_events') as batch:
        batch.add_column(sa.Column('target_entity_id', sa.Uuid(), nullable=True))
        batch.create_foreign_key('fk_audit_entity_tenant', 'intelligence_entities', ['tenant_id', 'target_entity_id'], ['tenant_id', 'id'])

def downgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_constraint('fk_audit_entity_tenant', type_='foreignkey')
        batch.drop_column('target_entity_id')
    with op.batch_alter_table('intelligence_entities') as batch:
        batch.drop_constraint('fk_entity_creator_tenant_user', type_='foreignkey')
        batch.drop_constraint('ck_entity_confidence', type_='check')
        batch.drop_column('created_by')
        batch.drop_column('verification_status')
        batch.drop_column('confidence')
