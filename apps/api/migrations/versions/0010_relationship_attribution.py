"""Add analyst, optional evidence reference and confidence to relationships.

Revision ID: 0010_relationship_attribution
"""
from alembic import op
import sqlalchemy as sa
revision = '0010_relationship_attribution'
down_revision = '0009_entity_version'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('intelligence_relationships') as batch:
        batch.add_column(sa.Column('created_by', sa.Uuid(), nullable=True))
        batch.add_column(sa.Column('evidence_id', sa.Uuid(), nullable=True))
        batch.add_column(sa.Column('confidence', sa.Integer(), nullable=True))
        batch.create_check_constraint('ck_relationship_confidence', 'confidence IS NULL OR (confidence >= 0 AND confidence <= 100)')
        batch.create_foreign_key('fk_relationship_actor_tenant', 'users', ['tenant_id','created_by'], ['tenant_id','id'])
        batch.create_foreign_key('fk_relationship_subject_evidence', 'evidence_references', ['tenant_id','subject_id','evidence_id'], ['tenant_id','entity_id','id'])

def downgrade():
    with op.batch_alter_table('intelligence_relationships') as batch:
        batch.drop_constraint('fk_relationship_subject_evidence', type_='foreignkey')
        batch.drop_constraint('fk_relationship_actor_tenant', type_='foreignkey')
        batch.drop_constraint('ck_relationship_confidence', type_='check')
        batch.drop_column('confidence')
        batch.drop_column('evidence_id')
        batch.drop_column('created_by')
