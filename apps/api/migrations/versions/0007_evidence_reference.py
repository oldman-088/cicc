"""Create tenant-scoped analyst-entered evidence references, not file uploads.

Revision ID: 0007_evidence_reference
"""
from alembic import op
import sqlalchemy as sa
revision = '0007_evidence_reference'
down_revision = '0006_entity_provenance'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('evidence_references',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('entity_id', sa.Uuid(), nullable=False),
        sa.Column('created_by', sa.Uuid(), nullable=False),
        sa.Column('description', sa.String(2000), nullable=False),
        sa.Column('source', sa.String(500), nullable=False),
        sa.Column('reference', sa.String(2048), nullable=True),
        sa.Column('sha256', sa.String(64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id', 'entity_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']),
        sa.ForeignKeyConstraint(['tenant_id', 'created_by'], ['users.tenant_id', 'users.id']))
    op.create_index('ix_evidence_references_tenant_id', 'evidence_references', ['tenant_id'])
    op.create_index('ix_evidence_references_entity_id', 'evidence_references', ['entity_id'])

def downgrade():
    op.drop_index('ix_evidence_references_entity_id', table_name='evidence_references')
    op.drop_index('ix_evidence_references_tenant_id', table_name='evidence_references')
    op.drop_table('evidence_references')
