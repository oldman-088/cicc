"""Create the initial tenant-scoped intelligence graph.

Revision ID: 0001_initial_graph
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0001_initial_graph'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    json_type = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')
    op.create_table('tenants',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False))
    op.create_table('intelligence_entities',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('source', sa.String(500), nullable=False),
        sa.Column('source_reference', sa.String(2048)),
        sa.Column('properties', json_type, nullable=False),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('tenant_id', 'id'))
    op.create_index('ix_intelligence_entities_tenant_id', 'intelligence_entities', ['tenant_id'])
    op.create_table('intelligence_relationships',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('subject_id', sa.Uuid(), nullable=False),
        sa.Column('object_id', sa.Uuid(), nullable=False),
        sa.Column('kind', sa.String(64), nullable=False),
        sa.Column('source', sa.String(500), nullable=False),
        sa.Column('provenance', json_type, nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id', 'subject_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']),
        sa.ForeignKeyConstraint(['tenant_id', 'object_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']))
    op.create_index('ix_intelligence_relationships_tenant_id', 'intelligence_relationships', ['tenant_id'])


def downgrade():
    op.drop_index('ix_intelligence_relationships_tenant_id', table_name='intelligence_relationships')
    op.drop_table('intelligence_relationships')
    op.drop_index('ix_intelligence_entities_tenant_id', table_name='intelligence_entities')
    op.drop_table('intelligence_entities')
    op.drop_table('tenants')
