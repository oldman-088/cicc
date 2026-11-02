"""Create tenant-scoped CISA snapshot storage; no live connector is enabled.

Revision ID: 0011_cisa_catalog
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision = '0011_cisa_catalog'
down_revision = '0010_relationship_attribution'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('cisa_catalog_states',
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), primary_key=True),
        sa.Column('catalog_version', sa.String(100), nullable=False),
        sa.Column('released_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False))
    op.create_table('cisa_catalog_records',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('entity_id', sa.Uuid(), nullable=False),
        sa.Column('cve_id', sa.String(32), nullable=False),
        sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(), 'postgresql'), nullable=False),
        sa.Column('first_collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('tenant_id', 'cve_id'),
        sa.ForeignKeyConstraint(['tenant_id', 'entity_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']))
    op.create_index('ix_cisa_catalog_records_tenant_id', 'cisa_catalog_records', ['tenant_id'])

def downgrade():
    op.drop_index('ix_cisa_catalog_records_tenant_id', table_name='cisa_catalog_records')
    op.drop_table('cisa_catalog_records')
    op.drop_table('cisa_catalog_states')
