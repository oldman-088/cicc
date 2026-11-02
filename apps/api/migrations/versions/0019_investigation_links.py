"""Link tenant-scoped investigations and entities.

Revision ID: 0019_investigation_links
"""
from alembic import op
import sqlalchemy as sa
revision = '0019_investigation_links'
down_revision = '0018_audit_investigation_target'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('investigation_entity_links',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('entity_id', sa.Uuid(), nullable=False),
        sa.Column('created_by', sa.Uuid(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id','investigation_id'], ['investigations.tenant_id','investigations.id']),
        sa.ForeignKeyConstraint(['tenant_id','entity_id'], ['intelligence_entities.tenant_id','intelligence_entities.id']),
        sa.ForeignKeyConstraint(['tenant_id','created_by'], ['users.tenant_id','users.id']),
        sa.UniqueConstraint('tenant_id','investigation_id','entity_id', name='uq_investigation_entity_link'))
    op.create_index('ix_investigation_link_scope_id','investigation_entity_links',['tenant_id','investigation_id','id'])

def downgrade():
    op.drop_index('ix_investigation_link_scope_id', table_name='investigation_entity_links')
    op.drop_table('investigation_entity_links')
