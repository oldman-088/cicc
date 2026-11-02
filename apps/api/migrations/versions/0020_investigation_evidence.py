"""Associate case-linked entities with their unverified evidence references.

Revision ID: 0020_investigation_evidence
"""
from alembic import op
import sqlalchemy as sa
revision = '0020_investigation_evidence'
down_revision = '0019_investigation_links'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('investigation_evidence_links',
        sa.Column('id',sa.Uuid(),primary_key=True),
        sa.Column('tenant_id',sa.Uuid(),sa.ForeignKey('tenants.id'),nullable=False),
        sa.Column('investigation_id',sa.Uuid(),nullable=False),
        sa.Column('entity_id',sa.Uuid(),nullable=False),
        sa.Column('evidence_id',sa.Uuid(),nullable=False),
        sa.Column('created_by',sa.Uuid(),nullable=False),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.ForeignKeyConstraint(['tenant_id','investigation_id','entity_id'],['investigation_entity_links.tenant_id','investigation_entity_links.investigation_id','investigation_entity_links.entity_id']),
        sa.ForeignKeyConstraint(['tenant_id','entity_id','evidence_id'],['evidence_references.tenant_id','evidence_references.entity_id','evidence_references.id']),
        sa.ForeignKeyConstraint(['tenant_id','created_by'],['users.tenant_id','users.id']),
        sa.UniqueConstraint('tenant_id','investigation_id','evidence_id',name='uq_investigation_evidence_link'))
    op.create_index('ix_investigation_evidence_scope_id','investigation_evidence_links',['tenant_id','investigation_id','id'])

def downgrade():
    op.drop_index('ix_investigation_evidence_scope_id',table_name='investigation_evidence_links')
    op.drop_table('investigation_evidence_links')
