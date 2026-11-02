"""Index tenant/kind/UUID filtered intelligence traversal.

Revision ID: 0026_entity_kind_index
"""
from alembic import op
revision = '0026_entity_kind_index'
down_revision = '0025_session_audit_target'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('ix_entity_tenant_kind_id','intelligence_entities',['tenant_id','kind','id'])

def downgrade():
    op.drop_index('ix_entity_tenant_kind_id',table_name='intelligence_entities')
