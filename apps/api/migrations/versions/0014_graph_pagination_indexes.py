"""Index timeline and relationship keyset pagination.

Revision ID: 0014_graph_pagination_indexes
"""
from alembic import op
revision = '0014_graph_pagination_indexes'
down_revision = '0013_audit_pagination_index'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('ix_provenance_tenant_entity_time_id', 'provenance_events', ['tenant_id','entity_id','occurred_at','id'])
    op.create_index('ix_rel_tenant_subject_time_id', 'intelligence_relationships', ['tenant_id','subject_id','created_at','id'])
    op.create_index('ix_rel_tenant_object_time_id', 'intelligence_relationships', ['tenant_id','object_id','created_at','id'])

def downgrade():
    op.drop_index('ix_rel_tenant_object_time_id', table_name='intelligence_relationships')
    op.drop_index('ix_rel_tenant_subject_time_id', table_name='intelligence_relationships')
    op.drop_index('ix_provenance_tenant_entity_time_id', table_name='provenance_events')
