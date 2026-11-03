"""Index relationship kind filtering in either endpoint direction.

Revision ID: 0039_relationship_kind_index
"""
from alembic import op

revision = '0039_relationship_kind_index'
down_revision = '0038_audit_relationship_target'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_rel_subject_kind_time_id', 'intelligence_relationships', ['tenant_id','subject_id','kind','created_at','id'])
    op.create_index('ix_rel_object_kind_time_id', 'intelligence_relationships', ['tenant_id','object_id','kind','created_at','id'])


def downgrade():
    op.drop_index('ix_rel_object_kind_time_id', table_name='intelligence_relationships')
    op.drop_index('ix_rel_subject_kind_time_id', table_name='intelligence_relationships')
