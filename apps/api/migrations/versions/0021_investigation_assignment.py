"""Add tenant-scoped investigation assignee.

Revision ID: 0021_investigation_assignment
"""
from alembic import op
import sqlalchemy as sa
revision = '0021_investigation_assignment'
down_revision = '0020_investigation_evidence'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('investigations') as batch:
        batch.add_column(sa.Column('assignee_id', sa.Uuid(), nullable=True))
        batch.create_foreign_key('fk_investigation_assignee', 'users', ['tenant_id','assignee_id'], ['tenant_id','id'])

def downgrade():
    with op.batch_alter_table('investigations') as batch:
        batch.drop_constraint('fk_investigation_assignee', type_='foreignkey')
        batch.drop_column('assignee_id')
