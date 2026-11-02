"""Add analyst notes to tenant-scoped investigations.

Revision ID: 0022_investigation_notes
"""
from alembic import op
import sqlalchemy as sa
revision = '0022_investigation_notes'
down_revision = '0021_investigation_assignment'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('investigation_notes',
        sa.Column('id',sa.Uuid(),primary_key=True),
        sa.Column('tenant_id',sa.Uuid(),sa.ForeignKey('tenants.id'),nullable=False),
        sa.Column('investigation_id',sa.Uuid(),nullable=False),
        sa.Column('author_id',sa.Uuid(),nullable=False),
        sa.Column('body',sa.String(4000),nullable=False),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.ForeignKeyConstraint(['tenant_id','investigation_id'],['investigations.tenant_id','investigations.id']),
        sa.ForeignKeyConstraint(['tenant_id','author_id'],['users.tenant_id','users.id']))
    op.create_index('ix_investigation_notes_scope_time_id','investigation_notes',['tenant_id','investigation_id','created_at','id'])

def downgrade():
    op.drop_index('ix_investigation_notes_scope_time_id',table_name='investigation_notes')
    op.drop_table('investigation_notes')
