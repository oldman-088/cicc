"""Track source synchronization attempts separately from successful imports.

Revision ID: 0012_cisa_sync_attempts
"""
from alembic import op
import sqlalchemy as sa
revision = '0012_cisa_sync_attempts'
down_revision = '0011_cisa_catalog'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('cisa_sync_attempts',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_code', sa.String(32), nullable=True),
        sa.CheckConstraint("status IN ('running', 'succeeded', 'failed', 'abandoned')", name='ck_cisa_sync_status'),
        sa.ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']))
    op.create_index('ix_cisa_sync_attempts_tenant_id', 'cisa_sync_attempts', ['tenant_id'])

def downgrade():
    op.drop_index('ix_cisa_sync_attempts_tenant_id', table_name='cisa_sync_attempts')
    op.drop_table('cisa_sync_attempts')
