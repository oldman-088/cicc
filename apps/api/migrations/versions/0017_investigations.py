"""Experimental tenant-scoped investigation records and history.

Revision ID: 0017_investigations
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision = '0017_investigations'
down_revision = '0016_expired_sessions_index'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('investigations',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('created_by', sa.Uuid(), nullable=False),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.String(4000), nullable=False),
        sa.Column('status', sa.String(16), server_default='open', nullable=False),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('tenant_id','id'),
        sa.ForeignKeyConstraint(['tenant_id','created_by'], ['users.tenant_id','users.id']),
        sa.CheckConstraint("status IN ('open', 'closed')", name='ck_investigation_status'),
        sa.CheckConstraint('version >= 1', name='ck_investigation_version'))
    op.create_index('ix_investigations_tenant_id_id', 'investigations', ['tenant_id','id'])
    op.create_table('investigation_events',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('investigation_id', sa.Uuid(), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(), 'postgresql'), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id','investigation_id'], ['investigations.tenant_id','investigations.id']),
        sa.ForeignKeyConstraint(['tenant_id','actor_id'], ['users.tenant_id','users.id']))
    op.create_index('ix_investigation_events_scope_time_id', 'investigation_events', ['tenant_id','investigation_id','occurred_at','id'])

def downgrade():
    op.drop_index('ix_investigation_events_scope_time_id', table_name='investigation_events')
    op.drop_table('investigation_events')
    op.drop_index('ix_investigations_tenant_id_id', table_name='investigations')
    op.drop_table('investigations')
