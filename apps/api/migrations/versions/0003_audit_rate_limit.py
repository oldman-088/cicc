"""Add security audit and rate-limit primitives.

Revision ID: 0003_audit_rate_limit
"""
from alembic import op
import sqlalchemy as sa

revision = '0003_audit_rate_limit'
down_revision = '0002_identity_sessions'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('security_audit_events',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=True),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']))
    op.create_index('ix_security_audit_events_tenant_id', 'security_audit_events', ['tenant_id'])
    op.create_table('rate_limit_buckets',
        sa.Column('key_digest', sa.String(64), primary_key=True),
        sa.Column('window_start', sa.Integer(), primary_key=True),
        sa.Column('attempts', sa.Integer(), nullable=False))

def downgrade():
    op.drop_table('rate_limit_buckets')
    op.drop_index('ix_security_audit_events_tenant_id', table_name='security_audit_events')
    op.drop_table('security_audit_events')
