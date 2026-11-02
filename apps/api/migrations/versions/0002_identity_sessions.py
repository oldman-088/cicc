"""Add tenant-scoped identities and opaque session digests.

Revision ID: 0002_identity_sessions
"""
from alembic import op
import sqlalchemy as sa

revision = '0002_identity_sessions'
down_revision = '0001_initial_graph'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table('users',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('username', sa.String(255), nullable=False),
        sa.Column('password_hash', sa.String(512), nullable=False),
        sa.Column('role', sa.String(32), nullable=False),
        sa.Column('active', sa.Boolean(), nullable=False),
        sa.UniqueConstraint('tenant_id', 'id'),
        sa.UniqueConstraint('tenant_id', 'username'))
    op.create_index('ix_users_tenant_id', 'users', ['tenant_id'])
    op.create_table('auth_sessions',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('user_id', sa.Uuid(), nullable=False),
        sa.Column('token_digest', sa.String(64), nullable=False, unique=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True)),
        sa.ForeignKeyConstraint(['tenant_id', 'user_id'], ['users.tenant_id', 'users.id']))
    op.create_index('ix_auth_sessions_tenant_id', 'auth_sessions', ['tenant_id'])
    op.create_index('ix_auth_sessions_user_id', 'auth_sessions', ['user_id'])

def downgrade():
    op.drop_index('ix_auth_sessions_user_id', table_name='auth_sessions')
    op.drop_index('ix_auth_sessions_tenant_id', table_name='auth_sessions')
    op.drop_table('auth_sessions')
    op.drop_index('ix_users_tenant_id', table_name='users')
    op.drop_table('users')
