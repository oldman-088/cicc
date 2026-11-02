"""Index expired sessions for bounded maintenance.

Revision ID: 0016_expired_sessions_index
"""
from alembic import op
revision = '0016_expired_sessions_index'
down_revision = '0015_rate_cleanup_index'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('ix_auth_sessions_expires_id', 'auth_sessions', ['expires_at','id'])

def downgrade():
    op.drop_index('ix_auth_sessions_expires_id', table_name='auth_sessions')
