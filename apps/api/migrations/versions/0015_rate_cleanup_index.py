"""Index rate-limit windows for bounded maintenance.

Revision ID: 0015_rate_cleanup_index
"""
from alembic import op
revision = '0015_rate_cleanup_index'
down_revision = '0014_graph_pagination_indexes'
branch_labels = None
depends_on = None

def upgrade():
    op.create_index('ix_rate_limit_window_start', 'rate_limit_buckets', ['window_start'])

def downgrade():
    op.drop_index('ix_rate_limit_window_start', table_name='rate_limit_buckets')
