"""Index tenant-scoped NVD attempt traversal.

Revision ID: 0033_nvd_attempt_index
"""
from alembic import op

revision = '0033_nvd_attempt_index'
down_revision = '0032_nvd_sync_attempts'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_nvd_sync_tenant_started_id', 'nvd_sync_attempts', ['tenant_id', 'started_at', 'id'])


def downgrade():
    op.drop_index('ix_nvd_sync_tenant_started_id', table_name='nvd_sync_attempts')
