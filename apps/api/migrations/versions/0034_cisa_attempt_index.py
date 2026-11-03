"""Index tenant-scoped CISA attempt traversal.

Revision ID: 0034_cisa_attempt_index
"""
from alembic import op

revision = '0034_cisa_attempt_index'
down_revision = '0033_nvd_attempt_index'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_cisa_sync_tenant_started_id', 'cisa_sync_attempts', ['tenant_id', 'started_at', 'id'])


def downgrade():
    op.drop_index('ix_cisa_sync_tenant_started_id', table_name='cisa_sync_attempts')
