"""Track manually invoked NVD lookup attempts.

Revision ID: 0032_nvd_sync_attempts
"""
from alembic import op
import sqlalchemy as sa

revision = '0032_nvd_sync_attempts'
down_revision = '0031_nvd_catalog'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('nvd_sync_attempts',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('cve_id', sa.String(32), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_code', sa.String(32), nullable=True),
        sa.CheckConstraint("status IN ('running', 'succeeded', 'not_found', 'failed', 'abandoned')", name='ck_nvd_sync_status'),
        sa.ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']))
    op.create_index('ix_nvd_sync_attempts_tenant_id', 'nvd_sync_attempts', ['tenant_id'])
    op.create_index('uq_nvd_sync_running_tenant', 'nvd_sync_attempts', ['tenant_id'], unique=True,
                    postgresql_where=sa.text("status = 'running'"), sqlite_where=sa.text("status = 'running'"))


def downgrade():
    op.drop_index('uq_nvd_sync_running_tenant', table_name='nvd_sync_attempts')
    op.drop_index('ix_nvd_sync_attempts_tenant_id', table_name='nvd_sync_attempts')
    op.drop_table('nvd_sync_attempts')
