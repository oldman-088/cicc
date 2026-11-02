"""Record previous and new role for administrative audit events.

Revision ID: 0005_audit_roles
"""
from alembic import op
import sqlalchemy as sa
revision = '0005_audit_roles'
down_revision = '0004_audit_target'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('security_audit_events', sa.Column('previous_role', sa.String(32), nullable=True))
    op.add_column('security_audit_events', sa.Column('new_role', sa.String(32), nullable=True))

def downgrade():
    with op.batch_alter_table('security_audit_events') as batch:
        batch.drop_column('new_role')
        batch.drop_column('previous_role')
