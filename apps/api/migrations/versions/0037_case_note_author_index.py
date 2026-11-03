"""Index case-scoped note author traversal.

Revision ID: 0037_case_note_author_index
"""
from alembic import op

revision = '0037_case_note_author_index'
down_revision = '0036_case_event_type_index'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index('ix_investigation_notes_author_time_id', 'investigation_notes',
                    ['tenant_id', 'investigation_id', 'author_id', 'created_at', 'id'])


def downgrade():
    op.drop_index('ix_investigation_notes_author_time_id', table_name='investigation_notes')
