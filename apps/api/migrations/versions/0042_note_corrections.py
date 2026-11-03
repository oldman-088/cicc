"""Add case-scoped append-only note correction links.

Revision ID: 0042_note_corrections
"""
from alembic import op
import sqlalchemy as sa

revision = '0042_note_corrections'
down_revision = '0041_audit_provenance_target'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('investigation_note_corrections',
        sa.Column('id',sa.Uuid(),primary_key=True),
        sa.Column('tenant_id',sa.Uuid(),sa.ForeignKey('tenants.id'),nullable=False),
        sa.Column('investigation_id',sa.Uuid(),nullable=False),
        sa.Column('original_note_id',sa.Uuid(),nullable=False),
        sa.Column('correction_note_id',sa.Uuid(),nullable=False),
        sa.Column('created_by',sa.Uuid(),nullable=False),
        sa.Column('created_at',sa.DateTime(timezone=True),nullable=False),
        sa.ForeignKeyConstraint(['tenant_id','investigation_id','original_note_id'],['investigation_notes.tenant_id','investigation_notes.investigation_id','investigation_notes.id']),
        sa.ForeignKeyConstraint(['tenant_id','investigation_id','correction_note_id'],['investigation_notes.tenant_id','investigation_notes.investigation_id','investigation_notes.id']),
        sa.ForeignKeyConstraint(['tenant_id','created_by'],['users.tenant_id','users.id']),
        sa.UniqueConstraint('tenant_id','investigation_id','original_note_id',name='uq_note_correction_original'),
        sa.UniqueConstraint('tenant_id','investigation_id','correction_note_id',name='uq_note_correction_replacement'),
        sa.CheckConstraint('original_note_id <> correction_note_id',name='ck_note_correction_distinct'))


def downgrade():
    op.drop_table('investigation_note_corrections')
