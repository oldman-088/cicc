"""Vulnerability intelligence records, tenant-scoped.

Revision ID: 0043_vuln_intel_records
Revises: 0042_note_corrections

NOT APPLIED. This file is authored so the owner can adopt it deliberately; no branch of
this package runs ``alembic upgrade`` against a shared database, and the DB-API store in
``vuln_intel/integration/dbapi_store.py`` works without this table existing at all (it is
given a connection and expects the DDL to be somebody's deliberate decision).

Two decisions are encoded here and both are reversible:

1. ``collected_at`` is the *observation* timestamp, not ``updated_at``. The store refuses
   to let an older observation overwrite a newer one, and that rule needs a column that
   means "when this was true", not "when we last wrote it". Conflating the two makes the
   rule unimplementable.

2. ``severity_rank`` is materialised. ``ORDER BY`` on the severity *name* sorts
   alphabetically and puts ``low`` above ``medium``. A generated column would be better,
   but SQLAlchemy/Alembic portability across SQLite and PostgreSQL is the constraint the
   host itself is already managing; the store writes this column in the same statement as
   the row, so it cannot drift.

The composite foreign key to ``tenants`` is deliberate: it makes a tenant-crossing write
impossible at the database level rather than by convention, matching how every other
table in this schema records tenancy.
"""
import sqlalchemy as sa
from alembic import op

revision = '0043_vuln_intel_records'
down_revision = '0042_note_corrections'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'vulnerability_record',
        sa.Column('tenant_id', sa.Uuid(), primary_key=True),
        sa.Column('cve', sa.String(32), primary_key=True),
        sa.Column('entity_id', sa.Uuid(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('origin', sa.String(16), nullable=False),
        sa.Column('collected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('severity_rank', sa.Integer(), nullable=False, server_default='99'),
        sa.Column('kev', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.ForeignKeyConstraint(['tenant_id'], ['tenants.id']),
        sa.CheckConstraint(
            "origin IN ('live','fixture','demo','unknown')", name='ck_record_origin'
        ),
        # A rank outside the scale means the writer invented an ordering.
        sa.CheckConstraint(
            'severity_rank >= 0 AND severity_rank <= 99', name='ck_record_severity_rank'
        ),
    )
    op.create_index(
        'ix_record_tenant_severity', 'vulnerability_record',
        ['tenant_id', 'severity_rank', 'cve'],
    )
    op.create_index(
        'ix_record_tenant_kev', 'vulnerability_record', ['tenant_id', 'kev', 'cve'],
    )

    op.create_table(
        'vulnerability_provenance_event',
        sa.Column('id', sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column('tenant_id', sa.Uuid(), nullable=False),
        sa.Column('cve', sa.String(32), nullable=False),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('source', sa.String(255), nullable=True),
        sa.Column('observed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.ForeignKeyConstraint(
            ['tenant_id', 'cve'],
            ['vulnerability_record.tenant_id', 'vulnerability_record.cve'],
            ondelete='CASCADE',
        ),
    )
    op.create_index(
        'ix_provenance_tenant_cve', 'vulnerability_provenance_event',
        ['tenant_id', 'cve', 'id'],
    )


def downgrade():
    op.drop_index('ix_provenance_tenant_cve', table_name='vulnerability_provenance_event')
    op.drop_table('vulnerability_provenance_event')
    op.drop_index('ix_record_tenant_kev', table_name='vulnerability_record')
    op.drop_index('ix_record_tenant_severity', table_name='vulnerability_record')
    op.drop_table('vulnerability_record')
