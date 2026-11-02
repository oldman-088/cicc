"""Capture provenance for newly created manual records; no historical backfill.

Revision ID: 0008_provenance_events
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision = '0008_provenance_events'
down_revision = '0007_evidence_reference'
branch_labels = None
depends_on = None

def upgrade():
    with op.batch_alter_table('evidence_references') as batch:
        batch.create_unique_constraint('uq_evidence_tenant_id', ['tenant_id', 'entity_id', 'id'])
    op.create_table('provenance_events',
        sa.Column('id', sa.Uuid(), primary_key=True),
        sa.Column('tenant_id', sa.Uuid(), sa.ForeignKey('tenants.id'), nullable=False),
        sa.Column('entity_id', sa.Uuid(), nullable=False),
        sa.Column('actor_id', sa.Uuid(), nullable=False),
        sa.Column('evidence_id', sa.Uuid()),
        sa.Column('event_type', sa.String(64), nullable=False),
        sa.Column('details', sa.JSON().with_variant(postgresql.JSONB(), 'postgresql'), nullable=False),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['tenant_id', 'entity_id'], ['intelligence_entities.tenant_id', 'intelligence_entities.id']),
        sa.ForeignKeyConstraint(['tenant_id', 'actor_id'], ['users.tenant_id', 'users.id']),
        sa.ForeignKeyConstraint(['tenant_id', 'entity_id', 'evidence_id'], ['evidence_references.tenant_id', 'evidence_references.entity_id', 'evidence_references.id']))
    op.create_index('ix_provenance_events_tenant_id', 'provenance_events', ['tenant_id'])
    op.create_index('ix_provenance_events_entity_id', 'provenance_events', ['entity_id'])

def downgrade():
    op.drop_index('ix_provenance_events_entity_id', table_name='provenance_events')
    op.drop_index('ix_provenance_events_tenant_id', table_name='provenance_events')
    op.drop_table('provenance_events')
    with op.batch_alter_table('evidence_references') as batch:
        batch.drop_constraint('uq_evidence_tenant_id', type_='unique')
