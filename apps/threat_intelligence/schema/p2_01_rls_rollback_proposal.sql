-- PROPOSAL ONLY: removing RLS weakens security. Requires owner approval,
-- a protected maintenance window, and verified compensating isolation controls.
BEGIN;
DROP POLICY ti_entity_tenant ON ti_relationship_entity;
ALTER TABLE ti_relationship_entity NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ti_relationship_entity DISABLE ROW LEVEL SECURITY;
DROP POLICY ti_record_tenant ON ti_relationship_record;
ALTER TABLE ti_relationship_record NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ti_relationship_record DISABLE ROW LEVEL SECURITY;
DROP POLICY ti_idempotency_tenant ON ti_relationship_idempotency;
ALTER TABLE ti_relationship_idempotency NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ti_relationship_idempotency DISABLE ROW LEVEL SECURITY;
DROP POLICY ti_audit_tenant ON ti_relationship_audit;
ALTER TABLE ti_relationship_audit NO FORCE ROW LEVEL SECURITY;
ALTER TABLE ti_relationship_audit DISABLE ROW LEVEL SECURITY;
COMMIT;
