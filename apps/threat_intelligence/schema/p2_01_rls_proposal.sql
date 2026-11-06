-- PROPOSAL ONLY. Requires reviewed identity, role, connection and migration model.
-- A custom GUC is not an authentication boundary: the SQL role can set it.
BEGIN;
ALTER TABLE ti_relationship_entity ENABLE ROW LEVEL SECURITY;
ALTER TABLE ti_relationship_entity FORCE ROW LEVEL SECURITY;
CREATE POLICY ti_entity_tenant ON ti_relationship_entity
    USING (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''));
ALTER TABLE ti_relationship_record ENABLE ROW LEVEL SECURITY;
ALTER TABLE ti_relationship_record FORCE ROW LEVEL SECURITY;
CREATE POLICY ti_record_tenant ON ti_relationship_record
    USING (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''));
ALTER TABLE ti_relationship_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE ti_relationship_idempotency FORCE ROW LEVEL SECURITY;
CREATE POLICY ti_idempotency_tenant ON ti_relationship_idempotency
    USING (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''));
ALTER TABLE ti_relationship_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE ti_relationship_audit FORCE ROW LEVEL SECURITY;
CREATE POLICY ti_audit_tenant ON ti_relationship_audit
    USING (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''));
COMMIT;
