-- PROPOSAL ONLY: downgrades to mutable-GUC isolation, NOT a security boundary.
-- Requires owner approval and compensating controls. Mapping/function retained.
BEGIN;
DROP POLICY ti_entity_tenant ON ti_relationship_entity;
CREATE POLICY ti_entity_tenant ON ti_relationship_entity
    USING (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''));
DROP POLICY ti_record_tenant ON ti_relationship_record;
CREATE POLICY ti_record_tenant ON ti_relationship_record
    USING (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''));
DROP POLICY ti_idempotency_tenant ON ti_relationship_idempotency;
CREATE POLICY ti_idempotency_tenant ON ti_relationship_idempotency
    USING (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''));
DROP POLICY ti_audit_tenant ON ti_relationship_audit;
CREATE POLICY ti_audit_tenant ON ti_relationship_audit
    USING (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('cicc.tenant_id', true), ''));
COMMIT;
