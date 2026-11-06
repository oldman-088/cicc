-- ALTERNATIVE PROPOSAL ONLY: deploy only after owner/DB security approval.
-- Apply AFTER p2_01_postgres_proposal.sql and p2_01_rls_proposal.sql.
-- Mapping, function ownership, login credentials and grants are host-managed.
BEGIN;
CREATE SCHEMA ti_security;
REVOKE ALL ON SCHEMA ti_security FROM PUBLIC;
CREATE TABLE ti_security.tenant_role_map (
    login_role NAME PRIMARY KEY,
    tenant_id VARCHAR(256) NOT NULL CHECK (length(tenant_id) > 0)
);
REVOKE ALL ON ti_security.tenant_role_map FROM PUBLIC;
CREATE FUNCTION ti_security.authenticated_tenant() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$ SELECT tenant_id::text FROM ti_security.tenant_role_map WHERE login_role = session_user $$;
REVOKE ALL ON FUNCTION ti_security.authenticated_tenant() FROM PUBLIC;
DROP POLICY ti_entity_tenant ON ti_relationship_entity;
CREATE POLICY ti_entity_tenant ON ti_relationship_entity
    USING (tenant_id = ti_security.authenticated_tenant())
    WITH CHECK (tenant_id = ti_security.authenticated_tenant());
DROP POLICY ti_record_tenant ON ti_relationship_record;
CREATE POLICY ti_record_tenant ON ti_relationship_record
    USING (tenant_id = ti_security.authenticated_tenant())
    WITH CHECK (tenant_id = ti_security.authenticated_tenant());
DROP POLICY ti_idempotency_tenant ON ti_relationship_idempotency;
CREATE POLICY ti_idempotency_tenant ON ti_relationship_idempotency
    USING (tenant_id = ti_security.authenticated_tenant())
    WITH CHECK (tenant_id = ti_security.authenticated_tenant());
DROP POLICY ti_audit_tenant ON ti_relationship_audit;
CREATE POLICY ti_audit_tenant ON ti_relationship_audit
    USING (tenant_id = ti_security.authenticated_tenant())
    WITH CHECK (tenant_id = ti_security.authenticated_tenant());
COMMIT;
