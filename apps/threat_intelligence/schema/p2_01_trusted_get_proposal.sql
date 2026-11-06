-- PROPOSAL ONLY. Apply after controlled write proposal and role-bound policies.
-- Host owns NOLOGIN function owner and explicit least-privilege EXECUTE grants.
BEGIN;
CREATE FUNCTION ti_security.trusted_get_relationship(p_relationship_id uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_tenant text := ti_security.authenticated_tenant();
    v_actor text := ti_security.authenticated_actor();
    v_record jsonb;
    v_outcome text;
    v_correlation uuid := gen_random_uuid();
BEGIN
    IF v_tenant IS NULL OR v_actor IS NULL THEN
        RAISE EXCEPTION 'login has no trusted identity' USING ERRCODE = '42501';
    END IF;
    IF p_relationship_id IS NULL THEN
        RAISE EXCEPTION 'invalid relationship id' USING ERRCODE = '22023';
    END IF;
    SELECT record INTO v_record FROM public.ti_relationship_record
      WHERE tenant_id = v_tenant AND relationship_id = p_relationship_id;
    v_outcome := CASE WHEN FOUND THEN 'success' ELSE 'not_found' END;
    IF v_record IS NOT NULL AND octet_length(v_record::text) > 4194304 THEN
        v_record := NULL; v_outcome := 'response_too_large';
    END IF;
    INSERT INTO public.ti_relationship_audit(event_id,tenant_id,actor,operation,resource_id,outcome,correlation_id,occurred_at)
      VALUES (gen_random_uuid(),v_tenant,v_actor,'relationship.read',p_relationship_id,v_outcome,v_correlation,clock_timestamp());
    RETURN jsonb_build_object('record',v_record,'correlation_id',v_correlation,'tenant',v_tenant,'actor',v_actor,'outcome',v_outcome);
END;
$$;
REVOKE ALL ON FUNCTION ti_security.trusted_get_relationship(uuid) FROM PUBLIC;
COMMIT;
