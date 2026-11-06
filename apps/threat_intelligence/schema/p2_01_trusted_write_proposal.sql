-- PROPOSAL ONLY: owner approval and role/grant review required.
-- Apply after the role-bound RLS proposal; this is not an app startup migration.
BEGIN;
CREATE TABLE ti_security.login_actor_map (
    login_role NAME PRIMARY KEY REFERENCES ti_security.tenant_role_map(login_role),
    actor VARCHAR(256) NOT NULL CHECK (length(btrim(actor)) > 0)
);
REVOKE ALL ON ti_security.login_actor_map FROM PUBLIC;

CREATE FUNCTION ti_security.authenticated_actor() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog
AS $$ SELECT actor::text FROM ti_security.login_actor_map WHERE login_role = session_user $$;
REVOKE ALL ON FUNCTION ti_security.authenticated_actor() FROM PUBLIC;

-- A tenant login receives only EXECUTE on this function, not direct INSERT,
-- UPDATE or DELETE on relationship, idempotency, entity or audit tables.
-- A trusted no-login owner must be provisioned by the host in production.
CREATE FUNCTION ti_security.trusted_create_relationship(p_key text, p_record jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
    v_tenant text := ti_security.authenticated_tenant();
    v_actor text := ti_security.authenticated_actor();
    v_hash text;
    v_normalized jsonb;
    v_id uuid;
    v_record jsonb;
    v_existing record;
    v_outcome text;
    v_correlation uuid := gen_random_uuid();
BEGIN
    IF v_tenant IS NULL OR v_actor IS NULL THEN
        RAISE EXCEPTION 'login has no trusted identity' USING ERRCODE = '42501';
    END IF;
    IF p_key IS NULL OR p_key !~ '^[A-Za-z0-9._:-]{1,128}$'
        OR p_record IS NULL OR jsonb_typeof(p_record) <> 'object'
        OR pg_column_size(p_record) > 1048576
        OR (p_record - ARRAY['relationship_id','source_entity','target_entity','relationship_type','confidence','evidence','provenance','temporal_context','confirmed','conflicting_intelligence','created_at','updated_at','experimental_label']) <> '{}'::jsonb
        OR jsonb_typeof(p_record->'source_entity') IS DISTINCT FROM 'object'
        OR jsonb_typeof(p_record->'target_entity') IS DISTINCT FROM 'object'
        OR ((p_record->'source_entity') - ARRAY['entity_id','entity_type','name','experimental_label']) <> '{}'::jsonb
        OR ((p_record->'target_entity') - ARRAY['entity_id','entity_type','name','experimental_label']) <> '{}'::jsonb
        OR p_record->>'relationship_type' IS NULL OR p_record->>'confidence' IS NULL
        OR p_record->>'experimental_label' IS DISTINCT FROM 'EXPERIMENTAL_DEMO_DATA_ONLY'
        OR p_record->'source_entity'->>'experimental_label' IS DISTINCT FROM 'EXPERIMENTAL_DEMO_DATA_ONLY'
        OR p_record->'target_entity'->>'experimental_label' IS DISTINCT FROM 'EXPERIMENTAL_DEMO_DATA_ONLY'
        OR nullif(btrim(p_record->'source_entity'->>'entity_type'), '') IS NULL
        OR nullif(btrim(p_record->'source_entity'->>'entity_id'), '') IS NULL
        OR nullif(btrim(p_record->'target_entity'->>'entity_type'), '') IS NULL
        OR nullif(btrim(p_record->'target_entity'->>'entity_id'), '') IS NULL
        OR nullif(btrim(p_record->>'provenance'), '') IS NULL
        OR p_record->>'relationship_type' NOT IN ('ATTRIBUTED_TO','USES','TARGETS','INDICATES','ASSOCIATED_WITH','EXPLOITS','AFFECTS','OBSERVED_IN','DERIVED_FROM','CORROBORATES','CONTRADICTS','CONTAINS','DEPENDS_ON','BELONGS_TO','RELATED_TO')
        OR p_record->>'confidence' NOT IN ('LOW','MEDIUM','HIGH','CONFIRMED','INFERRED')
        OR jsonb_typeof(p_record->'evidence') IS DISTINCT FROM 'array'
        OR jsonb_typeof(p_record->'confirmed') IS DISTINCT FROM 'boolean'
    THEN
        RAISE EXCEPTION 'invalid relationship input' USING ERRCODE = '22023';
    END IF;
    IF jsonb_array_length(p_record->'evidence') > 100
       OR EXISTS (SELECT 1 FROM jsonb_array_elements(p_record->'evidence') e
                  WHERE jsonb_typeof(e) IS DISTINCT FROM 'object'
                     OR (e - ARRAY['evidence_id','source','timestamp','description','confidence','provenance','experimental_label']) <> '{}'::jsonb
                     OR e->>'experimental_label' IS DISTINCT FROM 'EXPERIMENTAL_DEMO_DATA_ONLY'
                     OR nullif(btrim(e->>'source'), '') IS NULL
                     OR nullif(btrim(e->>'description'), '') IS NULL
                     OR nullif(btrim(e->>'provenance'), '') IS NULL
                     OR e->>'timestamp' IS NULL OR e->>'evidence_id' IS NULL
                     OR e->>'confidence' IS NULL OR e->>'confidence' NOT IN ('LOW','MEDIUM','HIGH','CONFIRMED','INFERRED'))
       OR ((p_record->>'confirmed')::boolean AND (jsonb_array_length(p_record->'evidence') = 0 OR p_record->>'confidence' = 'INFERRED'))
       OR (NOT (p_record->>'confirmed')::boolean AND p_record->>'confidence' = 'CONFIRMED')
    THEN
        RAISE EXCEPTION 'invalid relationship evidence' USING ERRCODE = '22023';
    END IF;

    -- Ignore server-generated identifiers and record timestamps when determining
    -- content identity; retain evidence collection timestamps and provenance.
    SELECT (p_record - 'relationship_id' - 'created_at' - 'updated_at' - 'evidence') ||
        jsonb_build_object('evidence', coalesce(jsonb_agg(e.value - 'evidence_id' ORDER BY e.ordinality), '[]'::jsonb))
    INTO v_normalized FROM jsonb_array_elements(p_record->'evidence') WITH ORDINALITY AS e(value, ordinality);
    v_hash := encode(sha256(convert_to(v_normalized::text, 'UTF8')), 'hex');
    PERFORM pg_advisory_xact_lock(hashtextextended(v_tenant, 0));

    SELECT fingerprint, relationship_id INTO v_existing FROM public.ti_relationship_idempotency
      WHERE tenant_id = v_tenant AND key = p_key;
    IF FOUND AND v_existing.fingerprint <> v_hash THEN
        v_outcome := 'conflict';
    ELSE
        SELECT relationship_id, record INTO v_id, v_record FROM public.ti_relationship_record
          WHERE tenant_id = v_tenant AND fingerprint = v_hash;
        IF FOUND THEN
            INSERT INTO public.ti_relationship_idempotency(tenant_id,key,fingerprint,relationship_id)
                VALUES (v_tenant,p_key,v_hash,v_id) ON CONFLICT DO NOTHING;
            v_outcome := 'replayed';
        ELSE
            v_id := (p_record->>'relationship_id')::uuid;
            INSERT INTO public.ti_relationship_entity VALUES (v_tenant,p_record->'source_entity'->>'entity_type',p_record->'source_entity'->>'entity_id') ON CONFLICT DO NOTHING;
            INSERT INTO public.ti_relationship_entity VALUES (v_tenant,p_record->'target_entity'->>'entity_type',p_record->'target_entity'->>'entity_id') ON CONFLICT DO NOTHING;
            INSERT INTO public.ti_relationship_record(tenant_id,relationship_id,source_type,source_id,target_type,target_id,relationship_type,fingerprint,record)
                VALUES (v_tenant,v_id,p_record->'source_entity'->>'entity_type',p_record->'source_entity'->>'entity_id',p_record->'target_entity'->>'entity_type',p_record->'target_entity'->>'entity_id',p_record->>'relationship_type',v_hash,p_record);
            INSERT INTO public.ti_relationship_idempotency VALUES (v_tenant,p_key,v_hash,v_id);
            v_record := p_record;
            v_outcome := 'created';
        END IF;
    END IF;
    INSERT INTO public.ti_relationship_audit(event_id,tenant_id,actor,operation,resource_id,outcome,correlation_id,occurred_at)
        VALUES (gen_random_uuid(),v_tenant,v_actor,'relationship.create',v_id,v_outcome,v_correlation,clock_timestamp());
    RETURN jsonb_build_object('outcome',v_outcome,'record',v_record,'correlation_id',v_correlation,'tenant',v_tenant,'actor',v_actor);
END;
$$;
REVOKE ALL ON FUNCTION ti_security.trusted_create_relationship(text, jsonb) FROM PUBLIC;
COMMIT;
