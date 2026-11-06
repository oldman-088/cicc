-- PROPOSAL ONLY: deploy after controlled get, with reviewed owner and grants.
BEGIN;
CREATE FUNCTION ti_security.trusted_list_relationships(p_entity_id text, p_entity_type text, p_type text, p_limit integer, p_offset integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_tenant text := ti_security.authenticated_tenant();
  v_actor text := ti_security.authenticated_actor();
  v_correlation uuid := gen_random_uuid();
  v_items jsonb;
  v_total bigint;
  v_outcome text := 'success';
BEGIN
  IF v_tenant IS NULL OR v_actor IS NULL THEN RAISE EXCEPTION 'login has no trusted identity' USING ERRCODE='42501'; END IF;
  IF (p_entity_id IS NULL) <> (p_entity_type IS NULL) OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500
     OR p_offset IS NULL OR p_offset NOT BETWEEN 0 AND 100000
     OR (p_entity_id IS NOT NULL AND (length(btrim(p_entity_id)) NOT BETWEEN 1 AND 256 OR length(btrim(p_entity_type)) NOT BETWEEN 1 AND 256))
     OR (p_type IS NOT NULL AND length(p_type) NOT BETWEEN 1 AND 32) THEN
    RAISE EXCEPTION 'invalid list parameters' USING ERRCODE='22023';
  END IF;
  WITH filtered AS NOT MATERIALIZED (
    SELECT sequence, record FROM public.ti_relationship_record r
     WHERE r.tenant_id=v_tenant AND (p_type IS NULL OR r.relationship_type=p_type)
       AND (p_entity_id IS NULL OR (r.source_type=p_entity_type AND r.source_id=p_entity_id)
                                OR (r.target_type=p_entity_type AND r.target_id=p_entity_id))
  ), page AS (SELECT * FROM filtered ORDER BY sequence LIMIT p_limit OFFSET p_offset)
  SELECT (SELECT count(*) FROM filtered),
    CASE WHEN coalesce((SELECT sum(octet_length(record::text)) FROM page),0) > 4194304 THEN NULL
         ELSE coalesce((SELECT jsonb_agg(record ORDER BY sequence) FROM page),'[]'::jsonb) END
    INTO v_total,v_items;
  IF v_items IS NULL THEN v_outcome := 'response_too_large'; v_items := '[]'::jsonb; v_total := 0; END IF;
  INSERT INTO public.ti_relationship_audit(event_id,tenant_id,actor,operation,outcome,correlation_id,occurred_at)
    VALUES(gen_random_uuid(),v_tenant,v_actor,'relationship.list',v_outcome,v_correlation,clock_timestamp());
  RETURN jsonb_build_object('tenant',v_tenant,'actor',v_actor,'correlation_id',v_correlation,'outcome',v_outcome,'items',v_items,'total',v_total);
END;
$$;
REVOKE ALL ON FUNCTION ti_security.trusted_list_relationships(text,text,text,integer,integer) FROM PUBLIC;

CREATE FUNCTION ti_security.trusted_traverse_relationships(p_id text, p_type text, p_depth integer, p_types text[], p_limit integer, p_offset integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE
  v_tenant text := ti_security.authenticated_tenant();
  v_actor text := ti_security.authenticated_actor();
  v_correlation uuid := gen_random_uuid();
  v_start text;
  v_frontier text[];
  v_visited text[];
  v_next text[];
  v_seen uuid[] := ARRAY[]::uuid[];
  v_items jsonb := '[]'::jsonb;
  v_source text;
  v_target text;
  v_total integer := 0;
  v_scanned integer;
  v_bytes bigint := 0;
  v_level integer;
  v_outcome text := 'success';
  r record;
BEGIN
  IF v_tenant IS NULL OR v_actor IS NULL THEN RAISE EXCEPTION 'login has no trusted identity' USING ERRCODE='42501'; END IF;
  IF p_id IS NULL OR p_type IS NULL OR length(btrim(p_id)) NOT BETWEEN 1 AND 256 OR length(btrim(p_type)) NOT BETWEEN 1 AND 256
     OR p_depth IS NULL OR p_depth NOT BETWEEN 0 AND 8 OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500
     OR p_offset IS NULL OR p_offset NOT BETWEEN 0 AND 100000
     OR (p_types IS NOT NULL AND (cardinality(p_types) > 15 OR array_position(p_types,NULL) IS NOT NULL
         OR EXISTS (SELECT 1 FROM unnest(p_types) AS t WHERE length(t) NOT BETWEEN 1 AND 32))) THEN
    RAISE EXCEPTION 'invalid traversal parameters' USING ERRCODE='22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.ti_relationship_entity e WHERE e.tenant_id=v_tenant AND e.entity_type=p_type AND e.entity_id=p_id) THEN
    v_outcome := 'not_found';
  ELSE
    v_start := jsonb_build_array(p_type,p_id)::text;
    v_frontier := ARRAY[v_start]; v_visited := v_frontier;
    FOR v_level IN 1..p_depth LOOP
      EXIT WHEN cardinality(v_frontier)=0 OR (p_types IS NOT NULL AND cardinality(p_types)=0);
      v_next := ARRAY[]::text[]; v_scanned := 0;
      FOR r IN SELECT q.* FROM public.ti_relationship_record q WHERE q.tenant_id=v_tenant
        AND (p_types IS NULL OR q.relationship_type=ANY(p_types))
        AND (jsonb_build_array(q.source_type,q.source_id)::text=ANY(v_frontier)
          OR jsonb_build_array(q.target_type,q.target_id)::text=ANY(v_frontier))
        ORDER BY q.sequence LIMIT 1001 LOOP
        v_scanned := v_scanned+1;
        IF v_scanned > 1000 THEN v_outcome := 'limit_exceeded'; EXIT; END IF;
        IF NOT r.relationship_id=ANY(v_seen) THEN
          v_seen := array_append(v_seen,r.relationship_id); v_total := v_total+1;
          IF v_total > 1000 THEN v_outcome := 'limit_exceeded'; EXIT; END IF;
          IF v_total > p_offset AND v_total <= p_offset+p_limit THEN
            v_bytes := v_bytes + octet_length(r.record::text);
            IF v_bytes > 4194304 THEN v_outcome := 'response_too_large'; EXIT; END IF;
            v_items := v_items || jsonb_build_array(jsonb_build_object('depth',v_level,'record',r.record));
          END IF;
        END IF;
        v_source := jsonb_build_array(r.source_type,r.source_id)::text;
        v_target := jsonb_build_array(r.target_type,r.target_id)::text;
        IF v_source=ANY(v_frontier) AND NOT v_target=ANY(v_visited) AND NOT v_target=ANY(v_next) THEN v_next := array_append(v_next,v_target); END IF;
        IF v_target=ANY(v_frontier) AND NOT v_source=ANY(v_visited) AND NOT v_source=ANY(v_next) THEN v_next := array_append(v_next,v_source); END IF;
      END LOOP;
      EXIT WHEN v_outcome <> 'success';
      v_visited := v_visited || v_next; v_frontier := v_next;
    END LOOP;
  END IF;
  INSERT INTO public.ti_relationship_audit(event_id,tenant_id,actor,operation,outcome,correlation_id,occurred_at)
    VALUES(gen_random_uuid(),v_tenant,v_actor,'relationship.traverse',v_outcome,v_correlation,clock_timestamp());
  RETURN jsonb_build_object('tenant',v_tenant,'actor',v_actor,'correlation_id',v_correlation,'outcome',v_outcome,
    'items',CASE WHEN v_outcome='success' THEN v_items ELSE '[]'::jsonb END,
    'total',CASE WHEN v_outcome='success' THEN v_total ELSE 0 END,
    'visited',CASE WHEN v_outcome='success' THEN cardinality(v_visited) ELSE 0 END);
END;
$$;
REVOKE ALL ON FUNCTION ti_security.trusted_traverse_relationships(text,text,integer,text[],integer,integer) FROM PUBLIC;
COMMIT;
