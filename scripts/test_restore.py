#!/usr/bin/env python3
"""Synthetic-only PostgreSQL logical dump/restore drill using disposable local servers.

Requires the locked API dev environment plus optional pgserver==0.1.4 and its
bundled pg_dump/pg_restore. Both servers use local trust authentication; run only
on a trusted machine. No supplied URLs, real records or persistent backup files
are accepted. This is not a production backup, recovery procedure or RTO test.
"""
from pathlib import Path
from datetime import datetime, timezone
import os
import subprocess
import sys
import tempfile
from uuid import uuid4

try:
    import pgserver
    from pgserver import PostgresServer
    from sqlalchemy import create_engine, select
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.orm import sessionmaker
except ImportError:
    sys.exit('Install the locked API dev requirements and optional pgserver==0.1.4')

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / 'apps/api'
sys.path.insert(0, str(API))
from app.models import Tenant, User, Entity, Investigation, InvestigationEvent, InvestigationEntityLink, NvdCatalogRecord, SecurityAuditEvent, Relationship, ProvenanceEvent


def main():
    tools = Path(pgserver.__file__).parent / 'pginstall' / 'bin'
    servers = []
    with tempfile.TemporaryDirectory(prefix='cicc-restore-drill-') as directory:
        try:
            for name in ('source', 'restore'):
                server = PostgresServer(Path(directory) / name, cleanup_mode='stop')
                servers.append(server)
            source, target = (server.get_uri() for server in servers)
            source_db = source.replace('postgresql://', 'postgresql+psycopg://', 1)
            target_db = target.replace('postgresql://', 'postgresql+psycopg://', 1)
            env = {**os.environ, 'DATABASE_URL':source_db}
            subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'], cwd=API, env=env, check=True)
            engine = create_engine(source_db)
            try:
                factory = sessionmaker(engine, expire_on_commit=False)
                tenant_id, actor_id, entity_id, case_id, event_id, audit_id, other_entity_id, relation_id, relation_audit_id, provenance_id, provenance_audit_id = (uuid4() for _ in range(11))
                with factory.begin() as db:
                    db.add(Tenant(id=tenant_id, name='synthetic restore tenant')); db.flush()
                    db.add(User(id=actor_id, tenant_id=tenant_id, username='fixture', role='admin', active=True, password_hash='synthetic-invalid-hash')); db.flush()
                    db.add(Entity(id=entity_id, tenant_id=tenant_id, created_by=actor_id, kind='indicator', title='synthetic entity', source='fixture'))
                    db.add(Entity(id=other_entity_id, tenant_id=tenant_id, created_by=actor_id, kind='indicator', title='synthetic second entity', source='fixture'))
                    db.add(Investigation(id=case_id, tenant_id=tenant_id, created_by=actor_id, title='synthetic case', description='synthetic only')); db.flush()
                    db.add(InvestigationEntityLink(tenant_id=tenant_id, investigation_id=case_id, entity_id=entity_id, created_by=actor_id))
                    db.add(InvestigationEvent(id=event_id, tenant_id=tenant_id, investigation_id=case_id, actor_id=actor_id, event_type='fixture', details={'synthetic':True})); db.flush()
                    db.add(ProvenanceEvent(id=provenance_id,tenant_id=tenant_id,entity_id=entity_id,actor_id=actor_id,event_type='fixture',details={'synthetic':True})); db.flush()
                    db.add(SecurityAuditEvent(id=provenance_audit_id,tenant_id=tenant_id,actor_id=actor_id,event_type='provenance_event_read',target_entity_id=entity_id,target_provenance_id=provenance_id))
                    db.add(Relationship(id=relation_id,tenant_id=tenant_id,subject_id=entity_id,object_id=other_entity_id,kind='RELATED_TO',source='fixture')); db.flush()
                    db.add(SecurityAuditEvent(id=relation_audit_id,tenant_id=tenant_id,actor_id=actor_id,event_type='relationship_read',target_entity_id=other_entity_id,target_relationship_id=relation_id,relationship_subject_id=entity_id,relationship_object_id=other_entity_id))
                    db.add(SecurityAuditEvent(id=audit_id, tenant_id=tenant_id, actor_id=actor_id, event_type='investigation_event_read', target_investigation_id=case_id, target_investigation_event_id=event_id))
                    db.add(NvdCatalogRecord(tenant_id=tenant_id, entity_id=entity_id, cve_id='CVE-2099-0001', details={'synthetic':True, 'description':'restore fixture only'}, first_collected_at=datetime(2026,1,1,tzinfo=timezone.utc), last_collected_at=datetime(2026,1,2,tzinfo=timezone.utc)))
            finally:
                engine.dispose()
            archive = Path(directory) / 'synthetic.dump'
            subprocess.run([str(tools/'pg_dump'), '--format=custom', '--no-owner', '--no-privileges', '--dbname', source, '--file', str(archive)], check=True)
            subprocess.run([str(tools/'pg_restore'), '--exit-on-error', '--no-owner', '--no-privileges', '--dbname', target, str(archive)], check=True)
            subprocess.run([sys.executable, '-m', 'alembic', 'check'], cwd=API, env={**os.environ,'DATABASE_URL':target_db}, check=True)
            engine = create_engine(target_db)
            try:
                factory = sessionmaker(engine, expire_on_commit=False)
                with factory() as db:
                    assert db.get(Tenant,tenant_id).name == 'synthetic restore tenant'
                    assert db.get(Entity,entity_id).title == 'synthetic entity'
                    assert db.get(Investigation,case_id).title == 'synthetic case'
                    assert db.scalar(select(InvestigationEntityLink).where(InvestigationEntityLink.investigation_id == case_id)).entity_id == entity_id
                    assert db.scalar(select(InvestigationEvent).where(InvestigationEvent.investigation_id == case_id)).details == {'synthetic':True}
                    audit = db.get(SecurityAuditEvent, audit_id)
                    assert audit.tenant_id == tenant_id and audit.target_investigation_id == case_id and audit.target_investigation_event_id == event_id
                    provenance_audit = db.get(SecurityAuditEvent, provenance_audit_id)
                    assert provenance_audit.target_entity_id == entity_id and provenance_audit.target_provenance_id == provenance_id
                    assert db.get(ProvenanceEvent, provenance_id).details == {'synthetic':True}
                    relation_audit = db.get(SecurityAuditEvent, relation_audit_id)
                    assert relation_audit.target_relationship_id == relation_id and relation_audit.target_entity_id == other_entity_id
                    assert relation_audit.relationship_subject_id == entity_id and relation_audit.relationship_object_id == other_entity_id
                    observation = db.scalar(select(NvdCatalogRecord).where(NvdCatalogRecord.tenant_id == tenant_id, NvdCatalogRecord.cve_id == 'CVE-2099-0001'))
                    assert observation.entity_id == entity_id and observation.details == {'synthetic':True, 'description':'restore fixture only'}
                    assert observation.first_collected_at == datetime(2026,1,1,tzinfo=timezone.utc) and observation.last_collected_at == datetime(2026,1,2,tzinfo=timezone.utc)
                # Check that a restored composite tenant constraint still rejects a cross-tenant link.
                with factory.begin() as db:
                    other = Tenant(id=uuid4(), name='other synthetic tenant'); db.add(other); db.flush()
                    other_entity = Entity(id=uuid4(),tenant_id=other.id,kind='indicator',title='foreign',source='fixture'); db.add(other_entity); db.flush()
                    db.add(InvestigationEntityLink(tenant_id=tenant_id,investigation_id=case_id,entity_id=other_entity.id,created_by=actor_id))
                    try:
                        db.flush()
                    except IntegrityError:
                        db.rollback()
                    else:
                        raise AssertionError('Restored tenant constraint did not reject mismatched link')
                # The restored audit event target must match its case and tenant.
                with factory.begin() as db:
                    other_case = Investigation(tenant_id=tenant_id, created_by=actor_id, title='other synthetic case', description='fixture')
                    db.add(other_case); db.flush()
                    db.add(SecurityAuditEvent(tenant_id=tenant_id, actor_id=actor_id, event_type='fixture',
                        target_investigation_id=other_case.id, target_investigation_event_id=event_id))
                    try:
                        db.flush()
                    except IntegrityError:
                        db.rollback()
                    else:
                        raise AssertionError('Restored audit event constraint did not reject mismatched case')
                # Provenance audit targets must match the referenced event's entity.
                with factory.begin() as db:
                    db.add(SecurityAuditEvent(tenant_id=tenant_id,actor_id=actor_id,event_type='fixture',
                        target_entity_id=other_entity_id,target_provenance_id=provenance_id))
                    try:
                        db.flush()
                    except IntegrityError:
                        db.rollback()
                    else:
                        raise AssertionError('Restored provenance audit constraint did not reject mismatched entity')
                # Audit targets must use an actual endpoint of the referenced relationship.
                with factory.begin() as db:
                    unrelated = Entity(id=uuid4(),tenant_id=tenant_id,kind='indicator',title='unrelated',source='fixture'); db.add(unrelated); db.flush()
                    db.add(SecurityAuditEvent(tenant_id=tenant_id,actor_id=actor_id,event_type='fixture',target_entity_id=unrelated.id,
                        target_relationship_id=relation_id,relationship_subject_id=entity_id,relationship_object_id=other_entity_id))
                    try:
                        db.flush()
                    except IntegrityError:
                        db.rollback()
                    else:
                        raise AssertionError('Restored relationship audit constraint did not reject unrelated entity')
                # The NVD observation's tenant/entity FK must also survive restore.
                with factory.begin() as db:
                    other = Tenant(id=uuid4(), name='nvd foreign synthetic tenant'); db.add(other); db.flush()
                    foreign = Entity(id=uuid4(), tenant_id=other.id, kind='vulnerability', title='foreign', source='fixture'); db.add(foreign); db.flush()
                    now = datetime.now(timezone.utc)
                    db.add(NvdCatalogRecord(tenant_id=tenant_id, entity_id=foreign.id, cve_id='CVE-2099-0002', details={'synthetic':True}, first_collected_at=now, last_collected_at=now))
                    try:
                        db.flush()
                    except IntegrityError:
                        db.rollback()
                    else:
                        raise AssertionError('Restored NVD tenant constraint did not reject mismatched entity')
            finally:
                engine.dispose()
            print('Synthetic logical dump and isolated restore drill passed; not a production recovery validation.')
        finally:
            for server in reversed(servers):
                server.cleanup()

if __name__ == '__main__':
    main()
