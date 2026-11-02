"""Tenant-filtered query primitive; callers must supply an authenticated principal."""
from sqlalchemy import select
from sqlalchemy.orm import Session
from .models import Entity
from .security import Permission, Principal, authorize

def list_entities(session: Session, principal: Principal, tenant_id):
    authorize(principal, tenant_id, Permission.READ_INTELLIGENCE)
    return list(session.scalars(select(Entity).where(Entity.tenant_id == tenant_id).order_by(Entity.id)))
