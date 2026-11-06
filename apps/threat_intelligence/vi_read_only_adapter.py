"""Candidate integration seam for host-owned, authorized VI read operations.

Not a gateway API or authorization boundary. The host must verify the context,
perform tenant/permission checks, scope loaders, select pools and audit/trace.
This module never mounts routes, trusts a client tenant ID or provisions roles.
"""
from dataclasses import dataclass
import json
from typing import Callable
from sqlalchemy.engine import Engine
from .vulnerability_quality import Inventory, Observation, Consultation, quality_json_for_version
from .cisa_kev_snapshot import conflict_document

@dataclass(frozen=True)
class QualitySnapshot:
    """Host-loader supplied, already authorized and scoped evidence; not identity."""
    inventory: Inventory
    observations: list[Observation]
    consultations: list[Consultation]

class VIReadOnlyAdapter:
    """Candidate hooks only; host must independently authenticate and authorize."""
    def __init__(self, *, load_scoped_quality: Callable, operator_engine: Callable):
        if not callable(load_scoped_quality) or not callable(operator_engine):
            raise TypeError('host-owned loader and engine callbacks required')
        self._load_scoped_quality=load_scoped_quality
        self._operator_engine=operator_engine

    def quality(self, verified_context, *, schema_version, as_of, max_observation_age):
        if schema_version!='cicc.vulnerability-quality/1': raise ValueError('unsupported quality schema version')
        snapshot=self._load_scoped_quality(verified_context)
        if not isinstance(snapshot,QualitySnapshot): raise TypeError('invalid quality snapshot')
        return json.loads(quality_json_for_version(schema_version,snapshot.inventory,snapshot.observations,
            snapshot.consultations,as_of=as_of,max_observation_age=max_observation_age))

    def kev_conflict(self, verified_context, *, schema_version, origin, conflict_id):
        if schema_version!='cicc.kev-conflict-summary/1': raise ValueError('unsupported conflict schema version')
        engine=self._operator_engine(verified_context)
        if not isinstance(engine,Engine): raise TypeError('invalid operator engine')
        return conflict_document(engine,origin=origin,conflict_id=conflict_id,schema_version=schema_version)
