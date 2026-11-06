"""Interoperability adapters: our model expressed in other projects' schemas."""

from .ctis import ConversionSummary, CtisConversion, to_ctis_finding, to_ctis_report
from .openvex import (
    OPENVEX_SPEC_VERSION,
    OpenVexExport,
    openvex_status_for,
    to_openvex,
)
from .sarif import parse_sarif, to_vulnerability_candidates
from .vex import VEX_SPEC_VERSION, VexExport, to_vex, vex_state_for

__all__ = [
    "OPENVEX_SPEC_VERSION",
    "VEX_SPEC_VERSION",
    "ConversionSummary",
    "CtisConversion",
    "OpenVexExport",
    "VexExport",
    "openvex_status_for",
    "parse_sarif",
    "to_ctis_finding",
    "to_ctis_report",
    "to_openvex",
    "to_vex",
    "to_vulnerability_candidates",
    "vex_state_for",
]
