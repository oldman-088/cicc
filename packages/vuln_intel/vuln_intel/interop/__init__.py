"""Interoperability adapters: our model expressed in other projects' schemas."""

from .ctis import ConversionSummary, CtisConversion, to_ctis_finding, to_ctis_report
from .sarif import parse_sarif, to_vulnerability_candidates
from .vex import VEX_SPEC_VERSION, VexExport, to_vex, vex_state_for

__all__ = [
    "VEX_SPEC_VERSION",
    "ConversionSummary",
    "CtisConversion",
    "VexExport",
    "parse_sarif",
    "to_ctis_finding",
    "to_ctis_report",
    "to_vex",
    "to_vulnerability_candidates",
    "vex_state_for",
]
