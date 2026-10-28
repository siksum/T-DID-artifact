"""Representation comparison: T-DID event -> generic standard record (OCSF 1.6.0, ECS 9.1.0, OpenTelemetry
Logs Data Model, CloudEvents 1.0.2) -> T-DID event rebuilt from only what the standard carried.

Mapping tables, level definitions and sources: ``rules/*.yaml``.
"""

from experiments.eval.mappers.core import (
    LEVELS,
    STANDARDS,
    MappingError,
    expressibility,
    from_standard,
    is_placeholder,
    roundtrip,
    threat_expressibility,
    to_standard,
    w3c_ref,
)

__all__ = [
    "LEVELS",
    "STANDARDS",
    "MappingError",
    "expressibility",
    "from_standard",
    "is_placeholder",
    "roundtrip",
    "threat_expressibility",
    "to_standard",
    "w3c_ref",
]
