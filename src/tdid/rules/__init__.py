"""Threat rules. Each module defines one Rule subclass; ``all_rules`` collects them in threat order."""

from __future__ import annotations

import importlib
import pkgutil

from tdid.rules.base import Rule


def all_rules() -> list[Rule]:
    rules: list[Rule] = []
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda m: m.name):
        if not info.name.startswith("thr"):
            continue
        module = importlib.import_module(f"{__name__}.{info.name}")
        rules.append(module.RULE)
    ids = [r.threat_id for r in rules]
    if len(ids) != len(set(ids)):
        raise RuntimeError(f"duplicate threat rules: {ids}")
    return rules
