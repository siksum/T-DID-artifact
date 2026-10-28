"""Product collectors: raw product records -> T-DID events.

A collector reads only records that the product's own components wrote (default logs, native
callbacks or SDK events, and records added at instrumentation points). It never opens test-client
traffic, scenario designs or ground truth; those files are listed in ``IGNORED`` and are skipped by
name, so a converted log cannot depend on them.

Two record levels share one mapping:
- ``native``: only what the unmodified product already emits.
- ``added``: native records plus the records added at T-DID instrumentation points.
Conversion cannot create information the product did not record; such fields are declared missing.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from tdid.collectors import credo, credo_vp, waltid
from tdid.collectors.common import IGNORED, Collected, finish

PRODUCTS = {"waltid": waltid, "credo": credo, "credo-vp": credo_vp}
LEVELS = ("native", "added")


def collect(product: str, path: Path, level: str = "added",
            policy: dict[str, Any] | None = None, fresh: bool = False) -> Collected:
    """``fresh``: the operator states that the product instance started with empty state for these
    records (e.g. launched for this run), so nothing relevant happened before the first record."""
    if product not in PRODUCTS:
        raise ValueError(f"unknown product {product!r}; expected one of {sorted(PRODUCTS)}")
    if level not in LEVELS:
        raise ValueError(f"unknown level {level!r}; expected one of {LEVELS}")
    if not Path(path).is_dir():
        raise ValueError(f"{path} is not a directory of raw product records")
    return finish(PRODUCTS[product].collect(Path(path), level, policy, fresh))


def convert(product: str, path: Path, level: str = "added",
            policy: dict[str, Any] | None = None, fresh: bool = False) -> list[dict[str, Any]]:
    return collect(product, path, level, policy, fresh).events


__all__ = ["IGNORED", "LEVELS", "PRODUCTS", "Collected", "collect", "convert"]
