# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Palusomni Co., Ltd.
"""E1 inventories: one ``<sha256>  <path>`` line per artifact of a deployed configuration (``sha256sum`` format)."""
from __future__ import annotations
import os
from .canon import open_bytes, sha_raw


class InventoryError(ValueError):
    pass


def parse_inventory(path: str) -> dict[str, str]:
    """basename -> sha256.  A duplicated basename cannot be bound unambiguously and is rejected, not resolved."""
    inv, dup = {}, []
    with open_bytes(path) as f:
        for raw in f.read().decode("utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"): continue
            parts = line.split(None, 1)
            if len(parts) != 2 or len(parts[0]) != 64: raise InventoryError(f"malformed inventory line: {raw!r}")
            base = os.path.basename(parts[1].strip().lstrip("*"))
            if base in inv: dup.append(base)
            inv[base] = parts[0].lower()
    if dup: raise InventoryError(f"duplicate inventory basenames: {sorted(set(dup))}")
    return inv


def make_inventory(paths) -> str:
    """Inventory text for the given files (basenames only, so no machine-specific path is recorded).

    Artifacts are identified by file name, so two files of the same name cannot both be listed: they are refused here,
    as ``parse_inventory`` would refuse the result."""
    paths = list(paths); names = [os.path.basename(p) for p in paths]
    dup = sorted({n for n in names if names.count(n) > 1})
    if dup: raise InventoryError(f"duplicate file names {dup}: an inventory identifies artifacts by file name; give the files distinct names")
    return "".join(f"{sha_raw(p)}  {os.path.basename(p)}\n" for p in sorted(paths, key=os.path.basename))
