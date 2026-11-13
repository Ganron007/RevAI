"""Report manifest generation and section row source mappings (RC-39, RC-62, RC-74).

Exposes deterministic section row manifests and frontier builders for technical
and master reports, covering static tools, UPX second-pass, and dynamic pack evidence.
"""

from v2_lib import (
    SECTION_ROW_SOURCES,
    UPX_SECTION_ROW_SOURCES,
    DYNAMIC_SECTION_ROW_SOURCES,
    SECTION_NAME_ALIASES,
    build_section_row_manifest,
    build_section_frontier,
)

__all__ = [
    "SECTION_ROW_SOURCES",
    "UPX_SECTION_ROW_SOURCES",
    "DYNAMIC_SECTION_ROW_SOURCES",
    "SECTION_NAME_ALIASES",
    "build_section_row_manifest",
    "build_section_frontier",
]
