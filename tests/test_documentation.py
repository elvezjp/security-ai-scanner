from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NUMBERED_HEADING = re.compile(r"^(#{2,3})\s+(\d+(?:\.\d+)*)\.", re.MULTILINE)


def test_product_specifications_have_matching_section_structure() -> None:
    english = NUMBERED_HEADING.findall((ROOT / "spec.md").read_text())
    japanese = NUMBERED_HEADING.findall((ROOT / "spec_ja.md").read_text())
    assert english == japanese


def test_readmes_link_to_their_primary_product_specification() -> None:
    assert "spec.md" in (ROOT / "README.md").read_text()
    assert "spec_ja.md" in (ROOT / "README_ja.md").read_text()


def test_product_specifications_link_to_each_other() -> None:
    assert "spec_ja.md" in (ROOT / "spec.md").read_text()
    assert "spec.md" in (ROOT / "spec_ja.md").read_text()
