from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
NUMBERED_HEADING = re.compile(r"^(#{2,3})\s+(\d+(?:\.\d+)*)\.", re.MULTILINE)
HEADING = re.compile(r"^(#+)\s+", re.MULTILINE)


def read_document(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_product_specifications_have_matching_section_structure() -> None:
    english = NUMBERED_HEADING.findall(read_document("spec.md"))
    japanese = NUMBERED_HEADING.findall(read_document("spec_ja.md"))
    assert english == japanese


def test_readmes_link_to_their_primary_product_specification() -> None:
    assert "spec.md" in read_document("README.md")
    assert "spec_ja.md" in read_document("README_ja.md")


def test_product_specifications_link_to_each_other() -> None:
    assert "spec_ja.md" in read_document("spec.md")
    assert "spec.md" in read_document("spec_ja.md")


def test_bilingual_governance_documents_have_matching_structure() -> None:
    for english_name, japanese_name in (
        ("CONTRIBUTING.md", "CONTRIBUTING_ja.md"),
        ("PROVENANCE.md", "PROVENANCE_ja.md"),
    ):
        assert HEADING.findall(read_document(english_name)) == HEADING.findall(
            read_document(japanese_name)
        )
        assert japanese_name in read_document(english_name)
        assert english_name in read_document(japanese_name)
