from __future__ import annotations

import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_mit_license_and_compliance_documents_are_packaged() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    metadata = project["project"]
    wheel_files = project["tool"]["hatch"]["build"]["targets"]["wheel"][
        "force-include"
    ]
    sdist_files = project["tool"]["hatch"]["build"]["targets"]["sdist"][
        "include"
    ]

    assert metadata["license"] == "MIT"
    assert metadata["license-files"] == ["LICENSE"]
    assert wheel_files["THIRD_PARTY_NOTICES.md"] == (
        "security_ai_scanner/THIRD_PARTY_NOTICES.md"
    )
    for name in (
        "LICENSE",
        "THIRD_PARTY_NOTICES.md",
        "PROVENANCE.md",
        "PROVENANCE_ja.md",
    ):
        assert name in sdist_files


def test_claude_sdk_is_opt_in_and_documented() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))
    metadata = project["project"]
    notices = (ROOT / "THIRD_PARTY_NOTICES.md").read_text("utf-8")

    assert metadata["dependencies"] == []
    assert any(
        dependency.startswith("claude-agent-sdk>=")
        for dependency in metadata["optional-dependencies"]["claude"]
    )
    assert "Commercial Terms of Service" in notices
