"""Prompt templates for security-ai-scanner."""

from importlib import resources

_LANGUAGE_NAMES = {
    "en": "English",
    "ja": "Japanese",
}


def load_scan_system_prompt(language: str = "en") -> str:
    """Load the security-scan system prompt for the given output language."""
    template = (
        resources.files(__package__).joinpath("security_scan.md").read_text("utf-8")
    )
    language_name = _LANGUAGE_NAMES.get(language, language)
    return template.replace("{language}", language_name)
