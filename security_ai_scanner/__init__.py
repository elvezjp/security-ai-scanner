"""security-ai-scanner: AI-powered security scanner for source code.

Public API:

    from security_ai_scanner import ScanConfig, run_scan

    result = run_scan(ScanConfig(target=Path("path/to/repo")))
    for finding in result.output.findings:
        print(finding.severity, finding.title)
"""

# Single-sourced from pyproject.toml via the installed distribution
# metadata, so summary.json / findings.json / --version cannot drift
# from the released version.
from importlib.metadata import PackageNotFoundError, version  # noqa: E402

try:
    __version__ = version("security-ai-scanner")
except PackageNotFoundError:  # pragma: no cover - source tree without install
    __version__ = "0.0.0+unknown"
del PackageNotFoundError, version

from .config import ScanConfig  # noqa: E402
from .findings import Finding, ScanOutput  # noqa: E402

__all__ = ["ScanConfig", "Finding", "ScanOutput", "run_scan", "__version__"]


def run_scan(config: ScanConfig):
    """Run a scan. Imported lazily to keep `import security_ai_scanner` light."""
    from .runner import run_scan as _run_scan

    return _run_scan(config)
