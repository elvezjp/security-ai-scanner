"""Exception types for security-ai-scanner."""


class ScannerError(Exception):
    """Base class for all security-ai-scanner errors."""


class TargetError(ScannerError):
    """The scan target is missing or not usable."""


class EngineError(ScannerError):
    """The AI engine failed to run or returned an error."""


class FindingsParseError(ScannerError):
    """The engine output could not be parsed into findings."""
