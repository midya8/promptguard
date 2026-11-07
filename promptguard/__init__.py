"""Local-first prompt, secret and prompt-injection linting."""

from .models import Finding, ScanResult
from .scanner import scan_paths, scan_text

__all__ = ["Finding", "ScanResult", "scan_paths", "scan_text"]
__version__ = "0.1.0"
