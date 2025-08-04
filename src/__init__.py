"""SPDX Compliance Checker Package."""

from .checker import ComplianceChecker
from .models import CheckResult, PolicyConfig

__version__ = "1.0.0"
__all__ = ["ComplianceChecker", "CheckResult", "PolicyConfig"]
