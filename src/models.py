"""Data models for SPDX compliance checker."""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Set, Optional


@dataclass
class CheckResult:
    """Optimized result container with efficient operations."""

    violations: List[str] = field(default_factory=list)
    passed_checks: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_compliant(self) -> bool:
        """Check if SBOM is compliant (no violations)."""
        return len(self.violations) == 0

    def add_violation(self, message: str) -> None:
        """Add a violation message."""
        self.violations.append(message)

    def add_passed(self, message: str) -> None:
        """Add a passed check message."""
        self.passed_checks.append(message)


@dataclass
class PolicyConfig:
    """Optimized policy configuration with pre-processed data."""

    disallowed_licenses: Set[str] = field(default_factory=set)
    no_assertion_fields: List[str] = field(default_factory=list)
    required_copyright: bool = False
    approved_suppliers: Set[str] = field(default_factory=set)

    @classmethod
    def from_dict(cls, config: Dict[str, Any]) -> "PolicyConfig":
        """Create PolicyConfig from dictionary with optimization."""
        return cls(
            disallowed_licenses=set(config.get("disallowed-licenses", [])),
            no_assertion_fields=config.get("no-assertion-values", []),
            required_copyright=config.get("required-copyright", False),
            approved_suppliers=set(config.get("approved-suppliers", [])),
        )
