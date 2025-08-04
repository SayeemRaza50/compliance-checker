"""Core compliance checking logic with optimized algorithms."""

import time
from typing import Dict, List, Any, Set, Optional
import yaml
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.model import Document, Package

from models import CheckResult, PolicyConfig


class ComplianceChecker:
    """Optimized SPDX compliance checker."""

    def __init__(self):
        self.policy_handlers = {
            "disallowed-licenses": self._check_licenses,
            "no-assertion-values": self._check_assertions,
            "required-copyright": self._check_copyright,
            "approved-suppliers": self._check_suppliers,
        }

    def check_compliance(self, sbom_path: str, policy_path: str) -> CheckResult:
        """Execute compliance checks with optimized performance."""
        start_time = time.time()

        policy = self._load_policy(policy_path)
        document = self._load_sbom(sbom_path)

        result = CheckResult()

        result.metadata = {
            "total_packages": len(document.packages) if document.packages else 0,
            "spdx_version": "SPDX-2.3",
            "document_name": getattr(document, "name", "SBOM Document"),
        }

        packages = document.packages if document.packages else []
        policy_config = PolicyConfig.from_dict(policy)

        for policy_type, handler in self.policy_handlers.items():
            if policy_type in policy:
                handler(packages, policy_config, result)

        result.metadata["processing_time"] = time.time() - start_time
        return result

    def _load_policy(self, policy_path: str) -> Dict[str, Any]:
        """Load policy file with error handling."""
        try:
            with open(policy_path, "r", encoding="utf-8") as f:
                return yaml.safe_load(f)
        except Exception as e:
            raise ValueError(f"Failed to load policy file: {e}")

    def _load_sbom(self, sbom_path: str) -> Document:
        """Load SBOM file with error handling."""
        try:
            return parse_file(sbom_path)
        except Exception as e:
            raise ValueError(f"Failed to load SBOM file: {e}")

    def _check_licenses(
        self, packages: List[Package], policy: PolicyConfig, result: CheckResult
    ) -> None:
        """Optimized license checking with O(n) complexity."""
        if not policy.disallowed_licenses:
            return

        # Convert to set for O(1) lookup
        disallowed: Set[str] = policy.disallowed_licenses
        violation_count = 0

        for pkg in packages:
            if pkg.license_concluded:
                license_str = str(pkg.license_concluded)
                if license_str in disallowed:
                    result.add_violation(
                        f"Package '{pkg.name}' uses disallowed license: {license_str}"
                    )
                    violation_count += 1

        if violation_count == 0:
            result.add_passed("disallowed-licenses: All packages use approved licenses")

    def _check_assertions(
        self, packages: List[Package], policy: PolicyConfig, result: CheckResult
    ) -> None:
        """Optimized NOASSERTION checking."""
        if not policy.no_assertion_fields:
            return

        fields = policy.no_assertion_fields
        violation_count = 0

        # Pre-compile the check value
        check_value = "NOASSERTION"

        for pkg in packages:
            for field in fields:
                value = getattr(pkg, field, None)
                if value and str(value).upper() == check_value:
                    result.add_violation(f"Package '{pkg.name}' has NOASSERTION for field: {field}")
                    violation_count += 1

        if violation_count == 0:
            result.add_passed("no-assertion-values: All critical fields have proper values")

    def _check_copyright(
        self, packages: List[Package], policy: PolicyConfig, result: CheckResult
    ) -> None:
        """Optimized copyright checking."""
        if not policy.required_copyright:
            return

        violation_count = 0

        for pkg in packages:
            # Single evaluation per package
            if not pkg.copyright_text or not str(pkg.copyright_text).strip():
                result.add_violation(f"Package '{pkg.name}' missing required copyright text")
                violation_count += 1

        if violation_count == 0:
            result.add_passed("required-copyright: All packages have copyright text")

    def _check_suppliers(
        self, packages: List[Package], policy: PolicyConfig, result: CheckResult
    ) -> None:
        """Optimized supplier checking with O(n) complexity."""
        if not policy.approved_suppliers:
            return

        approved: Set[str] = policy.approved_suppliers
        violation_count = 0

        prefix = "Organization: "
        prefix_len = len(prefix)

        for pkg in packages:
            if pkg.supplier:
                supplier_str = str(pkg.supplier)
                if supplier_str.startswith(prefix):
                    supplier_name = supplier_str[prefix_len:]
                else:
                    supplier_name = supplier_str

                if supplier_name not in approved:
                    result.add_violation(
                        f"Package '{pkg.name}' has unapproved supplier: {supplier_name}"
                    )
                    violation_count += 1

        if violation_count == 0:
            result.add_passed("approved-suppliers: All suppliers are approved")
