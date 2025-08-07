"""Core compliance checking logic with optimized algorithms."""

import time
from typing import Dict, List, Any, Set
import yaml
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.model import Document, Package
from license_expression import Licensing

from models import CheckResult, PolicyConfig

_licensing = Licensing()

ALIAS_MAP = {
    "GPL V3": "GPL-3.0-only",
    "GPL V2": "GPL-2.0-only", 
    "APACHE LICENSE 2.0": "Apache-2.0",
    "APACHE 2.0": "Apache-2.0",
    "MIT LICENSE": "MIT",
    "BSD 3-CLAUSE": "BSD-3-Clause",
    "MPL 2.0": "MPL-2.0",
}

IGNORED_LICENSES = {
    "NOASSERTION", "NONE", "", "UNKNOWN", "PROPRIETARY", 
    "NO-LICENSE", "UNLICENSED", "COMMERCIAL", "CUSTOM"
}

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
        packages = document.packages or []
        policy_config = PolicyConfig.from_dict(policy)

        result = CheckResult()

        result.metadata = {
            "total_packages": len(packages),
            "spdx_version": "SPDX-2.3",
            "document_name": getattr(document, "name", "SBOM Document"),
        }

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

    def _normalize_license_string(self, license_str: str) -> str:
        if not license_str:
            return license_str
        cleaned = license_str.strip().upper().replace("LICENSE", "").replace("THE ", "")
        cleaned = " ".join(cleaned.split())
        if cleaned in ALIAS_MAP:
            return ALIAS_MAP[cleaned]

        normalized_parts = []
        parts = cleaned.split()
        i = 0
        while i < len(parts):
            found_match = False
            for length in range(min(4, len(parts) - i), 0, -1):
                phrase = " ".join(parts[i:i+length])
                if phrase in ALIAS_MAP:
                    normalized_parts.append(ALIAS_MAP[phrase])
                    i += length
                    found_match = True
                    break
            if not found_match:
                normalized_parts.append(parts[i])
                i += 1
        return " ".join(normalized_parts)

    def _is_license_disallowed(self, license_expr, disallowed_licenses: Set[str]) -> bool:
        if license_expr is None or not disallowed_licenses:
            return False
        expr_str = str(license_expr).strip()
        if expr_str.upper() in IGNORED_LICENSES:
            return False
        if expr_str in disallowed_licenses:
            return True
        normalized = self._normalize_license_string(expr_str)
        if normalized.upper() in IGNORED_LICENSES:
            return False
        if normalized in disallowed_licenses:
            return True
        try:
            expr = _licensing.parse(expr_str)
            return self._check_expression(expr, disallowed_licenses)
        except Exception:
            return self._fallback_check(expr_str, disallowed_licenses)

    def _check_expression(self, node, disallowed_licenses: Set[str]) -> bool:
        if getattr(node, 'isliteral', False) and hasattr(node, 'key'):
            key = node.key
            norm_key = self._normalize_license_string(key)
            return key in disallowed_licenses or norm_key in disallowed_licenses
        if hasattr(node, 'license_symbol'):
            return self._check_expression(node.license_symbol, disallowed_licenses)
        operator = getattr(node, 'operator', None)
        if operator is not None:
            op = str(operator).lower().strip()
            operands = getattr(node, 'args', None) or getattr(node, 'children', None) or getattr(node, 'operands', None)
            if operands:
                if op == 'or':
                    return all(self._check_expression(o, disallowed_licenses) for o in operands)
                if op == 'and':
                    return any(self._check_expression(o, disallowed_licenses) for o in operands)
        node_str = str(node).strip()
        norm_str = self._normalize_license_string(node_str)
        return node_str in disallowed_licenses or norm_str in disallowed_licenses

    def _fallback_check(self, expr_str: str, disallowed_licenses: Set[str]) -> bool:
        if ' OR ' in expr_str:
            parts = [p.strip() for p in expr_str.split(' OR ')]
            norms = [self._normalize_license_string(p) for p in parts]
            return all(p in disallowed_licenses or n in disallowed_licenses for p,n in zip(parts, norms))
        if ' AND ' in expr_str:
            parts = [p.strip() for p in expr_str.split(' AND ')]
            norms = [self._normalize_license_string(p) for p in parts]
            return any(p in disallowed_licenses or n in disallowed_licenses for p,n in zip(parts, norms))
        if ' WITH ' in expr_str:
            base = expr_str.split(' WITH ')[0].strip()
            nbase = self._normalize_license_string(base)
            return base in disallowed_licenses or nbase in disallowed_licenses
        norm = self._normalize_license_string(expr_str)
        return expr_str in disallowed_licenses or norm in disallowed_licenses

    def _check_licenses(
        self, packages: List[Package], policy: PolicyConfig, result: CheckResult
    ) -> None:
        """Optimized license checking with O(n) complexity."""
        if not policy.disallowed_licenses:
            return
        violations = 0
        for pkg in packages:
            if pkg.license_concluded is not None and self._is_license_disallowed(pkg.license_concluded, policy.disallowed_licenses):
                result.add_violation(f"Package '{pkg.name}' uses disallowed license: {pkg.license_concluded}")
                violations += 1
        if violations == 0:
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
                if value is not None and str(value).upper() == check_value:
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
