"""Unit tests for compliance checker."""

import unittest
from unittest.mock import Mock
import sys
import os
import yaml

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checker import ComplianceChecker
from models import CheckResult, PolicyConfig
from spdx_tools.spdx.model import Package


class TestComplianceChecker(unittest.TestCase):
    """Test compliance checking logic."""
    @classmethod
    def setUpClass(cls):
        policy_path = os.path.join(os.path.dirname(__file__), "..", "examples/policy.yml")
        with open(policy_path, "r", encoding="utf-8") as f:
            policy_dict = yaml.safe_load(f)
        cls.policy_config = PolicyConfig.from_dict(policy_dict)
        cls.disallowed_licenses = cls.policy_config.disallowed_licenses
        cls.approved_suppliers = cls.policy_config.approved_suppliers
        cls.no_assertion_fields = cls.policy_config.no_assertion_fields
        cls.required_copyright = cls.policy_config.required_copyright

    def setUp(self):
        """Set up test fixtures."""
        self.checker = ComplianceChecker()
        self.result = CheckResult()

    def _create_package(self, name: str, **kwargs) -> Mock:
        """Helper to create mock package."""
        pkg = Mock(spec=Package)
        pkg.name = name
        for key, value in kwargs.items():
            setattr(pkg, key, value)
        return pkg

    def test_normalize_license_string(self):
        checker = self.checker
        self.assertEqual(checker._normalize_license_string("GPL V3"), "GPL-3.0-only")
        self.assertEqual(checker._normalize_license_string("Apache License 2.0"), "Apache-2.0")
        self.assertEqual(checker._normalize_license_string("MIT License"), "MIT")
        self.assertEqual(checker._normalize_license_string("BSD 3-Clause"), "BSD-3-Clause")
        self.assertEqual(checker._normalize_license_string("gpl v3"), "GPL-3.0-only")
        self.assertEqual(checker._normalize_license_string("apache license 2.0"), "Apache-2.0")
        normalized = checker._normalize_license_string("GPL V3 OR MIT License")
        self.assertIn("GPL-3.0-only", normalized)
        self.assertIn("MIT", normalized)
        self.assertEqual(checker._normalize_license_string("  GPL   V3  "), "GPL-3.0-only")

    def test_alias_normalization_integration(self):
        checker = self.checker
        normalized = checker._normalize_license_string("GPL V3")
        self.assertEqual(normalized, "GPL-3.0-only")
        if "GPL-3.0-only" in self.disallowed_licenses:
            self.assertTrue(checker._is_license_disallowed("GPL-3.0-only", self.disallowed_licenses))
            result = checker._is_license_disallowed("GPL V3", self.disallowed_licenses)
            self.assertTrue(result)

    def test_is_license_disallowed_simple(self):
        checker = self.checker
        for disallowed_license in self.disallowed_licenses:
            self.assertTrue(checker._is_license_disallowed(disallowed_license, self.disallowed_licenses))
        allowed_licenses = ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"]
        for allowed_license in allowed_licenses:
            self.assertFalse(checker._is_license_disallowed(allowed_license, self.disallowed_licenses))
        if "GPL-3.0-only" in self.disallowed_licenses:
            self.assertTrue(checker._is_license_disallowed("GPL V3", self.disallowed_licenses))

    def test_is_license_disallowed_nested_expressions(self):
        checker = self.checker
        disallowed_list = list(self.disallowed_licenses)
        if len(disallowed_list) >= 2:
            d1, d2 = disallowed_list[0], disallowed_list[1]
            self.assertFalse(checker._is_license_disallowed(f"({d1} OR MIT) AND Apache-2.0", self.disallowed_licenses))
            self.assertTrue(checker._is_license_disallowed(f"({d1} OR {d2}) AND Apache-2.0", self.disallowed_licenses))
            self.assertFalse(checker._is_license_disallowed(f"(MIT OR Apache-2.0) AND ({d1} OR BSD-3-Clause)", self.disallowed_licenses))
            self.assertTrue(checker._is_license_disallowed(f"({d1} OR {d2}) AND (MIT OR Apache-2.0)", self.disallowed_licenses))

    def test_is_license_disallowed_multiple_or_and(self):
        checker = self.checker
        self.assertFalse(checker._is_license_disallowed("MIT OR Apache-2.0 OR BSD-3-Clause", self.disallowed_licenses))
        disallowed_list = list(self.disallowed_licenses)
        if len(disallowed_list) >= 2:
            expr = f"{disallowed_list[0]} OR {disallowed_list[1]} OR MIT"
            self.assertFalse(checker._is_license_disallowed(expr, self.disallowed_licenses))
            if len(disallowed_list) >= 3:
                expr = f"{disallowed_list[0]} OR {disallowed_list[1]} OR {disallowed_list[2]}"
                self.assertTrue(checker._is_license_disallowed(expr, self.disallowed_licenses))
        self.assertFalse(checker._is_license_disallowed("MIT AND Apache-2.0 AND BSD-3-Clause", self.disallowed_licenses))
        if disallowed_list:
            expr = f"MIT AND {disallowed_list[0]} AND Apache-2.0"
            self.assertTrue(checker._is_license_disallowed(expr, self.disallowed_licenses))

    def test_is_license_disallowed_with_aliases(self):
        checker = self.checker
        expr1 = "GPL V3 OR MIT"
        self.assertFalse(checker._is_license_disallowed(expr1, self.disallowed_licenses))
        expr2 = "Apache License 2.0 AND MIT"
        if "Apache-2.0" in self.disallowed_licenses:
            self.assertTrue(checker._is_license_disallowed(expr2, self.disallowed_licenses))
        else:
            self.assertFalse(checker._is_license_disallowed(expr2, self.disallowed_licenses))
        expr3 = "GPL V2 OR MPL 2.0"
        gpl2 = "GPL-2.0-only" in self.disallowed_licenses
        mpl2 = "MPL-2.0" in self.disallowed_licenses
        if gpl2 and mpl2:
            self.assertTrue(checker._is_license_disallowed(expr3, self.disallowed_licenses))
        else:
            self.assertFalse(checker._is_license_disallowed(expr3, self.disallowed_licenses))

    def test_is_license_disallowed_special_values(self):
        checker = self.checker
        special_values = ["NOASSERTION", "NONE", "", "UNKNOWN", "PROPRIETARY", "NO-LICENSE", "UNLICENSED", "COMMERCIAL", "CUSTOM"]
        for special in special_values:
            self.assertFalse(checker._is_license_disallowed(special, self.disallowed_licenses))

    def test_is_license_disallowed_with_exceptions(self):
        checker = self.checker
        disallowed_list = list(self.disallowed_licenses)
        if disallowed_list:
            expr1 = f"{disallowed_list[0]} WITH Classpath-exception-2.0"
            self.assertTrue(checker._is_license_disallowed(expr1, self.disallowed_licenses))
            self.assertFalse(checker._is_license_disallowed("MIT WITH Custom-exception", self.disallowed_licenses))
            expr3 = f"({disallowed_list[0]} WITH GCC-exception-3.1) OR MIT"
            self.assertFalse(checker._is_license_disallowed(expr3, self.disallowed_licenses))

    def test_is_license_disallowed_malformed_expressions(self):
        checker = self.checker
        disallowed_list = list(self.disallowed_licenses)
        if disallowed_list:
            malformed = [
                f"{disallowed_list[0]} AND OR MIT",
                f"(({disallowed_list[0]} OR MIT)",
                f"{disallowed_list[0]} MAYBE MIT",
            ]
            for expr in malformed:
                result = checker._is_license_disallowed(expr, self.disallowed_licenses)
                self.assertIsInstance(result, bool)

    def test_check_licenses_complex_integration(self):
        """Test license checking detects violations."""
        disallowed = list(self.disallowed_licenses)
        packages = [
            self._create_package("pkg1", license_concluded="MIT"),
            self._create_package("pkg2", license_concluded=disallowed[0] if disallowed else "GPL-3.0-only"),
            self._create_package("pkg3", license_concluded=f"{disallowed[0]} OR MIT" if disallowed else "GPL-3.0-only OR MIT"),
            self._create_package("pkg4", license_concluded=f"{disallowed[0]} OR {disallowed[1]}" if len(disallowed) >= 2 else "GPL-3.0-only OR MPL-1.0"),
            self._create_package("pkg5", license_concluded=f"({disallowed[0]} OR BSD-3-Clause) AND MIT" if disallowed else "(GPL-3.0-only OR BSD-3-Clause) AND MIT"),
            self._create_package("pkg6", license_concluded=f"({disallowed[0]} OR {disallowed[1]}) AND Apache-2.0" if len(disallowed) >= 2 else "(GPL-3.0-only OR MPL-1.0) AND Apache-2.0"),
            self._create_package("pkg7", license_concluded="GPL V3 OR Apache License 2.0"),
            self._create_package("pkg8", license_concluded="NOASSERTION"),
            self._create_package("pkg9", license_concluded=f"{disallowed[0]} WITH GCC-exception-3.1" if disallowed else "GPL-3.0-only WITH GCC-exception-3.1"),
            self._create_package("pkg10", license_concluded=f"{disallowed[0]} OR {disallowed[1]} OR MIT" if len(disallowed) >= 2 else "GPL-3.0-only OR MPL-1.0 OR MIT"),
            self._create_package("pkg11", license_concluded=f"GPL V3 OR {disallowed[1]}" if len(disallowed) >= 2 and "GPL-3.0-only" in self.disallowed_licenses else "GPL V3 OR MPL-1.0"),
        ]
        self.checker._check_licenses(packages, self.policy_config, self.result)
        violation_names = [v.split("Package '")[1].split("'")[0] for v in self.result.violations if "Package '" in v]
        expected = {"pkg2", "pkg9"}
        if len(disallowed) >= 2:
            expected.update({"pkg4", "pkg6"})
        if len(disallowed) >= 2 and "GPL-3.0-only" in self.disallowed_licenses:
            expected.add("pkg11")
        self.assertEqual(set(violation_names), expected)

    def test_check_licenses_with_violations(self):
        disallowed = list(self.disallowed_licenses)
        packages = [self._create_package("pkg1", license_concluded="MIT")]
        for i, disallowed_license in enumerate(disallowed[:2]):
            packages.append(self._create_package(f"pkg{i+2}", license_concluded=disallowed_license))
        self.checker._check_licenses(packages, self.policy_config, self.result)
        self.assertEqual(len(self.result.violations), len(disallowed[:2]))

    def test_check_licenses_all_approved(self):
        """Test license checking when all licenses are approved."""
        packages = [
            self._create_package("pkg1", license_concluded="MIT"),
            self._create_package("pkg2", license_concluded="Apache-2.0"),
        ]

        self.checker._check_licenses(packages, self.policy_config, self.result)

        self.assertEqual(len(self.result.violations), 0)
        self.assertEqual(len(self.result.passed_checks), 1)
        self.assertIn("approved licenses", self.result.passed_checks[0])

    def test_check_assertions_detects_noassertion(self):
        """Test NOASSERTION detection."""
        packages = [self._create_package("pkg1", license_concluded="MIT", supplier="Acme")]
        pkg2 = self._create_package("pkg2", supplier="Widget")
        for field in self.no_assertion_fields:
            setattr(pkg2, field, "NOASSERTION")
        packages.append(pkg2)
        self.checker._check_assertions(packages, self.policy_config, self.result)
        self.assertGreaterEqual(len(self.result.violations), 1)
        self.assertTrue(any("pkg2" in v for v in self.result.violations))

    def test_check_copyright_missing(self):
        if not self.required_copyright:
            self.skipTest("Not required")
        packages = [
            self._create_package("pkg1", copyright_text="Copyright 2024 Acme"),
            self._create_package("pkg2", copyright_text=""),
            self._create_package("pkg3", copyright_text=None),
        ]

        self.checker._check_copyright(packages, self.policy_config, self.result)

        self.assertEqual(len(self.result.violations), 2)
        self.assertTrue(any("pkg2" in v for v in self.result.violations))
        self.assertTrue(any("pkg3" in v for v in self.result.violations))

    def test_check_suppliers_unapproved(self):
        approved = list(self.approved_suppliers)
        packages = []
        if approved:
            packages.append(self._create_package("pkg1", supplier=f"Organization: {approved[0]}"))
            if len(approved) > 1:
                packages.append(self._create_package("pkg3", supplier=approved[1]))
        packages.append(self._create_package("pkg2", supplier="Organization: Evil Corp"))

        self.checker._check_suppliers(packages, self.policy_config, self.result)

        self.assertEqual(len(self.result.violations), 1)
        self.assertIn("pkg2", self.result.violations[0])
        self.assertIn("Evil Corp", self.result.violations[0])

    def test_policy_config_from_dict(self):
        """Test PolicyConfig creation from dictionary."""
        self.assertIsInstance(self.policy_config.disallowed_licenses, set)
        self.assertIsInstance(self.policy_config.approved_suppliers, set)
        self.assertIsInstance(self.policy_config.no_assertion_fields, list)
        self.assertIsInstance(self.policy_config.required_copyright, bool)
        self.assertGreater(len(self.policy_config.disallowed_licenses), 0)
        self.assertGreater(len(self.policy_config.approved_suppliers), 0)

    def test_empty_policy(self):
        """Test handling of empty policy."""
        policy = PolicyConfig()
        packages = [self._create_package("pkg1", license_concluded="MIT")]

        # Should not raise any errors
        self.checker._check_licenses(packages, policy, self.result)
        self.checker._check_assertions(packages, policy, self.result)
        self.checker._check_copyright(packages, policy, self.result)
        self.checker._check_suppliers(packages, policy, self.result)

        self.assertEqual(len(self.result.violations), 0)


if __name__ == "__main__":
    unittest.main()
