"""Unit tests for compliance checker."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checker import ComplianceChecker
from models import CheckResult, PolicyConfig
from spdx_tools.spdx.model import Package


class TestComplianceChecker(unittest.TestCase):
    """Test compliance checking logic."""

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

    def test_check_licenses_with_violations(self):
        """Test license checking detects violations."""
        policy = PolicyConfig(disallowed_licenses={"MPL-1.0", "GPL-3.0"})
        packages = [
            self._create_package("pkg1", license_concluded="MIT"),
            self._create_package("pkg2", license_concluded="MPL-1.0"),
            self._create_package("pkg3", license_concluded="GPL-3.0"),
        ]

        self.checker._check_licenses(packages, policy, self.result)

        self.assertEqual(len(self.result.violations), 2)
        self.assertIn("pkg2", self.result.violations[0])
        self.assertIn("MPL-1.0", self.result.violations[0])
        self.assertIn("pkg3", self.result.violations[1])
        self.assertIn("GPL-3.0", self.result.violations[1])

    def test_check_licenses_all_approved(self):
        """Test license checking when all licenses are approved."""
        policy = PolicyConfig(disallowed_licenses={"MPL-1.0"})
        packages = [
            self._create_package("pkg1", license_concluded="MIT"),
            self._create_package("pkg2", license_concluded="Apache-2.0"),
        ]

        self.checker._check_licenses(packages, policy, self.result)

        self.assertEqual(len(self.result.violations), 0)
        self.assertEqual(len(self.result.passed_checks), 1)
        self.assertIn("approved licenses", self.result.passed_checks[0])

    def test_check_assertions_detects_noassertion(self):
        """Test NOASSERTION detection."""
        policy = PolicyConfig(no_assertion_fields=["license_concluded", "supplier"])
        packages = [
            self._create_package("pkg1", license_concluded="MIT", supplier="Acme"),
            self._create_package("pkg2", license_concluded="NOASSERTION", supplier="Widget"),
        ]

        self.checker._check_assertions(packages, policy, self.result)

        self.assertEqual(len(self.result.violations), 1)
        self.assertIn("pkg2", self.result.violations[0])
        self.assertIn("license_concluded", self.result.violations[0])

    def test_check_copyright_missing(self):
        """Test copyright checking for missing text."""
        policy = PolicyConfig(required_copyright=True)
        packages = [
            self._create_package("pkg1", copyright_text="Copyright 2024 Acme"),
            self._create_package("pkg2", copyright_text=""),
            self._create_package("pkg3", copyright_text=None),
        ]

        self.checker._check_copyright(packages, policy, self.result)

        self.assertEqual(len(self.result.violations), 2)
        self.assertTrue(any("pkg2" in v for v in self.result.violations))
        self.assertTrue(any("pkg3" in v for v in self.result.violations))

    def test_check_suppliers_unapproved(self):
        """Test supplier checking detects unapproved suppliers."""
        policy = PolicyConfig(approved_suppliers={"Acme Corp", "Widget Inc"})
        packages = [
            self._create_package("pkg1", supplier="Organization: Acme Corp"),
            self._create_package("pkg2", supplier="Organization: Evil Corp"),
            self._create_package("pkg3", supplier="Widget Inc"),  # No prefix
        ]

        self.checker._check_suppliers(packages, policy, self.result)

        self.assertEqual(len(self.result.violations), 1)
        self.assertIn("pkg2", self.result.violations[0])
        self.assertIn("Evil Corp", self.result.violations[0])

    def test_policy_config_from_dict(self):
        """Test PolicyConfig creation from dictionary."""
        config_dict = {
            "disallowed-licenses": ["MPL-1.0", "GPL-3.0"],
            "no-assertion-values": ["license_concluded"],
            "required-copyright": True,
            "approved-suppliers": ["Acme", "Widget"],
        }

        policy = PolicyConfig.from_dict(config_dict)

        self.assertEqual(policy.disallowed_licenses, {"MPL-1.0", "GPL-3.0"})
        self.assertEqual(policy.no_assertion_fields, ["license_concluded"])
        self.assertTrue(policy.required_copyright)
        self.assertEqual(policy.approved_suppliers, {"Acme", "Widget"})

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
