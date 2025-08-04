"""Integration tests for SPDX compliance checker."""

import unittest
import tempfile
import json
import yaml
import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from checker import ComplianceChecker


class TestIntegration(unittest.TestCase):
    """End-to-end integration tests."""

    def setUp(self):
        """Create temporary test files."""
        self.temp_dir = tempfile.mkdtemp()
        self.checker = ComplianceChecker()

    def tearDown(self):
        """Clean up temporary files."""
        import shutil

        shutil.rmtree(self.temp_dir)

    def _create_test_sbom(self, packages_data):
        """Create a test SBOM file."""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Test SBOM",
            "documentNamespace": "https://example.com/test",
            "creationInfo": {"created": "2025-08-03T10:00:00Z", "creators": ["Tool: test-1.0"]},
            "packages": packages_data,
        }

        sbom_path = Path(self.temp_dir) / "test_sbom.json"
        with open(sbom_path, "w") as f:
            json.dump(sbom, f)

        return str(sbom_path)

    def _create_test_policy(self, policy_data):
        """Create a test policy file."""
        policy_path = Path(self.temp_dir) / "test_policy.yml"
        with open(policy_path, "w") as f:
            yaml.dump(policy_data, f)

        return str(policy_path)

    def test_compliant_sbom(self):
        """Test fully compliant SBOM."""
        packages = [
            {
                "SPDXID": "SPDXRef-Package1",
                "name": "compliant-package",
                "downloadLocation": "https://example.com/package",
                "filesAnalyzed": False,
                "licenseConcluded": "MIT",
                "copyrightText": "Copyright 2025 Example Corp",
                "supplier": "Organization: Example Corp",
            }
        ]

        policy = {
            "disallowed-licenses": ["GPL-3.0"],
            "no-assertion-values": ["license_concluded"],
            "required-copyright": True,
            "approved-suppliers": ["Example Corp"],
        }

        sbom_path = self._create_test_sbom(packages)
        policy_path = self._create_test_policy(policy)

        result = self.checker.check_compliance(sbom_path, policy_path)

        self.assertTrue(result.is_compliant)
        self.assertEqual(len(result.violations), 0)
        self.assertEqual(len(result.passed_checks), 4)

    def test_multiple_violations(self):
        """Test SBOM with multiple violations."""
        packages = [
            {
                "SPDXID": "SPDXRef-Package1",
                "name": "bad-package-1",
                "downloadLocation": "https://example.com/bad1",
                "filesAnalyzed": False,
                "licenseConcluded": "GPL-3.0",
                "copyrightText": "",
                "supplier": "Organization: Unknown Corp",
            },
            {
                "SPDXID": "SPDXRef-Package2",
                "name": "bad-package-2",
                "downloadLocation": "https://example.com/bad2",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "copyrightText": "Copyright 2025 Good Corp",
                "supplier": "Organization: Good Corp",
            },
        ]

        policy = {
            "disallowed-licenses": ["GPL-3.0"],
            "no-assertion-values": ["license_concluded"],
            "required-copyright": True,
            "approved-suppliers": ["Good Corp"],
        }

        sbom_path = self._create_test_sbom(packages)
        policy_path = self._create_test_policy(policy)

        result = self.checker.check_compliance(sbom_path, policy_path)

        self.assertFalse(result.is_compliant)
        self.assertEqual(len(result.violations), 4)  # GPL, copyright, supplier, NOASSERTION
        self.assertEqual(len(result.passed_checks), 0)

    def test_performance_large_sbom(self):
        """Test performance with large SBOM."""
        # Create 1000 packages
        packages = []
        for i in range(1000):
            packages.append(
                {
                    "SPDXID": f"SPDXRef-Package{i}",
                    "name": f"package-{i}",
                    "downloadLocation": f"https://example.com/pkg{i}",
                    "filesAnalyzed": False,
                    "licenseConcluded": "MIT" if i % 10 != 0 else "GPL-3.0",
                    "copyrightText": f"Copyright 2025 Company{i % 5}",
                    "supplier": f"Organization: Company{i % 5}",
                }
            )

        policy = {
            "disallowed-licenses": ["GPL-3.0"],
            "required-copyright": True,
            "approved-suppliers": ["Company0", "Company1", "Company2"],
        }

        sbom_path = self._create_test_sbom(packages)
        policy_path = self._create_test_policy(policy)

        import time

        start = time.time()
        result = self.checker.check_compliance(sbom_path, policy_path)
        duration = time.time() - start

        # Should process 1000 packages in under 1 second
        self.assertLess(duration, 1.0)
        self.assertFalse(result.is_compliant)
        self.assertGreater(len(result.violations), 0)

        # Verify metadata
        self.assertEqual(result.metadata["total_packages"], 1000)


if __name__ == "__main__":
    unittest.main()
