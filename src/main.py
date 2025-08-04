#!/usr/bin/env python3
"""SPDX Compliance Checker - Command line entry point."""

import argparse
import sys
from pathlib import Path

from checker import ComplianceChecker
from models import CheckResult


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Check SPDX SBOM files for compliance with organizational policies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
            %(prog)s --sbom examples/sbom.json --policy examples/policy.yml
            %(prog)s -s my_sbom.json -p security_policy.yml
        """,
    )
    parser.add_argument(
        "--sbom", "-s", required=True, type=Path, help="Path to SBOM file (SPDX 2.3 JSON format)"
    )
    parser.add_argument(
        "--policy", "-p", required=True, type=Path, help="Path to policy file (YAML format)"
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    args = parser.parse_args()

    if not args.sbom.exists():
        parser.error(f"SBOM file not found: {args.sbom}")
    if not args.policy.exists():
        parser.error(f"Policy file not found: {args.policy}")

    return args


def format_results(result: CheckResult, verbose: bool = False) -> None:
    """Print formatted compliance check results."""
    print("SPDX COMPLIANCE CHECK RESULTS")

    if result.violations:
        print(f"\n  VIOLATIONS FOUND ({len(result.violations)}):")
        for violation in result.violations:
            print(f"  • {violation}")
    else:
        print("NO VIOLATIONS FOUND")

    if result.passed_checks:
        print(f"PASSED CHECKS ({len(result.passed_checks)}):")
        for check in result.passed_checks:
            print(f"  • {check}")

    if verbose and result.metadata:
        print(f" METADATA:")
        print(f"  • Packages analyzed: {result.metadata.get('total_packages', 0)}")
        print(f"  • Processing time: {result.metadata.get('processing_time', 0):.3f}s")
        print(f"  • SBOM version: {result.metadata.get('spdx_version', 'Unknown')}")

    print("\n" + "=" * 60)
    print(f"Summary: {'COMPLIANT' if result.is_compliant else 'NON-COMPLIANT'}")
    print("=" * 60 + "\n")


def main():
    """Main entry point."""
    args = parse_arguments()

    try:
        checker = ComplianceChecker()
        result = checker.check_compliance(sbom_path=str(args.sbom), policy_path=str(args.policy))

        format_results(result, args.verbose)

        sys.exit(0 if result.is_compliant else 1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
