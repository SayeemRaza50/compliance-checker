# SPDX Compliance Checker

Command-line tool for validating SPDX 2.3 SBOM files against organizational security policies.

## Features

- Fast O(n) processing for large SBOMs
- Validates licenses, assertions, copyright, and suppliers
- Clear violation reporting with specific package details
- Exit codes for CI/CD integration
- Modular architecture for adding new policy types

## Installation

```bash
# Clone repository
git clone https://github.com/ SayeemRaza50/spdx-compliance-checker.git
cd spdx-compliance-checker

# Setup virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

After installation via setup.py, you can use the command directly:
```bash
spdx-check --sbom examples/sbom.json --policy examples/policy.yml
```

## Usage

### Basic Command

```bash
python src/main.py --sbom <path_to_sbom> --policy <path_to_policy>
```

### Options

- `--sbom, -s`: Path to SBOM file (SPDX 2.3 JSON format) [required]
- `--policy, -p`: Path to policy file (YAML format) [required]  
- `--verbose, -v`: Show detailed output with metadata

### Exit Codes

- `0`: SBOM is fully compliant
- `1`: Policy violations detected
- `2`: Processing error

## Policy Configuration

Define compliance rules in YAML format:

```yaml
# Disallowed licenses
disallowed-licenses:
  - MPL-1.0
  - GPL-3.0
  - AGPL-3.0

# Fields that must not contain NOASSERTION
no-assertion-values:
  - license_concluded
  - supplier

# Require copyright text for all packages
required-copyright: true

# List of approved suppliers
approved-suppliers:
  - "Acme Corporation"
  - "Widget Inc"
  - "Example Company"
  - "OpenSource Foundation"
```

## Testing

```bash
# Run non-compliant SBOM check (will show violations)
make run

# Run compliant SBOM check (will pass)
make run2

# Run all unit tests
make test

# Run specific test module
python -m unittest tests.test_checker

# Run with pytest
python -m pytest tests/ -v
```

## Output Format

### Non-compliant SBOM output:
```
SPDX COMPLIANCE CHECK RESULTS

VIOLATIONS FOUND (5):
• Package 'tensorflow' has NOASSERTION for field: license_concluded
• Package 'mysql-connector' uses disallowed license: GPL-3.0
• Package 'custom-auth-lib' missing required copyright text
• Package 'custom-auth-lib' has NOASSERTION for field: supplier
• Package 'react' has unapproved supplier: Meta Platforms

PASSED CHECKS (0):

============================================================
Summary: NON-COMPLIANT
============================================================
```

### Compliant SBOM output:
```
SPDX COMPLIANCE CHECK RESULTS

NO VIOLATIONS FOUND

PASSED CHECKS (4):
• disallowed-licenses: All packages use approved licenses
• no-assertion-values: All critical fields have proper values
• required-copyright: All packages have copyright text
• approved-suppliers: All suppliers are approved

============================================================
Summary: COMPLIANT
============================================================
```

## CI/CD Integration

The tool integrates seamlessly with CI/CD pipelines using standard exit codes. Returns 0 for compliant SBOMs and 1 for violations.

### GitHub Actions

```yaml
name: SBOM Compliance CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - run: make install
      - run: make run  # Test non-compliant SBOM
        continue-on-error: true
      - run: make run2  # Test compliant SBOM
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Setup') {
            steps {
                sh 'python3 -m venv venv'
                sh '. venv/bin/activate && pip install -r requirements.txt'
            }
        }
        stage('SBOM Compliance Check') {
            steps {
                sh '. venv/bin/activate && python src/main.py --sbom artifacts/sbom.json --policy config/policy.yml'
            }
        }
    }
}
```

### GitLab CI

```yaml
sbom-compliance:
  stage: test
  image: python:3.10
  script:
    - pip install -r requirements.txt
    - python src/main.py --sbom $CI_PROJECT_DIR/sbom.json --policy $CI_PROJECT_DIR/policy.yml
```

## Project Structure

```
spdx-compliance-checker/
├── src/
│   ├── __init__.py          # Package initialization
│   ├── main.py              # CLI entry point
│   ├── checker.py           # Core compliance logic
│   └── models.py            # Data models
├── tests/
│   ├── __init__.py
│   ├── test_checker.py      # Unit tests
│   └── test_integration.py  # Integration tests
├── examples/
│   ├── policy.yml           # Policy configuration
│   ├── sbom.json           # Non-compliant SBOM for testing
│   └── clear_sbom.json     # Compliant SBOM for testing
├── .github/
│   └── workflows/
│       └── ci.yml          # GitHub Actions workflow
├── setup.py                # Package configuration
├── requirements.txt        # Python dependencies
├── Makefile               # Build automation
├── README.md
└── .gitignore
```

## Architecture

### Design Principles

1. **Performance**: O(n) complexity for all checks using set-based lookups
2. **Modularity**: Separate handlers for each policy type
3. **Extensibility**: Easy to add new policy checks
4. **Clear Separation**: Distinct layers for CLI, checking logic, and data models

### Core Components

- **main.py**: Command-line interface and argument parsing
- **checker.py**: Compliance checking engine with policy handlers
- **models.py**: Data structures (CheckResult, PolicyConfig)

### Policy Checks Implemented

1. **disallowed-licenses**: Identifies packages using prohibited licenses
2. **no-assertion-values**: Detects NOASSERTION in critical fields
3. **required-copyright**: Ensures all packages have copyright text
4. **approved-suppliers**: Validates package suppliers against whitelist

## Development

```bash
pip install pytest black flake8

make format

make lint

make clean
```

## Performance

The tool can process SBOMs with 1000+ packages in under 1 second. All policy checks run in O(n) time complexity where n is the number of packages.

## Future Improvements

### Performance Enhancements
- Parallel processing for very large SBOMs (10k+ packages)
- Streaming parser for memory efficiency
- Result caching for repeated checks

### Additional Features
- Support for SPDX 3.0
- Multiple SBOM formats (CycloneDX, SWID)
- REST API endpoint
- Database backend for compliance tracking
- Custom policy plugins

### Enterprise Features
- Policy versioning and audit trails
- Web dashboard for metrics
- Integration with vulnerability databases
- Automated remediation suggestions
- LDAP/SSO authentication

## Requirements

- Python 3.8+
- spdx-tools 0.8.2
- PyYAML 6.0.1

## License

MIT License - see LICENSE file for details.

## Author

Sayeem Raza