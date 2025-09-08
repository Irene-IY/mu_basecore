#!/usr/bin/env python3
"""
Crypto Test Analysis Script

This script analyzes EDK2 crypto unit test results to provide comprehensive
reporting of test coverage, successes, and failures.

The script automatically detects unhandled tests (like new MLDSA algorithms)
and provides suggestions for categorizing them.

Usage:
    python analyze_crypto_tests.py [options]

Examples:
    # Use default paths
    python analyze_crypto_tests.py

    # Custom XML file
    python analyze_crypto_tests.py --xml-file d:\\custom_test_results.xml

    # Custom output directory
    python analyze_crypto_tests.py --output-dir ./reports

    # Verbose output
    python analyze_crypto_tests.py --xml-file test.xml --verbose

Exit Codes:
    0 - Success (all tests passed, no unhandled tests)
    1 - Error (file not found, parsing error, etc.)
    2 - Warning (some tests failed)
    3 - Warning (unhandled tests detected)
"""

import xml.etree.ElementTree as ET
import json
import re
import argparse
import sys
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from datetime import datetime


@dataclass
class TestResult:
    """Represents a single test case result"""

    name: str
    classname: str
    status: str  # "passed", "failed", "skipped"
    time: str
    failure_message: str = ""
    system_output: str = ""
    category: str = ""


@dataclass
class TestSuite:
    """Represents a test suite with multiple test cases"""

    name: str
    package: str
    total_tests: int
    passed: int
    failed: int
    skipped: int
    test_cases: List[TestResult]


@dataclass
class AnalysisReport:
    """Complete analysis report"""

    timestamp: str
    version_info: Dict[str, str]
    summary: Dict[str, Any]
    test_suites: List[TestSuite]
    coverage_analysis: Dict[str, Any]
    recommendations: List[str]
    unhandled_tests: List[Dict[str, str]]


class CryptoTestAnalyzer:
    def __init__(self):
        self.test_results = []
        self.crypto_categories = {
            "HASH": ["Sha1", "Sha256", "Sha384", "Sha512", "Sm3", "ParallelHash256"],
            "HMAC": ["HmacSha256", "HmacSha384"],
            "RSA": ["Rsa"],
            "AES": ["Aes"],
            "DH": ["Dh"],
            "PKCS": ["Pkcs1", "Pkcs5", "Pkcs7"],
            "EKU": ["VerifyEKUs"],
            "X509": ["X509"],
            "HKDF": ["Hkdf"],
            "EC": ["Ec"],
            "TLS": ["Tls"],
            "OAEP": ["RsaOaep"],
            "RANDOM": ["Random"],
            "AEAD": ["AeadAes"],
            "BIGNUM": ["Bn"],
            "AUTHENTICODE": ["Authenticode"],
            "TIMESTAMP": ["ImageTimestamp"],
        }

    def parse_junit_xml(self, xml_file_path: str):
        """Parse JUnit XML test results"""
        tree = ET.parse(xml_file_path)
        root = tree.getroot()

        for testsuite in root.findall("testsuite"):
            suite_name = testsuite.get("name", "")
            package = testsuite.get("package", "")
            total_tests = int(testsuite.get("tests", "0"))
            failures = int(testsuite.get("failures", "0"))
            skipped = int(testsuite.get("skipped", "0"))
            passed = total_tests - failures - skipped

            test_cases = []
            for testcase in testsuite.findall("testcase"):
                test_name = testcase.get("name", "")
                classname = testcase.get("classname", "")
                time = testcase.get("time", "0")
                failure_message = ""

                # Determine status
                if testcase.find("skipped") is not None:
                    status = "skipped"
                elif testcase.find("failure") is not None:
                    status = "failed"
                    failure_elem = testcase.find("failure")
                    if failure_elem is not None:
                        # Capture both the failure message and type
                        failure_type = failure_elem.get("type", "Unknown")
                        failure_text = failure_elem.text if failure_elem.text else ""
                        failure_message = f"Type: {failure_type}\n{failure_text}"
                    else:
                        failure_message = "No failure details available"
                elif testcase.find("error") is not None:
                    status = "failed"
                    error_elem = testcase.find("error")
                    if error_elem is not None:
                        error_type = error_elem.get("type", "Unknown")
                        error_text = error_elem.text if error_elem.text else ""
                        failure_message = f"Error Type: {error_type}\n{error_text}"
                    else:
                        failure_message = "No error details available"
                else:
                    status = "passed"

                # Extract system output (contains detailed error messages)
                system_out_elem = testcase.find("system-out")
                system_output = ""
                if system_out_elem is not None and system_out_elem.text:
                    system_output = system_out_elem.text.strip()

                # Categorize test
                category = self.categorize_test(test_name, classname)

                test_cases.append(
                    TestResult(
                        name=test_name,
                        classname=classname,
                        status=status,
                        time=time,
                        failure_message=failure_message,
                        system_output=system_output,
                        category=category,
                    )
                )

            self.test_results.append(
                TestSuite(
                    name=suite_name,
                    package=package,
                    total_tests=total_tests,
                    passed=passed,
                    failed=failures,
                    skipped=skipped,
                    test_cases=test_cases,
                )
            )

    def categorize_test(self, test_name: str, classname: str) -> str:
        """Categorize a test based on its name and classname"""
        test_text = f"{test_name} {classname}".lower()

        for category, keywords in self.crypto_categories.items():
            if any(keyword.lower() in test_text for keyword in keywords):
                return category

        # Return 'UNHANDLED' for better tracking of uncategorized tests
        return "UNHANDLED"

    def get_version_info(self) -> Dict[str, str]:
        """Extract version information from various sources"""
        version_info = {}

        # Try to get git commit information
        try:
            import subprocess

            result = subprocess.run(
                ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd="."
            )
            if result.returncode == 0:
                version_info["git_commit"] = result.stdout.strip()[:12]  # Short hash

            result = subprocess.run(
                ["git", "rev-parse", "--abbrev-ref", "HEAD"],
                capture_output=True,
                text=True,
                cwd=".",
            )
            if result.returncode == 0:
                version_info["git_branch"] = result.stdout.strip()

            result = subprocess.run(
                ["git", "log", "-1", "--format=%cd", "--date=iso"],
                capture_output=True,
                text=True,
                cwd=".",
            )
            if result.returncode == 0:
                version_info["last_commit_date"] = result.stdout.strip()
        except Exception:
            pass

        # Try to get CryptoPkg version from DEC file
        try:
            dec_file_path = "MU_BASECORE/CryptoPkg/CryptoPkg.dec"
            if Path(dec_file_path).exists():
                with open(dec_file_path, "r") as f:
                    content = f.read()
                    # Look for PACKAGE_VERSION
                    version_match = re.search(
                        r"PACKAGE_VERSION\s*=\s*([^\r\n]+)", content
                    )
                    if version_match:
                        version_info["cryptopkg_version"] = version_match.group(
                            1
                        ).strip()

                    # Look for PACKAGE_NAME
                    name_match = re.search(r"PACKAGE_NAME\s*=\s*([^\r\n]+)", content)
                    if name_match:
                        version_info["cryptopkg_name"] = name_match.group(1).strip()
        except Exception:
            pass

        # Try to get OpenSSL version information
        try:
            openssl_path = "MU_BASECORE/CryptoPkg/Library/OpensslLib/openssl"
            if Path(openssl_path).exists():
                # Look for VERSION.dat or similar version files
                for version_file in [
                    "VERSION.dat",
                    "VERSION",
                    "include/openssl/opensslv.h",
                ]:
                    version_file_path = Path(openssl_path) / version_file
                    if version_file_path.exists():
                        with open(version_file_path, "r") as f:
                            content = f.read()
                            if "opensslv.h" in version_file:
                                # Parse OpenSSL version from header file
                                version_match = re.search(
                                    r'#\s*define\s+OPENSSL_VERSION_TEXT\s+"([^"]+)"',
                                    content,
                                )
                                if version_match:
                                    version_info["openssl_version"] = (
                                        version_match.group(1).strip()
                                    )
                            else:
                                # Simple version file
                                version_info["openssl_version"] = content.strip()[
                                    :50
                                ]  # Limit length
                        break
        except Exception:
            pass

        # Add analysis script version
        version_info["analyzer_version"] = "1.1.0"

        # Add platform information
        try:
            import platform

            version_info["python_version"] = platform.python_version()
            version_info["platform"] = platform.platform()
        except Exception:
            pass

        return version_info

    def analyze_coverage(self) -> Dict[str, Any]:
        """Analyze test coverage by categories"""
        coverage = {
            "by_category": {},
            "total_categories": 0,
            "categories_with_tests": 0,
        }

        # Group tests by category
        tests_by_category = {}
        for suite in self.test_results:
            for test in suite.test_cases:
                if test.category not in tests_by_category:
                    tests_by_category[test.category] = []
                tests_by_category[test.category].append(test)

        # Analyze each category
        for category, category_tests in tests_by_category.items():
            passed_tests = [t for t in category_tests if t.status == "passed"]
            failed_tests = [t for t in category_tests if t.status == "failed"]
            skipped_tests = [t for t in category_tests if t.status == "skipped"]

            coverage["by_category"][category] = {
                "total_tests": len(category_tests),
                "passed_tests": len(passed_tests),
                "failed_tests": len(failed_tests),
                "skipped_tests": len(skipped_tests),
                "pass_rate": len(passed_tests) / len(category_tests)
                if category_tests
                else 0,
            }

        coverage["total_categories"] = len(tests_by_category)
        coverage["categories_with_tests"] = len(
            [c for c in tests_by_category.values() if c]
        )

        return coverage

    def analyze_unhandled_tests(self) -> List[Dict[str, str]]:
        """Identify and analyze tests that couldn't be categorized"""
        unhandled_tests = []

        for suite in self.test_results:
            for test in suite.test_cases:
                if test.category == "UNHANDLED":
                    # Extract potential keywords from test name for categorization suggestions
                    test_name_lower = test.name.lower()
                    classname_lower = test.classname.lower()

                    # Look for potential crypto algorithm names or patterns
                    potential_keywords = []
                    common_crypto_terms = [
                        "mldsa",
                        "dilithium",
                        "falcon",
                        "sphincs",
                        "lattice",  # Post-quantum
                        "aes",
                        "des",
                        "chacha",
                        "salsa",  # Symmetric encryption
                        "ecdsa",
                        "ecdh",
                        "ed25519",
                        "x25519",  # Elliptic curve
                        "blake",
                        "keccak",
                        "whirlpool",  # Alternative hashes
                        "poly1305",
                        "gcm",
                        "ccm",
                        "ocb",  # AEAD modes
                        "argon2",
                        "scrypt",
                        "pbkdf",  # Key derivation
                        "curve25519",
                        "curve448",
                        "secp256r1",  # Specific curves
                        "kyber",
                        "ntru",
                        "frodo",  # Post-quantum KEM
                    ]

                    for term in common_crypto_terms:
                        if term in test_name_lower or term in classname_lower:
                            potential_keywords.append(term.upper())

                    # Extract words that look like crypto algorithms (capitalized or mixed case)
                    import re

                    crypto_pattern = r"\b[A-Z][a-z]*[0-9]*\b|\b[a-z]+[0-9]+\b"
                    name_matches = re.findall(crypto_pattern, test.name)
                    class_matches = re.findall(crypto_pattern, test.classname)

                    potential_keywords.extend(
                        [m.upper() for m in name_matches + class_matches]
                    )
                    potential_keywords = list(
                        set(potential_keywords)
                    )  # Remove duplicates

                    unhandled_tests.append(
                        {
                            "name": test.name,
                            "classname": test.classname,
                            "suite": suite.name,
                            "status": test.status,
                            "potential_keywords": potential_keywords,
                            "suggested_category": self._suggest_category(
                                potential_keywords
                            ),
                            "full_text": f"{test.name} {test.classname}",
                        }
                    )

        return unhandled_tests

    def _suggest_category(self, potential_keywords: List[str]) -> str:
        """Suggest a category based on potential keywords"""
        if not potential_keywords:
            return "NEW_CATEGORY"

        # Map common terms to suggested categories
        category_mapping = {
            "MLDSA": "POSTQUANTUM_SIGNATURE",
            "DILITHIUM": "POSTQUANTUM_SIGNATURE",
            "FALCON": "POSTQUANTUM_SIGNATURE",
            "SPHINCS": "POSTQUANTUM_SIGNATURE",
            "KYBER": "POSTQUANTUM_KEM",
            "NTRU": "POSTQUANTUM_KEM",
            "FRODO": "POSTQUANTUM_KEM",
            "BLAKE": "HASH",
            "KECCAK": "HASH",
            "WHIRLPOOL": "HASH",
            "CHACHA": "SYMMETRIC",
            "SALSA": "SYMMETRIC",
            "POLY1305": "AEAD",
            "ARGON2": "KDF",
            "SCRYPT": "KDF",
            "PBKDF": "KDF",
            "ED25519": "EC",
            "X25519": "EC",
            "CURVE25519": "EC",
            "CURVE448": "EC",
        }

        for keyword in potential_keywords:
            if keyword in category_mapping:
                return category_mapping[keyword]

        # If no specific mapping, suggest based on common patterns
        return f"NEW_CATEGORY_{potential_keywords[0]}"

    def generate_recommendations(self, coverage: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on analysis"""
        recommendations = []

        # Check for failed tests and suggest fixes
        failed_tests = []
        for suite in self.test_results:
            for test in suite.test_cases:
                if test.status == "failed":
                    failed_tests.append(test)

        if failed_tests:
            recommendations.append(
                f"Address {len(failed_tests)} failed tests. Review the 'Failed Tests Summary' section for detailed error information."
            )

            # Analyze common failure patterns
            failure_patterns = {}
            for test in failed_tests:
                # Look at both system output and failure message for patterns
                error_text = (
                    test.system_output if test.system_output else test.failure_message
                )
                if error_text:
                    error_lower = error_text.lower()
                    # Look for common error patterns
                    if "unsupported" in error_lower:
                        pattern = "Unsupported Operation"
                    elif "not implemented" in error_lower:
                        pattern = "Not Implemented"
                    elif "assertion" in error_lower or "assert fail" in error_lower:
                        pattern = "Assertion Failure"
                    elif "null" in error_lower:
                        pattern = "Null Pointer"
                    elif "memory" in error_lower:
                        pattern = "Memory Error"
                    elif "invalid" in error_lower:
                        pattern = "Invalid Parameter"
                    else:
                        pattern = "Other"

                    if pattern not in failure_patterns:
                        failure_patterns[pattern] = 0
                    failure_patterns[pattern] += 1

            if failure_patterns:
                most_common = max(failure_patterns.items(), key=lambda x: x[1])
                recommendations.append(
                    f"Most common failure type: {most_common[0]} ({most_common[1]} occurrences). "
                    f"Consider reviewing crypto library implementations for this pattern."
                )

        # Check for high skip rates
        total_tests = sum(s.total_tests for s in self.test_results)
        total_skipped = sum(s.skipped for s in self.test_results)
        skip_rate = total_skipped / total_tests if total_tests > 0 else 0

        if skip_rate > 0.3:
            recommendations.append(
                f"High test skip rate ({skip_rate:.1%}). Review test implementations to reduce skipped tests."
            )

        return recommendations

    def generate_markdown_report(self, report: AnalysisReport) -> str:
        """Generate markdown report"""
        md = f"""# Crypto Test Analysis Report

**Generated:** {report.timestamp}

## Version Information

"""

        # Add version information
        for key, value in report.version_info.items():
            friendly_name = key.replace("_", " ").title()
            md += f"- **{friendly_name}:** {value}\n"

        md += f"""
## Executive Summary

- **Total Test Suites:** {report.summary["total_suites"]}
- **Total Tests:** {report.summary["total_tests"]}
- **Passed:** {report.summary["total_passed"]} ({report.summary["pass_rate"]:.1%})
- **Failed:** {report.summary["total_failed"]} ({report.summary["fail_rate"]:.1%})
- **Skipped:** {report.summary["total_skipped"]} ({report.summary["skip_rate"]:.1%})

## Test Results by Suite

| Suite | Total | Passed | Failed | Skipped | Pass Rate |
|-------|-------|--------|--------|---------|-----------|
"""

        for suite in report.test_suites:
            pass_rate = suite.passed / suite.total_tests if suite.total_tests > 0 else 0
            md += f"| {suite.name} | {suite.total_tests} | {suite.passed} | {suite.failed} | {suite.skipped} | {pass_rate:.1%} |\n"

        # Add failed tests summary section
        failed_tests = []
        for suite in report.test_suites:
            for test in suite.test_cases:
                if test.status == "failed":
                    failed_tests.append((suite.name, test))

        if failed_tests:
            md += "\n## Failed Tests Summary\n\n"
            md += f"**Total Failed Tests:** {len(failed_tests)}\n\n"

            for suite_name, test in failed_tests:
                md += f"### ❌ {test.name} ({test.category})\n"
                md += f"**Test Suite:** {suite_name}\n\n"

                # Show both failure message and system output
                if test.system_output:
                    md += "**Detailed Error Output:**\n"
                    md += "```\n"
                    md += test.system_output
                    md += "\n```\n\n"
                elif test.failure_message:
                    md += "**Error Details:**\n"
                    md += "```\n"
                    md += test.failure_message.strip()
                    md += "\n```\n\n"
                else:
                    md += "No error details available.\n\n"

        md += "\n## Coverage Analysis by Category\n\n"

        for category, data in report.coverage_analysis["by_category"].items():
            if data["total_tests"] > 0:
                md += f"### {category}\n\n"
                md += f"- **Total Tests:** {data['total_tests']}\n"
                md += f"- **Passed:** {data['passed_tests']}\n"
                md += f"- **Failed:** {data['failed_tests']}\n"
                md += f"- **Skipped:** {data['skipped_tests']}\n\n"

        md += "## Detailed Test Results\n\n"

        for suite in report.test_suites:
            md += f"### {suite.name}\n\n"
            for test in suite.test_cases:
                status_emoji = {"passed": "✅", "failed": "❌", "skipped": "⏭️"}[
                    test.status
                ]
                md += f"- {status_emoji} **{test.name}** ({test.category})\n"
                if test.status == "failed":
                    # Show detailed system output for failed tests
                    if test.system_output:
                        md += "  - **Detailed Error:**\n"
                        md += "    ```\n"
                        # Split system output into lines and indent properly
                        for line in test.system_output.strip().split("\n"):
                            md += f"    {line}\n"
                        md += "    ```\n"
                    elif test.failure_message:
                        md += "  - **Error Details:**\n"
                        md += "    ```\n"
                        for line in test.failure_message.strip().split("\n"):
                            md += f"    {line}\n"
                        md += "    ```\n"
            md += "\n"

        if report.unhandled_tests:
            md += "## ⚠️ Unhandled Tests\n\n"
            md += f"Found **{len(report.unhandled_tests)}** test(s) that couldn't be automatically categorized:\n\n"

            for test in report.unhandled_tests:
                status_emoji = (
                    "✅"
                    if test["status"] == "passed"
                    else "❌"
                    if test["status"] == "failed"
                    else "⏭️"
                )
                md += f"### {status_emoji} {test['name']}\n"
                md += f"- **Test Suite:** {test['suite']}\n"
                md += f"- **Class:** {test['classname']}\n"
                md += f"- **Status:** {test['status']}\n"
                md += f"- **Suggested Category:** `{test['suggested_category']}`\n"

                if test["potential_keywords"]:
                    md += f"- **Potential Keywords:** {', '.join(test['potential_keywords'])}\n"

                md += f"- **Full Test Text:** `{test['full_text']}`\n\n"

                # Suggest how to handle this test
                md += "**Suggested Action:**\n"
                if test["suggested_category"].startswith("NEW_CATEGORY"):
                    md += f"Consider adding a new category `{test['suggested_category']}` to `crypto_categories` with appropriate keywords.\n\n"
                else:
                    md += f"Add keywords to existing `{test['suggested_category']}` category or create a new category.\n\n"

                # Provide example code for adding to categories
                if test["potential_keywords"]:
                    example_keywords = "', '".join(
                        test["potential_keywords"][:3]
                    )  # Show up to 3 keywords
                    md += "**Example Configuration:**\n"
                    md += "```python\n"
                    md += f"'{test['suggested_category']}': ['{example_keywords}'],\n"
                    md += "```\n\n"

            md += "### Adding New Categories\n\n"
            md += "To handle these tests, update the `crypto_categories` dictionary in the analyzer:\n\n"
            md += "```python\n"
            md += "self.crypto_categories = {\n"
            md += "    # ... existing categories ...\n"
            md += "    'POSTQUANTUM_SIGNATURE': ['Mldsa', 'Dilithium', 'Falcon', 'Sphincs'],\n"
            md += "    'POSTQUANTUM_KEM': ['Kyber', 'Ntru', 'Frodo'],\n"
            md += "    # Add your new categories here\n"
            md += "}\n"
            md += "```\n\n"

        if report.recommendations:
            md += "## Recommendations\n\n"
            for i, rec in enumerate(report.recommendations, 1):
                md += f"{i}. {rec}\n\n"

        return md

    def generate_report(self, junit_xml_path: str) -> AnalysisReport:
        """Generate complete analysis report"""
        # Parse input files
        self.parse_junit_xml(junit_xml_path)

        # Get version information
        version_info = self.get_version_info()

        # Calculate summary statistics
        total_tests = sum(s.total_tests for s in self.test_results)
        total_passed = sum(s.passed for s in self.test_results)
        total_failed = sum(s.failed for s in self.test_results)
        total_skipped = sum(s.skipped for s in self.test_results)

        summary = {
            "total_suites": len(self.test_results),
            "total_tests": total_tests,
            "total_passed": total_passed,
            "total_failed": total_failed,
            "total_skipped": total_skipped,
            "pass_rate": total_passed / total_tests if total_tests > 0 else 0,
            "fail_rate": total_failed / total_tests if total_tests > 0 else 0,
            "skip_rate": total_skipped / total_tests if total_tests > 0 else 0,
        }

        # Perform coverage analysis
        coverage_analysis = self.analyze_coverage()

        # Analyze unhandled tests
        unhandled_tests = self.analyze_unhandled_tests()

        # Generate recommendations
        recommendations = self.generate_recommendations(coverage_analysis)

        # Add recommendations for unhandled tests
        if unhandled_tests:
            recommendations.insert(
                0,
                f"Found {len(unhandled_tests)} unhandled test(s) that couldn't be categorized - review and add to crypto_categories",
            )

        return AnalysisReport(
            timestamp=datetime.now().isoformat(),
            version_info=version_info,
            summary=summary,
            test_suites=self.test_results,
            coverage_analysis=coverage_analysis,
            recommendations=recommendations,
            unhandled_tests=unhandled_tests,
        )


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Analyze EDK2 crypto unit test results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze_crypto_tests.py
  python analyze_crypto_tests.py --xml-file d:\\custom_test_results.xml
  python analyze_crypto_tests.py --xml-file test.xml --output-dir ./reports
        """,
    )

    parser.add_argument(
        "--xml-file",
        default=r"d:\BaseCryptLibUnitTestApp_JUNIT_RESULT.XML",
        help="Path to JUnit XML test results file (default: d:\\BaseCryptLibUnitTestApp_JUNIT_RESULT.XML)",
    )

    parser.add_argument(
        "--output-dir",
        default=r"c:\git\flickdm\MTP_DEMO_SHARED_CRYPTO",
        help="Output directory for reports (default: current directory)",
    )

    parser.add_argument(
        "--markdown-output",
        help="Custom path for markdown report (overrides --output-dir)",
    )

    parser.add_argument(
        "--json-output", help="Custom path for JSON report (overrides --output-dir)"
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose output"
    )

    return parser.parse_args()


def validate_input_files(xml_file: str) -> None:
    """Validate that input files exist and are readable"""
    xml_path = Path(xml_file)

    if not xml_path.exists():
        print(f"❌ ERROR: XML file not found: {xml_file}")
        print(
            "   Please ensure the crypto unit tests have been run and the XML file exists."
        )
        sys.exit(1)

    if not xml_path.is_file():
        print(f"❌ ERROR: XML path is not a file: {xml_file}")
        sys.exit(1)

    print("✅ Input files validated successfully")


def print_configuration_info(args) -> None:
    """Print information about the current configuration and files being analyzed"""
    print("🔍 Crypto Test Analysis Configuration")
    print("=" * 50)

    # Input files
    print(f"📁 XML Test Results: {args.xml_file}")
    xml_path = Path(args.xml_file)
    if xml_path.exists():
        xml_size = xml_path.stat().st_size
        xml_modified = xml_path.stat().st_mtime
        xml_date = datetime.fromtimestamp(xml_modified).strftime("%Y-%m-%d %H:%M:%S")
        print(f"   Size: {xml_size:,} bytes | Modified: {xml_date}")

    # Output files
    print(f"📁 Output Directory: {args.output_dir}")

    if args.markdown_output:
        print(f"📄 Markdown Report: {args.markdown_output}")
    else:
        markdown_path = Path(args.output_dir) / "crypto_test_analysis.md"
        print(f"📄 Markdown Report: {markdown_path}")

    if args.json_output:
        print(f"📄 JSON Report: {args.json_output}")
    else:
        json_path = Path(args.output_dir) / "crypto_test_analysis.json"
        print(f"📄 JSON Report: {json_path}")

    print("=" * 50)
    print()


def main():
    """Main execution function"""
    # Parse command line arguments
    args = parse_arguments()

    # Print configuration information
    print_configuration_info(args)

    # Validate input files exist
    validate_input_files(args.xml_file)

    # Determine output file paths
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.markdown_output:
        markdown_output = args.markdown_output
    else:
        markdown_output = output_dir / "crypto_test_analysis.md"

    if args.json_output:
        json_output = args.json_output
    else:
        json_output = output_dir / "crypto_test_analysis.json"

    if args.verbose:
        print("🔄 Starting analysis...")
        print(f"   Parsing XML test results from: {args.xml_file}")

    # Create analyzer and generate report
    analyzer = CryptoTestAnalyzer()

    try:
        report = analyzer.generate_report(args.xml_file)
    except Exception as e:
        print(f"❌ ERROR: Failed to generate analysis report: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        sys.exit(1)

    if args.verbose:
        print(
            f"   Generated analysis report with {len(report.test_suites)} test suites"
        )
        if report.unhandled_tests:
            print(f"   ⚠️  Detected {len(report.unhandled_tests)} unhandled test(s)")

    # Generate markdown report
    if args.verbose:
        print(f"   Writing markdown report to: {markdown_output}")

    try:
        markdown_content = analyzer.generate_markdown_report(report)
        with open(markdown_output, "w", encoding="utf-8") as f:
            f.write(markdown_content)
    except Exception as e:
        print(f"❌ ERROR: Failed to write markdown report: {e}")
        sys.exit(1)

    # Generate JSON report
    if args.verbose:
        print(f"   Writing JSON report to: {json_output}")

    try:
        json_content = json.dumps(asdict(report), indent=2, default=str)
        with open(json_output, "w", encoding="utf-8") as f:
            f.write(json_content)
    except Exception as e:
        print(f"❌ ERROR: Failed to write JSON report: {e}")
        sys.exit(1)

    # Print completion summary
    print("✅ Analysis complete!")
    print(f"📄 Markdown report: {markdown_output}")
    print(f"📄 JSON report: {json_output}")

    print("\n📊 Summary:")
    print(f"- Total Tests: {report.summary['total_tests']}")
    print(
        f"- Passed: {report.summary['total_passed']} ({report.summary['pass_rate']:.1%})"
    )
    print(
        f"- Failed: {report.summary['total_failed']} ({report.summary['fail_rate']:.1%})"
    )
    print(
        f"- Skipped: {report.summary['total_skipped']} ({report.summary['skip_rate']:.1%})"
    )

    if report.unhandled_tests:
        print(f"- ⚠️  Unhandled Tests: {len(report.unhandled_tests)}")

    if report.recommendations:
        print("\n🔧 Top Recommendations:")
        for i, rec in enumerate(report.recommendations[:3], 1):
            # Truncate long recommendations for summary
            rec_summary = rec.split(".")[0] if "." in rec else rec
            if len(rec_summary) > 80:
                rec_summary = rec_summary[:77] + "..."
            print(f"{i}. {rec_summary}")

    print(
        "\n📖 View the full markdown report for detailed analysis and recommendations."
    )

    # Exit with appropriate code
    if report.summary["total_failed"] > 0:
        print(f"\n⚠️  Warning: {report.summary['total_failed']} test(s) failed")
        sys.exit(2)  # Exit code 2 for test failures
    elif report.unhandled_tests:
        print(f"\n⚠️  Warning: {len(report.unhandled_tests)} unhandled test(s) detected")
        sys.exit(3)  # Exit code 3 for unhandled tests
    else:
        sys.exit(0)  # Success


if __name__ == "__main__":
    main()
