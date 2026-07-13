"""Regression tests for govulncheck reachability classification."""

from __future__ import annotations

import json
import unittest

from check_govuln_findings import classify_findings


def _stream(*items: dict[str, object]) -> str:
    return "\n".join(json.dumps(item) for item in items)


class ClassifyFindingsTests(unittest.TestCase):
    def test_module_only_trace_is_not_a_called_vulnerability(self) -> None:
        dependencies, standard_library, uncalled = classify_findings(
            _stream(
                {"config": {"protocol_version": "v1.0.0"}},
                {
                    "finding": {
                        "osv": "GO-2026-5932",
                        "trace": [
                            {"module": "golang.org/x/crypto", "version": "v0.52.0"}
                        ],
                    }
                },
            )
        )
        self.assertEqual(dependencies, set())
        self.assertEqual(standard_library, set())
        self.assertEqual(uncalled, {("GO-2026-5932", "golang.org/x/crypto")})

    def test_function_frame_is_a_called_dependency(self) -> None:
        dependencies, _, uncalled = classify_findings(
            _stream(
                {
                    "finding": {
                        "osv": "GO-2099-0001",
                        "trace": [
                            {
                                "module": "example.test/dependency",
                                "package": "example.test/dependency/unsafe",
                                "function": "Vulnerable",
                            }
                        ],
                    }
                }
            )
        )
        self.assertEqual(dependencies, {("GO-2099-0001", "example.test/dependency")})
        self.assertEqual(uncalled, set())

    def test_called_stdlib_finding_is_reported_separately(self) -> None:
        dependencies, standard_library, _ = classify_findings(
            _stream(
                {
                    "finding": {
                        "osv": "GO-2099-0002",
                        "trace": [
                            {"module": "stdlib", "package": "net/http", "function": "Serve"}
                        ],
                    }
                }
            )
        )
        self.assertEqual(dependencies, set())
        self.assertEqual(standard_library, {"GO-2099-0002"})


if __name__ == "__main__":
    unittest.main()
