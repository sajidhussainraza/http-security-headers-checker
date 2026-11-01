#!/usr/bin/env python3
"""Self-check tests for http_headers_checker.py (all offline)."""

import unittest
from unittest.mock import patch

import http_headers_checker as h


GOOD = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(), microphone=(), geolocation=()",
}


class FakeResponse:
    def __init__(self, headers, status=200, url="https://example.com"):
        self.headers = headers
        self.status = status
        self.url = url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestEvaluate(unittest.TestCase):
    def test_all_headers_present_scores_100_grade_a(self):
        report = h.evaluate("https://example.com", GOOD)
        self.assertEqual(report["score"], 100)
        self.assertEqual(report["grade"], "A")

    def test_no_headers_scores_0_grade_f(self):
        report = h.evaluate("https://example.com", {})
        self.assertEqual(report["score"], 0)
        self.assertEqual(report["grade"], "F")

    def test_short_hsts_is_warn_not_pass(self):
        headers = dict(GOOD)
        headers["strict-transport-security"] = "max-age=300"
        report = h.evaluate("https://example.com", headers)
        hsts = [r for r in report["results"]
                if r["header"] == "Strict-Transport-Security"][0]
        self.assertEqual(hsts["status"], "WARN")
        self.assertEqual(hsts["points"], 10)

    def test_hsts_without_max_age_is_warn(self):
        headers = dict(GOOD)
        headers["strict-transport-security"] = "includeSubDomains"
        report = h.evaluate("https://example.com", headers)
        hsts = [r for r in report["results"]
                if r["header"] == "Strict-Transport-Security"][0]
        self.assertEqual(hsts["status"], "WARN")

    def test_missing_csp_fails_that_check_only(self):
        headers = dict(GOOD)
        del headers["content-security-policy"]
        report = h.evaluate("https://example.com", headers)
        self.assertEqual(report["score"], 80)
        csp = [r for r in report["results"]
               if r["header"] == "Content-Security-Policy"][0]
        self.assertEqual(csp["status"], "FAIL")

    def test_unsafe_inline_csp_is_warn(self):
        headers = dict(GOOD)
        headers["content-security-policy"] = (
            "default-src 'self'; script-src 'unsafe-inline'")
        report = h.evaluate("https://example.com", headers)
        csp = [r for r in report["results"]
               if r["header"] == "Content-Security-Policy"][0]
        self.assertEqual(csp["status"], "WARN")
        self.assertEqual(csp["points"], 10)

    def test_frame_ancestors_covers_missing_x_frame_options(self):
        headers = dict(GOOD)
        del headers["x-frame-options"]
        headers["content-security-policy"] = (
            "default-src 'self'; frame-ancestors 'none'")
        report = h.evaluate("https://example.com", headers)
        xfo = [r for r in report["results"]
               if r["header"] == "X-Frame-Options"][0]
        self.assertEqual(xfo["status"], "PASS")

    def test_sameorigin_frame_option_passes(self):
        headers = dict(GOOD)
        headers["x-frame-options"] = "SAMEORIGIN"
        report = h.evaluate("https://example.com", headers)
        xfo = [r for r in report["results"]
               if r["header"] == "X-Frame-Options"][0]
        self.assertEqual(xfo["status"], "PASS")

    def test_wrong_nosniff_value_is_warn(self):
        headers = dict(GOOD)
        headers["x-content-type-options"] = "sniff"
        report = h.evaluate("https://example.com", headers)
        xcto = [r for r in report["results"]
                if r["header"] == "X-Content-Type-Options"][0]
        self.assertEqual(xcto["status"], "WARN")

    def test_header_names_are_case_insensitive(self):
        headers = {k.upper(): v for k, v in GOOD.items()}
        report = h.evaluate("https://example.com",
                            h.normalize_headers(headers))
        self.assertEqual(report["score"], 100)

    def test_version_disclosing_server_header_is_info_only(self):
        headers = dict(GOOD)
        headers["server"] = "nginx/1.24.0"
        report = h.evaluate("https://example.com", headers)
        self.assertEqual(report["score"], 100)
        self.assertTrue(any("Server header" in n for n in report["info"]))

    def test_x_powered_by_is_info_only(self):
        headers = dict(GOOD)
        headers["x-powered-by"] = "PHP/8.1.0"
        report = h.evaluate("https://example.com", headers)
        self.assertEqual(report["score"], 100)
        self.assertTrue(any("X-Powered-By" in n for n in report["info"]))

    def test_unsafe_url_referrer_policy_is_warn(self):
        headers = dict(GOOD)
        headers["referrer-policy"] = "unsafe-url"
        report = h.evaluate("https://example.com", headers)
        rp = [r for r in report["results"]
              if r["header"] == "Referrer-Policy"][0]
        self.assertEqual(rp["status"], "WARN")
        self.assertEqual(rp["points"], 5)

    def test_grade_boundaries(self):
        self.assertEqual(h.grade(90), "A")
        self.assertEqual(h.grade(89), "B")
        self.assertEqual(h.grade(75), "B")
        self.assertEqual(h.grade(74), "C")
        self.assertEqual(h.grade(60), "C")
        self.assertEqual(h.grade(59), "D")
        self.assertEqual(h.grade(40), "D")
        self.assertEqual(h.grade(39), "F")


class TestFetch(unittest.TestCase):
    @patch("http_headers_checker.urllib.request.urlopen")
    def test_fetch_uses_head_and_normalizes(self, mock_open):
        mock_open.return_value = FakeResponse(
            {"Strict-Transport-Security": "max-age=31536000"})
        url, status, headers = h.fetch_headers("https://example.com")
        self.assertEqual(status, 200)
        self.assertEqual(headers["strict-transport-security"],
                         "max-age=31536000")
        request = mock_open.call_args[0][0]
        self.assertEqual(request.get_method(), "HEAD")


if __name__ == "__main__":
    unittest.main(verbosity=2)
