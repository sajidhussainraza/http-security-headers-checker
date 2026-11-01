#!/usr/bin/env python3
"""HTTP Security Headers Checker.

Fetches a URL's response headers and grades the site on the security
headers that matter most: HSTS, Content-Security-Policy, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.

It reads headers only. It never submits forms, never follows a login, and
never sends credentials, so it is safe to point at a site you are auditing
with permission.

Usage:
    python3 http_headers_checker.py https://example.com
    python3 http_headers_checker.py https://example.com --json
"""

import argparse
import json
import sys
import urllib.error
import urllib.request

TIMEOUT = 10
USER_AGENT = "http-headers-checker/1.0 (security audit; headers only)"


def normalize_headers(raw):
    """Lower-case header names so lookups are case-insensitive."""
    return {str(k).lower(): str(v) for k, v in raw.items()}


def _hsts_max_age(value):
    """Return the max-age seconds from an HSTS value, or None."""
    for part in value.split(";"):
        part = part.strip()
        if part.lower().startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip())
            except ValueError:
                return None
    return None


def check_hsts(headers, url):
    value = headers.get("strict-transport-security")
    if value is None:
        return ("Strict-Transport-Security", "FAIL", 0, 20,
                "Missing",
                "Add: Strict-Transport-Security: "
                "max-age=31536000; includeSubDomains")
    max_age = _hsts_max_age(value)
    if max_age is None:
        return ("Strict-Transport-Security", "WARN", 5, 20,
                "Present but no usable max-age: %s" % value,
                "Set max-age to at least 31536000 (one year).")
    if max_age < 31536000:
        return ("Strict-Transport-Security", "WARN", 10, 20,
                "max-age=%d is shorter than one year" % max_age,
                "Raise max-age to 31536000 or more.")
    detail = "max-age=%d" % max_age
    if "includesubdomains" in value.lower().replace(" ", ""):
        detail += "; includeSubDomains"
    return ("Strict-Transport-Security", "PASS", 20, 20, detail,
            "Good. Keep it on every HTTPS response.")


def check_csp(headers, url):
    value = headers.get("content-security-policy")
    if value is None:
        return ("Content-Security-Policy", "FAIL", 0, 20,
                "Missing",
                "Add a Content-Security-Policy that allow-lists script, "
                "style, and connect sources instead of '*'.")
    if "unsafe-inline" in value or "unsafe-eval" in value:
        return ("Content-Security-Policy", "WARN", 10, 20,
                "Present but weak: %s" % value,
                "Remove 'unsafe-inline' / 'unsafe-eval' where possible; "
                "use nonces or hashes for inline scripts.")
    return ("Content-Security-Policy", "PASS", 20, 20,
            "Present", "Good. Review it when new scripts are added.")


def check_frame_options(headers, url):
    value = headers.get("x-frame-options")
    if value is None:
        # A frame-ancestors directive in CSP covers the same risk.
        csp = headers.get("content-security-policy", "")
        if "frame-ancestors" in csp:
            return ("X-Frame-Options", "PASS", 20, 20,
                    "Missing, but CSP frame-ancestors covers framing",
                    "Good. Either control is enough; keep one.")
        return ("X-Frame-Options", "FAIL", 0, 20,
                "Missing",
                "Add: X-Frame-Options: DENY (or SAMEORIGIN), or a CSP "
                "frame-ancestors directive.")
    if value.strip().upper() in ("DENY", "SAMEORIGIN"):
        return ("X-Frame-Options", "PASS", 20, 20,
                value.strip(), "Good.")
    return ("X-Frame-Options", "WARN", 5, 20,
            "Weak value: %s" % value,
            "Use DENY, or SAMEORIGIN if the site must frame itself.")


def check_content_type_options(headers, url):
    value = headers.get("x-content-type-options")
    if value is None:
        return ("X-Content-Type-Options", "FAIL", 0, 15,
                "Missing",
                "Add: X-Content-Type-Options: nosniff")
    if value.strip().lower() == "nosniff":
        return ("X-Content-Type-Options", "PASS", 15, 15,
                "nosniff", "Good.")
    return ("X-Content-Type-Options", "WARN", 5, 15,
            "Unexpected value: %s" % value,
            "Set it to exactly: nosniff")


def check_referrer_policy(headers, url):
    value = headers.get("referrer-policy")
    if value is None:
        return ("Referrer-Policy", "FAIL", 0, 15,
                "Missing",
                "Add: Referrer-Policy: strict-origin-when-cross-origin "
                "(or no-referrer for maximum privacy).")
    if value.strip().lower() == "unsafe-url":
        return ("Referrer-Policy", "WARN", 5, 15,
                "unsafe-url",
                "unsafe-url leaks the full page URL to other sites. "
                "Use strict-origin-when-cross-origin or no-referrer.")
    return ("Referrer-Policy", "PASS", 15, 15,
            value.strip(), "Good.")


def check_permissions_policy(headers, url):
    value = headers.get("permissions-policy")
    if value is None:
        return ("Permissions-Policy", "FAIL", 0, 10,
                "Missing",
                "Add: Permissions-Policy: camera=(), microphone=(), "
                "geolocation=() (plus any feature the site truly uses).")
    return ("Permissions-Policy", "PASS", 10, 10,
            "Present", "Good. Keep unused powerful features disabled.")


CHECKS = (
    check_hsts,
    check_csp,
    check_frame_options,
    check_content_type_options,
    check_referrer_policy,
    check_permissions_policy,
)


def info_findings(headers):
    """Non-scored observations worth reporting, not grading."""
    findings = []
    server = headers.get("server", "")
    if server and any(ch.isdigit() for ch in server):
        findings.append(
            "Server header discloses version info: %s "
            "(consider returning a generic value)" % server)
    if "x-powered-by" in headers:
        findings.append(
            "X-Powered-By header discloses stack info: %s "
            "(consider removing it)" % headers["x-powered-by"])
    return findings


def grade(score):
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def evaluate(url, headers):
    """Score one header set. Returns a report dict."""
    results = []
    total = 0
    for check in CHECKS:
        name, status, points, maximum, detail, advice = check(headers, url)
        results.append({
            "header": name,
            "status": status,
            "points": points,
            "max": maximum,
            "detail": detail,
            "advice": advice,
        })
        total += points
    return {
        "url": url,
        "score": total,
        "grade": grade(total),
        "results": results,
        "info": info_findings(headers),
    }


def fetch_headers(url):
    """Fetch response headers only. Returns (final_url, status, headers)."""
    request = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.url, response.status, normalize_headers(
                dict(response.headers.items()))
    except urllib.error.HTTPError as err:
        # Error pages still carry the site's security headers.
        return err.url, err.code, normalize_headers(
            dict(err.headers.items()))
    except ValueError:
        # Some servers reject HEAD; fall back to GET and read headers only.
        request = urllib.request.Request(url, method="GET",
                                         headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return response.url, response.status, normalize_headers(
                dict(response.headers.items()))


def format_report(report, status, final_url):
    lines = []
    lines.append("URL:    %s" % report["url"])
    if final_url != report["url"]:
        lines.append("Final:  %s" % final_url)
    lines.append("Status: %s" % status)
    lines.append("Score:  %d/100 (grade %s)" % (report["score"],
                                                report["grade"]))
    lines.append("Checks:")
    for item in report["results"]:
        lines.append("  - [%s] %s (%d/%d) %s" % (
            item["status"], item["header"], item["points"], item["max"],
            item["detail"]))
        if item["status"] != "PASS":
            lines.append("      Fix: %s" % item["advice"])
    for note in report["info"]:
        lines.append("  - [INFO] %s" % note)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Grade a site's HTTP security headers.")
    parser.add_argument("url", help="URL to check (include https://)")
    parser.add_argument("--json", action="store_true",
                        help="Print the report as JSON")
    args = parser.parse_args(argv)
    url = args.url
    if "://" not in url:
        url = "https://" + url
    try:
        final_url, status, headers = fetch_headers(url)
    except urllib.error.URLError as err:
        print("Error: could not reach %s (%s)" % (url, err.reason),
              file=sys.stderr)
        return 1
    report = evaluate(url, headers)
    if args.json:
        report["http_status"] = status
        report["final_url"] = final_url
        print(json.dumps(report, indent=2))
    else:
        print(format_report(report, status, final_url))
    return 0


if __name__ == "__main__":
    sys.exit(main())
