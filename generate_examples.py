#!/usr/bin/env python3
"""Generate examples.txt from fixed header sets (no network needed)."""

import http_headers_checker as h

CASES = [
    ("Well-configured site: every header present and strong.", {
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
    }),
    ("Bare site: no security headers at all.", {}),
    ("Half-configured site: HSTS and nosniff only, CSP missing.", {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
    }),
    ("Weak configuration: short HSTS, unsafe-inline CSP, no frame "
     "protection, version-disclosing Server header.", {
        "strict-transport-security": "max-age=300",
        "content-security-policy":
            "default-src *; script-src 'unsafe-inline'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "unsafe-url",
        "server": "Apache/2.4.52",
        "x-powered-by": "PHP/8.1.0",
    }),
]

with open("examples.txt", "w") as out:
    for title, headers in CASES:
        report = h.evaluate("https://example.com", headers)
        out.write("# %s\n" % title)
        out.write(h.format_report(report, 200, "https://example.com"))
        out.write("\n\n")
print("Wrote examples.txt with %d cases." % len(CASES))
