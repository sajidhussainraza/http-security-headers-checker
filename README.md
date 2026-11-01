# HTTP Security Headers Checker

A small, dependency-free Python CLI tool (standard library only) that
fetches a site's response headers and grades it on the security headers
that matter most, with a concrete fix for every gap it finds.

It reads headers only. It never submits forms, never follows a login,
and never sends credentials, so it is safe to point at a site you have
permission to audit.

## Run it

```bash
# Grade a site (include https://)
python3 http_headers_checker.py https://example.com

# Machine-readable output for lab reports and scripts
python3 http_headers_checker.py https://example.com --json
```

## What it checks

| Header | Points | What a good value looks like |
|--------|--------|------------------------------|
| Strict-Transport-Security | 20 | `max-age=31536000; includeSubDomains` |
| Content-Security-Policy | 20 | An allow-list policy, no `unsafe-inline` / `unsafe-eval` |
| X-Frame-Options | 20 | `DENY` or `SAMEORIGIN` (a CSP `frame-ancestors` directive also counts) |
| X-Content-Type-Options | 15 | `nosniff` |
| Referrer-Policy | 15 | `strict-origin-when-cross-origin` (not `unsafe-url`) |
| Permissions-Policy | 10 | Unused powerful features disabled, e.g. `camera=(), microphone=()` |

Each check is PASS, WARN (present but weak, partial points), or FAIL
(missing, zero points). Version-disclosing `Server` and `X-Powered-By`
headers are reported as INFO only: they cost no points, but they hand
an attacker free reconnaissance.

Scores map to grades: 90+ = A, 75–89 = B, 60–74 = C, 40–59 = D,
below 40 = F.

## Example output

```text
URL:    https://example.com
Status: 200
Score:  50/100 (grade D)
Checks:
  - [WARN] Strict-Transport-Security (10/20) max-age=300 is shorter than one year
      Fix: Raise max-age to 31536000 or more.
  - [WARN] Content-Security-Policy (10/20) Present but weak: default-src *; script-src 'unsafe-inline'
      Fix: Remove 'unsafe-inline' / 'unsafe-eval' where possible; use nonces or hashes for inline scripts.
  - [FAIL] X-Frame-Options (0/20) Missing
      Fix: Add: X-Frame-Options: DENY (or SAMEORIGIN), or a CSP frame-ancestors directive.
  - [PASS] X-Content-Type-Options (15/15) nosniff
  - [WARN] Referrer-Policy (5/15) unsafe-url
      Fix: unsafe-url leaks the full page URL to other sites. Use strict-origin-when-cross-origin or no-referrer.
  - [FAIL] Permissions-Policy (0/10) Missing
      Fix: Add: Permissions-Policy: camera=(), microphone=(), geolocation=() (plus any feature the site truly uses).
  - [INFO] Server header discloses version info: Apache/2.4.52 (consider returning a generic value)
  - [INFO] X-Powered-By header discloses stack info: PHP/8.1.0 (consider removing it)
```

Four worked examples (perfect, bare, half-configured, weak) are in
`examples.txt`, generated offline by `generate_examples.py`.

## Tests

```bash
python3 test_checker.py
```

15 self-check tests, all offline: full and empty header sets, weak
values (short HSTS, `unsafe-inline` CSP, `unsafe-url` referrer),
`frame-ancestors` covering a missing `X-Frame-Options`, case-insensitive
header names, INFO-only disclosures, grade boundaries, and a mocked
HEAD fetch. 15/15 pass.

## Limitations

A good grade here is not a secure site: headers are one layer, and this
tool does not test the application itself (injection, authentication,
access control), the TLS configuration, or whether a CSP is actually
strict enough for the site's real scripts. It also trusts the headers
of whatever URL it is pointed at, so only audit sites you own or have
permission to test, and re-check after every deployment: headers are
easy to lose in a server migration.
