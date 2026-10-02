"""Shared fixtures for the clf-log-analyzer test suite.

The sample log below is deterministic: fixed hosts, paths, statuses and
timestamps, so every assertion elsewhere can rely on exact numbers.
"""

from __future__ import annotations

from pathlib import Path

#: A combined-format line with a quoted user-agent containing spaces.
SAMPLE_COMBINED = (
    '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET /index.html HTTP/1.1" 200 512 '
    '"https://example.com/start" "Mozilla/5.0 (X11; Linux x86_64) Firefox/122.0"'
)

#: A common-format line with no trailing combined fields.
SAMPLE_COMMON = '198.51.100.5 - - [12/Mar/2024:09:15:30 +0000] "GET /health HTTP/1.1" 200 2'

#: A line whose byte count is the CLF "no body" placeholder.
SAMPLE_NO_SIZE = (
    '203.0.113.7 - - [12/Mar/2024:09:16:10 +0000] "POST /api/v1/login HTTP/1.1" 401 - '
    '"-" "PostmanRuntime/7.37.0"'
)

#: An IPv6 client line with no protocol suffix on the request.
SAMPLE_IPV6 = (
    '2001:db8:85a3::8a2e:370:7334 - - [12/Mar/2024:09:17:00 +0000] "GET /admin HTTP/1.0" 403 512 '
    '"-" "curl/8.5.0"'
)

#: Deliberately malformed input used to exercise error collection.
SAMPLE_MALFORMED = "### not a log line at all ###"

#: A complete, deterministic sample log: 10 entries across 09:15-09:19.
SAMPLE_LOG = "\n".join(
    [
        '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET /index.html HTTP/1.1" 200 512 '
        '"https://example.com/start" "Mozilla/5.0 (X11; Linux x86_64) Firefox/122.0"',
        '203.0.113.7 - - [12/Mar/2024:09:15:20 +0000] "GET /style.css HTTP/1.1" 200 4096 '
        '"https://example.com/index.html" "Mozilla/5.0 (X11; Linux x86_64) Firefox/122.0"',
        '198.51.100.5 - - [12/Mar/2024:09:15:30 +0000] "GET /health HTTP/1.1" 200 2',
        '198.51.100.9 - - [12/Mar/2024:09:16:05 +0000] "GET /index.html HTTP/1.1" 404 289 '
        '"-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
        '203.0.113.7 - - [12/Mar/2024:09:16:10 +0000] "POST /api/v1/login HTTP/1.1" 401 - '
        '"-" "PostmanRuntime/7.37.0"',
        '2001:db8:85a3::8a2e:370:7334 - - [12/Mar/2024:09:17:00 +0000] "GET /admin HTTP/1.0" 403 512 '
        '"-" "curl/8.5.0"',
        '198.51.100.5 - - [12/Mar/2024:09:18:00 +0000] "GET /index.html HTTP/1.1" 200 512 '
        '"https://example.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"',
        '203.0.113.7 - - [12/Mar/2024:09:18:45 +0000] "GET /missing.js HTTP/1.1" 500 153 '
        '"https://example.com/index.html" "Mozilla/5.0 (X11; Linux x86_64) Firefox/122.0"',
        '198.51.100.9 - - [12/Mar/2024:09:19:12 +0000] "GET /style.css HTTP/1.1" 304 - '
        '"https://example.com/index.html" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"',
        '192.0.2.44 - - [12/Mar/2024:09:19:58 +0000] "HEAD /index.html HTTP/1.1" 301 0 '
        '"-" "Go-http-client/2.0"',
        SAMPLE_MALFORMED,
        "",
    ]
)


def write_sample_log(path: Path, text: str = SAMPLE_LOG) -> Path:
    """Write *text* to *path* as a UTF-8 log file and return the path."""
    path.write_text(text, encoding="utf-8")
    return path