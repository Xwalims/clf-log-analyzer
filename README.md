# clf-log-analyzer

A dependency-free analyzer for Apache and nginx access logs. It parses Common
Log Format and Combined Log Format, aggregates the traffic into deterministic
statistics, and renders the result as a fixed-width text report or JSON.

<!-- hero -->

[![CI](https://github.com/Xwalims/clf-log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Xwalims/clf-log-analyzer/actions/workflows/ci.yml)
![python 3.11 – 3.13](https://img.shields.io/badge/python-3.11–3.13-blue)
![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![dependencies](https://img.shields.io/badge/dependencies-none-2f6f4f)

## Contents

- [What it is](#what-it-is)
- [Why](#why)
- [Usage](#usage)
  - [Default text report](#default-text-report)
  - [JSON for pipelines](#json-for-pipelines)
  - [Strict mode in a monitoring pipeline](#strict-mode-in-a-monitoring-pipeline)
  - [Gzip logs](#gzip-logs)
- [Supported formats](#supported-formats)
- [License](#license)

<!-- /hero -->

## What it is

Given an access log, it answers the questions you actually have after an
incident or a traffic spike: how much traffic was there, when did it happen,
what broke, who was asking, and which endpoints dominate.

## Why

Most log tooling wants a virtualenv, a dependency tree, or a network fetch
before it will tell you the error rate for the last hour. On an incident
host that is often not available. This tool is pure standard library: it
runs from a checkout with the interpreter you already have, reads plain or
gzip-compressed logs, and never raises on a corrupt line, because a single
bad line should not hide the nine hundred thousand good ones behind it.

Design choices worth stating up front:

- **No dependencies.** Standard library only, Python 3.11 or newer.
- **Deterministic output.** Ties in every ranking break by ascending key, so
  the same log always renders byte-for-byte identically. That makes the
  report safe to diff between runs or to assert in a test.
- **Never fatal on bad data.** Malformed lines are collected and reported.
  `--strict` opts into fail-fast behaviour for pipeline use.
- **Timezone-aware.** Timestamps carry their UTC offset. Per-minute buckets
  compare absolute instants, so lines logged in different offsets aggregate
  together correctly.

## Install

There is nothing to install. Clone and run:

```bash
git clone https://github.com/Xwalims/clf-log-analyzer.git
cd clf-log-analyzer
python3 -m clf_log_analyzer.cli --help
```

To put a `clf-log-analyzer` command on your `PATH`:

```bash
python3 -m pip install .
```

## Usage

All output below is real, pasted from a terminal running this tool.

### Default text report

```console
$ python3 -m clf_log_analyzer.cli /tmp/demo/access.log
clf-log-analyzer 0.1.0  /tmp/demo/access.log
====================================================================
Requests              10
Lines read            11
Malformed lines       1
Time span             2024-03-12T09:15:03+00:00  ->  2024-03-12T09:19:58+00:00
Unique clients        5
Unique paths          6
Bytes transferred     5.9 KiB (6,076 in 8 responses)
Average response      759 B

Status classes
  2xx        4  ( 40.0%)
  3xx        2  ( 20.0%)
  4xx        3  ( 30.0%)
  5xx        1  ( 10.0%)

Status codes
  200:4  301:1  304:1  401:1  403:1  404:1  500:1

Methods
  GET            8
  HEAD           1
  POST           1

Top 6 paths
                       /index.html |██████████████████████████████ 4
                        /style.css |███████████████                2
                            /admin |███████▌                       1
                     /api/v1/login |███████▌                       1
                           /health |███████▌                       1
                       /missing.js |███████▌                       1

Top 5 clients
                       203.0.113.7 |██████████████████████████████ 4
                      198.51.100.5 |███████████████                2
                      198.51.100.9 |███████████████                2
                        192.0.2.44 |███████▌                       1
      2001:db8:85a3::8a2e:370:7334 |███████▌                       1

Requests per minute (5 buckets)
09:15 #  3
09:16 +  2
09:17 :  1
09:18 +  2
09:19 +  2

Malformed lines (1 shown)
  line 11: expected '[': '### not a log line at all ###'
```

Note the IPv6 client and the malformed line on line 11: the report still
renders, and the bad line is called out instead of silently dropped.

### JSON for pipelines

```console
$ python3 -m clf_log_analyzer.cli /tmp/demo/access.log --json --top 2
{
  "bytes": {
    "average": 759.5,
    "count": 8,
    "total": 6076
  },
  "error_count": 1,
  "errors": [
    {
      "line": 11,
      "message": "expected '['"
    }
  ],
  "first_seen": "2024-03-12T09:15:03+00:00",
  "last_seen": "2024-03-12T09:19:58+00:00",
  "malformed_lines": 1,
  "methods": {
    "GET": 8,
    "HEAD": 1,
    "POST": 1
  },
  "per_minute": [
    {
      "count": 3,
      "minute": "2024-03-12T09:15:00+00:00"
    },
    {
      "count": 2,
      "minute": "2024-03-12T09:16:00+00:00"
    },
    {
      "count": 1,
      "minute": "2024-03-12T09:17:00+00:00"
    },
    {
      "count": 2,
      "minute": "2024-03-12T09:18:00+00:00"
    },
    {
      "count": 2,
      "minute": "2024-03-12T09:19:00+00:00"
    }
  ],
  "slowest": [],
  "status_classes": {
    "2xx": 4,
    "3xx": 2,
    "4xx": 3,
    "5xx": 1
  },
  "status_codes": {
    "200": 4,
    "301": 1,
    "304": 1,
    "401": 1,
    "403": 1,
    "404": 1,
    "500": 1
  },
  "top_clients": [
    {
      "count": 4,
      "ip": "203.0.113.7"
    },
    {
      "count": 2,
      "ip": "198.51.100.5"
    }
  ],
  "top_paths": [
    {
      "count": 4,
      "path": "/index.html"
    },
    {
      "count": 2,
      "path": "/style.css"
    }
  ],
  "total_lines": 11,
  "total_requests": 10,
  "unique_clients": 5,
  "unique_paths": 6
}
```

Keys are sorted, so the output diffs cleanly in CI or feeds straight into
`jq`.

### Bar charts instead of a sparkline

```console
$ python3 -m clf_log_analyzer.cli /tmp/demo/access.log --chart bars --top 3
Top 3 paths
                       /index.html |██████████████████████████████ 4
                        /style.css |███████████████                2
                            /admin |███████▌                       1

Top 3 clients
                       203.0.113.7 |██████████████████████████████ 4
                      198.51.100.5 |███████████████                2
                      198.51.100.9 |███████████████                2

Requests per minute (5 buckets)
                             09:15 |██████████████████████████████ 3
                             09:16 |████████████████████           2
                             09:17 |██████████                     1
                             09:18 |████████████████████           2
                             09:19 |████████████████████           2
```

### Strict mode in a monitoring pipeline

```console
$ python3 -m clf_log_analyzer.cli /tmp/demo/access.log --strict > /dev/null
clf-log-analyzer: error: malformed line in /tmp/demo/access.log: line 11: expected '[': '### not a log line at all ###'
$ echo $?
1
```

### Gzip logs

Compression is detected from the file's magic bytes, not its extension, so
rotated logs work whether or not they kept the `.gz` suffix:

```console
$ python3 -m clf_log_analyzer.cli /var/log/nginx/access.log.1.gz --top 5
```

## Supported formats

Common Log Format:

```
host ident authuser [date] "request" status bytes
```

Combined Log Format:

```
host ident authuser [date] "request" status bytes "referer" "user-agent"
```

Also handled:

- A fourth quoted field carrying a request duration in seconds, as written by
  the nginx `$request_time` variable. It is exposed as `Entry.duration` and
  drives the slowest-request table. Only finite numbers are accepted: a field
  of `nan`, `inf` or `1e400` is corrupt data, so it is discarded and `duration`
  is `None`, exactly as if the field were absent. The request itself is still
  counted and still contributes its status, size and timing. This matters
  because `float()` happily accepts all three, and a single surviving `nan`
  prints as the text `nans` in the report, inverts the min/max duration range
  and makes `--json` emit a bare `NaN` token that strict JSON parsers reject.
- IPv6 client addresses, bare (`2001:db8::1`) or in Apache's bracketed form
  (`[2001:db8::1]`), which is unwrapped on parse.
- `-` for any absent field. A `-` byte count becomes `None`, not `0`, so the
  average response size reflects only responses that carried a body.
- Escaped characters inside quoted fields: `\"`, `\\`, `\n`, `\t` and nginx's
  `\xHH` hexadecimal form.
- UTC offsets of `+HHMM`, `+HH:MM` or none at all, which is read as UTC.

## Supported flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `LOGFILE` | required | Path to the access log. `.gz` is decompressed transparently. |
| `-f`, `--format` | `auto` | Enforce `auto`, `common` or `combined` while parsing. |
| `--top N` | `10` | Rows per ranking table. `0` omits the rankings. |
| `--chart` | `sparkline` | Per-minute rendering: `sparkline`, `bars` or `none`. |
| `--json` | off | Emit a machine-readable summary instead of text. |
| `--strict` | off | Exit `1` if any line is malformed. |
| `--max-errors N` | `5` | Malformed lines listed individually. `0` lists none. |
| `--version` | | Print the version and exit. |
| `-h`, `--help` | | Print usage and exit. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed. Malformed lines, if any, were reported. |
| `1` | `--strict` was given and at least one line was malformed. |
| `2` | Usage error, or the log file could not be read. |

## Library API

Everything the CLI does is available as importable functions.

```python
from clf_log_analyzer import build_summary, parse_file, summary_to_dict

result = parse_file("/var/log/nginx/access.log")
summary = build_summary(result.entries, top=5, malformed_lines=len(result.errors))

print(summary.total_requests, "requests,", summary.bytes_total, "bytes")
for path, count in summary.top_paths:
    print(f"  {count:>6}  {path}")

payload = summary_to_dict(summary, top=5)
print(payload["status_classes"])   # {'2xx': 4, '3xx': 2, '4xx': 3, '5xx': 1}
```

Parsing individual lines, with errors collected rather than raised:

```python
from clf_log_analyzer import parse_lines

result = parse_lines([
    '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET / HTTP/1.1" 200 512',
    "garbage that is not a log line",
])

print(len(result.entries))              # 1
print(result.errors[0].line_number)     # 2
print(result.errors[0].message)         # expected '['
```

Key modules:

- `clf_log_analyzer.parser` -- `Entry`, `parse_line`, `parse_lines`,
  `parse_file`, `open_log`, `detect_format`, `MalformedLineError`.
- `clf_log_analyzer.aggregate` -- `build_summary`, `top_paths`,
  `top_clients`, `per_minute_counts`, `byte_totals`, `slowest_entries`.
- `clf_log_analyzer.chart` -- `sparkline`, `bar_chart`, `render_bars`,
  `render_sparkline`.
- `clf_log_analyzer.cli` -- `build_parser`, `main`.

## How the tests run

The suite uses only `unittest` from the standard library. From the project
root:

```bash
python3 -m unittest discover -s tests -t . -v
```

Five test modules cover the parser, aggregation, charts, non-finite duration
fields and an end-to-end CLI that runs the module in a real subprocess against
real temporary files. CI runs the same command on Python 3.11, 3.12 and 3.13.

## License

MIT. See [LICENSE](LICENSE).
