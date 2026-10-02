"""Command-line interface for clf-log-analyzer.

Run as ``python3 -m clf_log_analyzer.cli LOGFILE`` or, once installed, as
``clf-log-analyzer LOGFILE``.

Exit codes are stable and part of the public contract:

* ``0`` -- the analysis completed (malformed lines, if any, were reported).
* ``1`` -- ``--strict`` was given and at least one line was malformed.
* ``2`` -- usage error, or the log file could not be read.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .aggregate import Aggregate, build_summary, summary_to_dict
from .chart import bar_chart, render_sparkline
from .parser import (
    FORMAT_AUTO,
    FORMAT_COMBINED,
    FORMAT_COMMON,
    MalformedLineError,
    format_errors,
    open_log,
    parse_lines,
)

__all__ = ["build_parser", "main", "EXIT_OK", "EXIT_MALFORMED", "EXIT_USAGE"]

EXIT_OK = 0
EXIT_MALFORMED = 1
EXIT_USAGE = 2

#: Default number of rows in each ranking table.
DEFAULT_TOP = 10


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the CLI.

    Returns:
        A configured :class:`argparse.ArgumentParser`.  Separated from
        :func:`main` so tests can introspect defaults without running it.
    """
    parser = argparse.ArgumentParser(
        prog="clf-log-analyzer",
        description=(
            "Analyze an Apache/nginx access log (Common or Combined Log Format). "
            "Gzip-compressed files are read transparently."
        ),
        epilog=(
            "Exit codes: 0 success, 1 malformed lines in --strict mode, "
            "2 usage or I/O error."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("logfile", metavar="LOGFILE", help="path to the access log to analyze")
    parser.add_argument(
        "-f",
        "--format",
        dest="log_format",
        choices=[FORMAT_AUTO, FORMAT_COMMON, FORMAT_COMBINED],
        default=FORMAT_AUTO,
        help="log format to enforce while parsing",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=DEFAULT_TOP,
        metavar="N",
        help="rows to show in each ranking table (0 for none)",
    )
    parser.add_argument(
        "--chart",
        dest="chart",
        choices=["sparkline", "bars", "none"],
        default="sparkline",
        help="chart to render for the per-minute time series",
    )
    parser.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="print a machine-readable JSON summary instead of a text report",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="exit with status 1 if any line is malformed",
    )
    parser.add_argument(
        "--max-errors",
        type=int,
        default=5,
        metavar="N",
        help="malformed lines to list individually (0 for none)",
    )
    parser.add_argument("--version", action="version", version=f"clf-log-analyzer {__version__}")
    return parser


def _rule(char: str = "-", width: int = 68) -> str:
    """Return a horizontal rule of *width* characters."""
    return char * width


def _kv(label: str, value: str, label_width: int = 22) -> str:
    """Format one aligned ``label  value`` report line."""
    return f"{label.ljust(label_width)}{value}"


def _format_bytes(value: int) -> str:
    """Render a byte count with binary units, e.g. ``"1.5 MiB"``."""
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0 or unit == "TiB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{int(size)} B"


def _format_span(summary: Aggregate) -> str:
    """Render the first/last timestamp pair, or ``"n/a"`` when empty."""
    if summary.first_seen is None or summary.last_seen is None:
        return "n/a"
    return f"{summary.first_seen.isoformat()}  ->  {summary.last_seen.isoformat()}"


def render_report(
    summary: Aggregate,
    chart: str = "sparkline",
    max_errors: int = 0,
    error_lines: Sequence[str] = (),
    logfile: str = "",
) -> str:
    """Render a full human-readable text report for *summary*.

    Args:
        summary: The aggregated statistics to render.
        chart: ``"sparkline"``, ``"bars"`` or ``"none"``.
        max_errors: Retained for interface symmetry; error lines are taken
            from *error_lines*.
        error_lines: Pre-rendered malformed-line messages.
        logfile: Optional path shown in the header.

    Returns:
        The complete report as a single string with trailing newlines
        normalised.  Never raises on an empty summary.
    """
    out: list[str] = []
    header = f"clf-log-analyzer {__version__}"
    if logfile:
        header += f"  {logfile}"
    out.append(header)
    out.append(_rule("="))
    out.append(_kv("Requests", f"{summary.total_requests:,}"))
    out.append(_kv("Lines read", f"{summary.total_lines:,}"))
    if summary.malformed_lines:
        out.append(_kv("Malformed lines", f"{summary.malformed_lines:,}"))
    out.append(_kv("Time span", _format_span(summary)))
    out.append(_kv("Unique clients", f"{summary.unique_clients:,}"))
    out.append(_kv("Unique paths", f"{summary.unique_paths:,}"))
    out.append(_kv(
        "Bytes transferred",
        f"{_format_bytes(summary.bytes_total)} ({summary.bytes_total:,} in {summary.bytes_count:,} responses)",
    ))
    out.append(_kv("Average response", _format_bytes(int(summary.bytes_avg))))
    out.append("")

    out.append("Status classes")
    if summary.status_classes:
        for label, count in summary.status_classes:
            share = 100.0 * count / summary.total_requests if summary.total_requests else 0.0
            out.append(f"  {label}  {count:>7,}  ({share:5.1f}%)")
    else:
        out.append("  (none)")
    out.append("")

    out.append("Status codes")
    if summary.status_codes:
        out.append("  " + "  ".join(f"{code}:{count:,}" for code, count in summary.status_codes))
    else:
        out.append("  (none)")
    out.append("")

    if summary.methods:
        out.append("Methods")
        for method, count in summary.methods:
            out.append(f"  {method:<8}{count:>8,}")
        out.append("")

    out.append(f"Top {len(summary.top_paths)} paths")
    if summary.top_paths:
        out.append(bar_chart([(path, count) for path, count in summary.top_paths]))
    else:
        out.append("  (none)")
    out.append("")

    out.append(f"Top {len(summary.top_clients)} clients")
    if summary.top_clients:
        out.append(bar_chart([(ip, count) for ip, count in summary.top_clients]))
    else:
        out.append("  (none)")
    out.append("")

    if summary.slowest:
        out.append(f"Slowest {len(summary.slowest)} requests")
        out.append(f"  {'duration':>10}  {'status':>6}  path")
        for entry, duration in summary.slowest:
            out.append(f"  {duration:>9.3f}s  {entry.status:>6}  {entry.path}")
        out.append("")

    if chart != "none":
        series = [
            (minute.strftime("%H:%M"), count) for minute, count in summary.per_minute
        ]
        out.append(f"Requests per minute ({len(series)} buckets)")
        if not series:
            out.append("  (no data)")
        elif chart == "bars":
            out.append(bar_chart([(label, count) for label, count in series]))
        else:
            out.append(render_sparkline(series, width=60))
        out.append("")

    if error_lines:
        out.append(f"Malformed lines ({len(error_lines)} shown)")
        for line in error_lines:
            out.append(f"  {line}")
        out.append("")

    return "\n".join(out).rstrip("\n") + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Argument list excluding the program name.  ``None`` means read
            from :data:`sys.argv`.

    Returns:
        A process exit status: ``0`` success, ``1`` malformed lines under
        ``--strict``, ``2`` usage or I/O error.
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.top < 0:
        print("clf-log-analyzer: error: --top must not be negative", file=sys.stderr)
        return EXIT_USAGE

    try:
        with open_log(args.logfile) as handle:
            result = parse_lines(handle, args.log_format, strict=args.strict)
    except FileNotFoundError:
        print(f"clf-log-analyzer: error: no such file: {args.logfile}", file=sys.stderr)
        return EXIT_USAGE
    except IsADirectoryError:
        print(f"clf-log-analyzer: error: is a directory: {args.logfile}", file=sys.stderr)
        return EXIT_USAGE
    except PermissionError:
        print(f"clf-log-analyzer: error: permission denied: {args.logfile}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"clf-log-analyzer: error: cannot read {args.logfile}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except MalformedLineError as exc:
        print(f"clf-log-analyzer: error: malformed line in {args.logfile}: {exc}", file=sys.stderr)
        return EXIT_MALFORMED
    except UnicodeError as exc:
        print(f"clf-log-analyzer: error: cannot decode {args.logfile}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    summary = build_summary(
        result.entries,
        top=args.top,
        malformed_lines=len(result.errors),
        total_lines=result.total_lines,
    )

    if args.as_json:
        payload = summary_to_dict(summary, top=args.top)
        payload["errors"] = [
            {"line": err.line_number, "message": err.message} for err in result.errors[: args.max_errors]
        ]
        payload["error_count"] = len(result.errors)
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        errors = format_errors(result.errors, args.max_errors)
        print(render_report(summary, chart=args.chart, error_lines=errors, logfile=args.logfile))

    if args.strict and result.errors:
        print(
            f"clf-log-analyzer: {len(result.errors)} malformed line(s) in {args.logfile}",
            file=sys.stderr,
        )
        return EXIT_MALFORMED
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())