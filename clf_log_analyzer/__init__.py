"""clf-log-analyzer: dependency-free analysis of Apache/nginx access logs.

Public API::

    from clf_log_analyzer import parse_file, build_summary, render_report

    result = parse_file("access.log")
    summary = build_summary(result.entries)
    print(render_report(summary))

Every public name below is re-exported from the submodules it is defined in.
"""

from __future__ import annotations

__version__ = "0.1.0"

from .aggregate import (
    Aggregate,
    status_class_counts,
    top_paths,
    top_clients,
    slowest_entries,
    per_minute_counts,
    byte_totals,
    build_summary,
    summary_to_dict,
)
from .chart import (
    BAR_GLYPHS,
    SPARK_CHARS,
    bar_chart,
    render_bars,
    render_sparkline,
    sparkline,
    format_count,
)
from .parser import (
    FORMAT_AUTO,
    FORMAT_COMBINED,
    FORMAT_COMMON,
    Entry,
    MalformedLineError,
    ParseError,
    ParseResult,
    detect_format,
    format_errors,
    iter_entries,
    open_log,
    parse_file,
    parse_line,
    parse_lines,
)

# ``build_parser``/``main`` stay importable from the package root, but are
# resolved lazily: importing ``clf_log_analyzer.cli`` eagerly would make
# ``python3 -m clf_log_analyzer.cli`` load the module twice and emit a
# RuntimeWarning about it already being present in sys.modules.
_CLI_EXPORTS = frozenset({"build_parser", "main"})


def __getattr__(name: str) -> object:
    """Import the CLI submodule on first attribute access."""
    if name in _CLI_EXPORTS:
        from . import cli

        return getattr(cli, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    """List the package namespace, including the lazily loaded CLI names."""
    return sorted(set(globals()) | _CLI_EXPORTS)

__all__ = [
    "__version__",
    # parser
    "Entry",
    "ParseError",
    "ParseResult",
    "MalformedLineError",
    "LogFormat",
    "FORMAT_AUTO",
    "FORMAT_COMMON",
    "FORMAT_COMBINED",
    "detect_format",
    "format_errors",
    "parse_line",
    "parse_lines",
    "iter_entries",
    "open_log",
    "parse_file",
    # aggregate
    "Aggregate",
    "status_class_counts",
    "top_paths",
    "top_clients",
    "slowest_entries",
    "per_minute_counts",
    "byte_totals",
    "build_summary",
    "summary_to_dict",
    # chart
    "BAR_GLYPHS",
    "SPARK_CHARS",
    "sparkline",
    "render_sparkline",
    "bar_chart",
    "render_bars",
    "format_count",
    # cli
    "build_parser",
    "main",
]

# Re-exported for ``from clf_log_analyzer import LogFormat`` even though the
# alias is defined as a Literal in the parser module.
from .parser import LogFormat  # noqa: E402  (placed last to keep __all__ tidy)