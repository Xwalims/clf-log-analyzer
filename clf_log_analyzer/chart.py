"""Fixed-width ASCII rendering: sparklines for time series and bar charts.

Everything here returns a plain string of a predictable width, so reports can
be pasted into tickets and terminal transcripts without reflowing.  No
external plotting dependency is used and no Unicode is required: the glyph
sets below are plain ASCII, which keeps output readable over SSH sessions
with a legacy locale.
"""

from __future__ import annotations

from typing import Sequence

__all__ = [
    "SPARK_CHARS",
    "BAR_GLYPHS",
    "format_count",
    "sparkline",
    "render_sparkline",
    "bar_chart",
    "render_bars",
    "truncate_label",
]

#: Eight intensity levels, lowest first.
SPARK_CHARS = " .:-=+*#"

#: Fractional block glyphs for bars, lowest first, used for the remainder cell.
BAR_GLYPHS = " ▏▎▍▌▋▊▉█"


def format_count(value: float) -> str:
    """Format a number for a chart column: thousands separators, no float noise.

    Negative zero is normalised to ``"0"`` so that an average of ``-0.0``
    never renders as ``"-0"``.
    """
    if value < 0 and value > -0.005:
        value = 0.0
    if isinstance(value, float) and not value.is_integer():
        return f"{value:,.2f}"
    return f"{int(round(value)):,}"


def truncate_label(label: str, width: int) -> str:
    """Clip *label* to *width* characters, marking the cut with an ellipsis.

    Args:
        label: Text to fit, typically a URL path.
        width: Maximum characters in the result; values below ``3`` are
            raised to ``3`` so the ellipsis always has room.

    Returns:
        The label unchanged when it fits, otherwise a left-truncated short
        form.  Paths keep their tail because the tail is the informative end.
    """
    width = max(width, 3)
    if len(label) <= width:
        return label
    if width <= 3:
        return "..."
    return "..." + label[-(width - 3) :]


def _scale(values: Sequence[float]) -> list[float]:
    """Scale values into 0.0..1.0 against the largest value.

    A zero maximum (all-zero input, or an empty series) yields all zeros
    rather than dividing by zero.
    """
    if not values:
        return []
    peak = max(values)
    if peak <= 0:
        return [0.0] * len(values)
    return [value / peak for value in values]


def sparkline(values: Sequence[float], empty: str = "(no data)") -> str:
    """Render *values* as a single-line sparkline.

    Each value maps to one character from :data:`SPARK_CHARS`, scaled against
    the largest value in the series.

    Args:
        values: The series to render, in display order.
        empty: Returned verbatim when *values* is empty.

    Returns:
        A string of exactly ``len(values)`` characters, or *empty*.
    """
    if not values:
        return empty
    scaled = _scale([float(value) for value in values])
    last = len(SPARK_CHARS) - 1
    return "".join(SPARK_CHARS[min(last, int(round(value * last)))] for value in scaled)


def render_sparkline(
    series: Sequence[tuple[str, float]],
    width: int = 60,
    empty: str = "(no data)",
) -> str:
    """Render a labelled sparkline block with a leading and trailing rule.

    Args:
        series: ``(label, value)`` pairs in display order.
        width: Total block width in characters; the sparkline itself is
            ``width`` minus the label column.
        empty: Returned verbatim when *series* is empty.

    Returns:
        A multi-line string.  When *series* is empty the result is just
        *empty*, so the caller can print it unconditionally.
    """
    if not series:
        return empty
    width = max(width, 20)
    label_width = min(max(len(label) for label, _ in series), 24)
    body_width = max(width - label_width - 1, 1)
    counts = [value for _, value in series]
    # One character per bucket; collapse long series onto a fixed width so the
    # block always renders to the same number of columns.
    step = max(len(counts) // body_width, 1)
    collapsed = [sum(counts[start : start + step]) for start in range(0, len(counts), step)]
    line = sparkline(collapsed)
    labels = [label for label, _ in series[::step]][: len(line)]
    labels += [series[-1][0]] * (len(line) - len(labels))
    rows = [
        f"{truncate_label(label, label_width).ljust(label_width)} {line[index]}"
        f"  {format_count(collapsed[index])}"
        for index, label in enumerate(labels)
    ]
    return "\n".join(rows)


def _bar(value: float, peak: float, width: int) -> str:
    """Return a fixed-width bar of *width* cells for *value* against *peak*.

    Fractional Unicode blocks give sub-cell resolution so a 9-versus-10
    comparison is still visible.  Falls back to ``"#"`` on terminals without
    block glyphs via the plain-ASCII fallback parameter of :func:`render_bars`.
    """
    if width <= 0 or value <= 0:
        return ""
    fraction = min(value / peak, 1.0) if peak > 0 else 0.0
    exact = fraction * width
    full = int(exact)
    remainder = exact - full
    glyph_index = int(remainder * (len(BAR_GLYPHS) - 1))
    bar = "█" * full
    if full < width:
        bar += BAR_GLYPHS[glyph_index]
    return bar[:width]


def bar_chart(
    rows: Sequence[tuple[str, float]],
    width: int = 30,
    label_width: int = 34,
    ascii_only: bool = False,
) -> str:
    """Render a horizontal bar chart, one row per item.

    Args:
        rows: ``(label, value)`` pairs; rendered in the order given, which is
            the caller's ranking.
        width: Bar area width in characters.
        label_width: Character budget for labels, truncated from the left.
        ascii_only: Use ``#`` instead of block glyphs, for terminals or
            locales without Unicode coverage.

    Returns:
        A multi-line string, or an empty string when *rows* is empty.
    """
    if not rows:
        return ""
    width = max(width, 1)
    values = [float(value) for _, value in rows]
    peak = max(values)
    lines: list[str] = []
    for (label, value) in rows:
        if ascii_only:
            filled = int(round(min(value / peak, 1.0) * width)) if peak > 0 else 0
            bar = "#" * max(filled, 1 if value > 0 else 0)
        else:
            bar = _bar(float(value), peak, width)
        text = truncate_label(label, label_width)
        padding = label_width - len(text)
        lines.append(f"{' ' * padding}{text} |{bar.ljust(width)} {format_count(value)}")
    return "\n".join(lines)


def render_bars(
    rows: Sequence[tuple[str, float]],
    title: str = "",
    width: int = 30,
    label_width: int = 34,
    ascii_only: bool = False,
) -> str:
    """Render a bar chart with an optional title, appending a peak footer.

    Args:
        rows: ``(label, value)`` pairs in ranking order.
        title: Optional heading line; omitted when empty.
        width: Bar area width in characters.
        label_width: Character budget for labels.
        ascii_only: Use ``#`` instead of block glyphs.

    Returns:
        A multi-line string; just the footer when *rows* is empty, so a
        caller can print the result unconditionally.
    """
    if not rows:
        return "(no data)" if title else ""
    chart = bar_chart(rows, width, label_width, ascii_only)
    peak = max(float(value) for _, value in rows)
    footer = f"peak: {format_count(peak)}"
    return f"{title}\n{chart}\n{footer}" if title else f"{chart}\n{footer}"