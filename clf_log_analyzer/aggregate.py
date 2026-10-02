"""Pure aggregation functions turning parsed entries into deterministic statistics.

Every function here is a pure transformation of an iterable of
:class:`~clf_log_analyzer.parser.Entry` objects: no I/O, no globals, no
randomness.  Ordering is fully deterministic -- ties are always broken by the
key itself, ascending, so repeated runs over the same input produce
byte-identical reports.
"""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Sequence

from .parser import Entry

__all__ = [
    "Aggregate",
    "status_class_counts",
    "top_paths",
    "top_clients",
    "slowest_entries",
    "per_minute_counts",
    "byte_totals",
    "method_counts",
    "build_summary",
    "summary_to_dict",
]

#: Status classes in the order they are always rendered.
STATUS_CLASS_ORDER = ("1xx", "2xx", "3xx", "4xx", "5xx", "other")

#: Sentinel "top" meaning "do not truncate", used for whole-dimension rankings.
_UNLIMITED = sys.maxsize


@dataclass(frozen=True, slots=True)
class Aggregate:
    """An immutable statistical summary of a parsed access log.

    Attributes:
        total_requests: Number of parsed entries.
        first_seen: Earliest timestamp, or ``None`` when empty.
        last_seen: Latest timestamp, or ``None`` when empty.
        status_classes: Counts per status class, ordered by
            :data:`STATUS_CLASS_ORDER`.
        status_codes: Counts per exact status code, ascending by code.
        methods: Counts per request method, descending by count then name.
        per_minute: ``(minute, count)`` pairs sorted by minute ascending.
        top_paths: ``(path, count)`` pairs, most requested first.
        top_clients: ``(ip, count)`` pairs, most requests first.
        slowest: ``(entry, duration)`` pairs, slowest first, only for
            entries carrying a duration.
        bytes_total: Sum of all non-``None`` response sizes.
        bytes_count: Number of entries contributing to :attr:`bytes_total`.
        bytes_avg: Mean response size rounded to two decimals, or ``0.0``.
        unique_paths: Distinct request paths seen.
        unique_clients: Distinct client addresses seen.
        malformed_lines: Number of lines that failed to parse.
        total_lines: Non-blank lines read, parsed and malformed combined.
    """

    total_requests: int
    first_seen: datetime | None
    last_seen: datetime | None
    status_classes: list[tuple[str, int]]
    status_codes: list[tuple[int, int]]
    methods: list[tuple[str, int]]
    per_minute: list[tuple[datetime, int]]
    top_paths: list[tuple[str, int]]
    top_clients: list[tuple[str, int]]
    slowest: list[tuple[Entry, float]]
    bytes_total: int
    bytes_count: int
    bytes_avg: float
    unique_paths: int
    unique_clients: int
    malformed_lines: int = 0
    total_lines: int = 0
    duration: tuple[float, float] = (0.0, 0.0)

    def as_dict(self, top: int = 10) -> dict[str, object]:
        """Return a JSON-serialisable view of the summary.

        Args:
            top: How many rows to include for the path, client and slowest
                rankings.  ``0`` omits those lists entirely.
        """
        return summary_to_dict(self, top)


def _ranked(counter: Counter[str], top: int) -> list[tuple[str, int]]:
    """Rank a counter by descending count, breaking ties ascending by key.

    This single helper is what makes every "top N" list in the package
    deterministic: no reliance on dict insertion order or sort stability.
    """
    if top <= 0:
        return []
    return sorted(counter.items(), key=lambda item: (-item[1], item[0]))[:top]


def status_class_counts(entries: Iterable[Entry]) -> list[tuple[str, int]]:
    """Count entries per HTTP status class, in fixed class order.

    Classes with no entries are omitted, but the relative order of the
    classes that are present is always :data:`STATUS_CLASS_ORDER`.
    """
    counter: Counter[str] = Counter(entry.status_class for entry in entries)
    return [(label, counter[label]) for label in STATUS_CLASS_ORDER if counter.get(label)]


def method_counts(entries: Iterable[Entry]) -> list[tuple[str, int]]:
    """Count entries per request method, most frequent first then alphabetical."""
    return _ranked(Counter(entry.method for entry in entries), top=_UNLIMITED)


def top_paths(entries: Iterable[Entry], top: int = 10) -> list[tuple[str, int]]:
    """Return the *top* most requested paths.

    Ties are broken by ascending path so that equal counts always render in
    the same order.
    """
    return _ranked(Counter(entry.path for entry in entries), top)


def top_clients(entries: Iterable[Entry], top: int = 10) -> list[tuple[str, int]]:
    """Return the *top* client addresses by request count, deterministically."""
    return _ranked(Counter(entry.ip for entry in entries), top)


def slowest_entries(entries: Iterable[Entry], top: int = 5) -> list[tuple[Entry, float]]:
    """Return the *top* slowest entries that carry a duration.

    Ordering is descending by duration, then by ascending line number so
    entries with identical durations keep their file order.  Entries without
    a recorded duration are skipped rather than assumed to be instant.
    """
    timed = [(entry, float(entry.duration)) for entry in entries if entry.duration is not None]
    timed.sort(key=lambda pair: (-pair[1], pair[0].line_number))
    return timed[: max(top, 0)]


def per_minute_counts(entries: Iterable[Entry]) -> list[tuple[datetime, int]]:
    """Bucket entries into one-minute buckets, sorted by minute ascending.

    Minutes with no traffic are not invented; only minutes that actually
    received a request appear, which keeps the series sparse and honest for
    log files that cover long idle stretches.  Bucketing compares absolute
    instants, so entries from different UTC offsets land in the correct
    shared bucket.
    """
    counter: Counter[datetime] = Counter(entry.minute for entry in entries)
    return sorted(counter.items(), key=lambda item: item[0])


def byte_totals(entries: Iterable[Entry]) -> tuple[int, int, float]:
    """Return ``(total_bytes, entries_with_size, average_bytes)``.

    Responses logged as ``-`` contribute to neither total nor divisor, so the
    average reflects only responses that actually carried a body.
    """
    sizes = [entry.size for entry in entries if entry.size is not None]
    total = sum(sizes)
    count = len(sizes)
    average = round(total / count, 2) if count else 0.0
    return total, count, average


def build_summary(
    entries: Iterable[Entry],
    top: int = 10,
    malformed_lines: int = 0,
    total_lines: int | None = None,
) -> Aggregate:
    """Build a full :class:`Aggregate` from parsed entries.

    Args:
        entries: The parsed entries to summarise.
        top: Default row count for the path and client rankings stored in the
            result.
        malformed_lines: Count of unparsable lines, carried through for
            reporting.
        total_lines: Non-blank lines read; defaults to the number of entries
            plus *malformed_lines*.

    Returns:
        A populated :class:`Aggregate`.  An empty input yields a zeroed
        summary rather than an error.
    """
    items: Sequence[Entry] = list(entries)
    status_codes = sorted(Counter(entry.status for entry in items).items())
    per_minute = per_minute_counts(items)
    durations = sorted(entry.duration for entry in items if entry.duration is not None)
    total_bytes, size_count, bytes_avg = byte_totals(items)
    return Aggregate(
        total_requests=len(items),
        first_seen=min((entry.timestamp for entry in items), default=None),
        last_seen=max((entry.timestamp for entry in items), default=None),
        status_classes=status_class_counts(items),
        status_codes=status_codes,
        methods=method_counts(items),
        per_minute=per_minute,
        top_paths=top_paths(items, top),
        top_clients=top_clients(items, top),
        slowest=slowest_entries(items, min(top, 5)),
        bytes_total=total_bytes,
        bytes_count=size_count,
        bytes_avg=bytes_avg,
        unique_paths=len({entry.path for entry in items}),
        unique_clients=len({entry.ip for entry in items}),
        malformed_lines=malformed_lines,
        total_lines=len(items) + malformed_lines if total_lines is None else total_lines,
        duration=(
            durations[0] if durations else 0.0,
            durations[-1] if durations else 0.0,
        ),
    )


def summary_to_dict(summary: Aggregate, top: int = 10) -> dict[str, object]:
    """Convert an :class:`Aggregate` into nested plain dicts and lists.

    Timestamps become ISO 8601 strings and the slowest-request entries are
    reduced to their :meth:`Entry.as_dict` form, so the result is safe to
    hand straight to :func:`json.dumps`.
    """
    return {
        "total_requests": summary.total_requests,
        "total_lines": summary.total_lines,
        "malformed_lines": summary.malformed_lines,
        "unique_paths": summary.unique_paths,
        "unique_clients": summary.unique_clients,
        "first_seen": summary.first_seen.isoformat() if summary.first_seen else None,
        "last_seen": summary.last_seen.isoformat() if summary.last_seen else None,
        "bytes": {
            "total": summary.bytes_total,
            "count": summary.bytes_count,
            "average": summary.bytes_avg,
        },
        "status_classes": {label: count for label, count in summary.status_classes},
        "status_codes": {str(code): count for code, count in summary.status_codes},
        "methods": dict(summary.methods),
        "per_minute": [
            {"minute": minute.isoformat(), "count": count} for minute, count in summary.per_minute
        ],
        "top_paths": [{"path": path, "count": count} for path, count in summary.top_paths[:top]],
        "top_clients": [{"ip": ip, "count": count} for ip, count in summary.top_clients[:top]],
        "slowest": [
            {**entry.as_dict(), "duration": duration} for entry, duration in summary.slowest[:top]
        ],
    }