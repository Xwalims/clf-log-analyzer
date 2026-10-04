"""Tests for non-finite ``$request_time`` fields.

``float()`` accepts ``nan``, ``inf``, ``-inf`` and overflowing literals like
``1e400``.  Every assertion here is anchored to something outside the project:
``json.dumps(..., allow_nan=False)`` refuses to serialise a non-finite float,
which is the same rule RFC 8259 states and that ``node -e 'JSON.parse(..)'``
enforces, so "this payload is not valid JSON" is a fact about JSON rather than
about this package's opinions.  The sorts are anchored to the definition of
min/max: the minimum of a set is never greater than its maximum.
"""

from __future__ import annotations

import json
import math
import unittest

from clf_log_analyzer.aggregate import build_summary, slowest_entries, summary_to_dict
from clf_log_analyzer.chart import bar_chart, format_count, render_sparkline, sparkline
from clf_log_analyzer.cli import render_report
from clf_log_analyzer.parser import parse_line

TEMPLATE = (
    '203.0.113.7 - - [12/Mar/2024:09:15:%s +0000] "GET /x HTTP/1.1" 200 512 '
    '"-" "curl/8.5.0" "%s"'
)

#: Every spelling of a non-finite or overflowing float literal.
NON_FINITE = ("nan", "NaN", "NAN", "-nan", "inf", "Inf", "INF", "infinity",
              "Infinity", "-inf", "-Infinity", "1e400", "-1e400")


def line(second: str, duration: str) -> str:
    return TEMPLATE % (second, duration)


def entries(*pairs: tuple[str, str]):
    return [parse_line(line(sec, dur), line_number=i + 1) for i, (sec, dur) in enumerate(pairs)]


class NonFiniteDurationTests(unittest.TestCase):
    """A duration field must be a finite float or nothing at all."""

    def test_every_non_finite_spelling_is_rejected(self) -> None:
        for token in NON_FINITE:
            with self.subTest(token=token):
                self.assertIsNone(parse_line(line("03", token)).duration)

    def test_overflowing_literal_is_rejected(self) -> None:
        # Ground truth: 1e400 overflows float to +inf, which math.isfinite
        # rejects.  Without the guard this becomes inf, and inf - inf is nan,
        # which is how one corrupt field poisons every downstream statistic.
        self.assertEqual(float("1e400"), math.inf)
        self.assertIsNone(parse_line(line("03", "1e400")).duration)

    def test_negative_durations_are_still_kept(self) -> None:
        # The guard is finiteness, not sign: nginx's timer cannot go negative,
        # but a finite negative value is data, not a corruption, and silently
        # discarding it would hide a misconfigured upstream clock.
        self.assertEqual(parse_line(line("03", "-1.5")).duration, -1.5)

    def test_ordinary_durations_are_unaffected(self) -> None:
        for token, expected in (("0", 0.0), ("0.042", 0.042), ("12", 12.0),
                                ("1e3", 1000.0), ("3.5", 3.5)):
            with self.subTest(token=token):
                self.assertEqual(parse_line(line("03", token)).duration, expected)

    def test_lone_trailing_field_is_guarded_too(self) -> None:
        # A common-format line with one extra quoted field takes the other
        # duration branch; both must reject non-finite input.
        common = ('198.51.100.5 - - [12/Mar/2024:09:15:30 +0000] "GET /h HTTP/1.1" 200 2')
        self.assertIsNone(parse_line(common + ' "nan"').duration)
        self.assertEqual(parse_line(common + ' "0.042"').duration, 0.042)

    def test_non_finite_does_not_make_the_line_malformed(self) -> None:
        # The parser is deliberately tolerant: a corrupt field is dropped, not
        # fatal.  The entry is still counted and still reports its real data.
        entry = parse_line(line("03", "nan"))
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.path, "/x")
        self.assertEqual(entry.size, 512)
        self.assertIsNone(entry.duration)


class DurationStatisticsTests(unittest.TestCase):
    """A corrupt duration must not corrupt the statistics computed from it."""

    def test_min_and_max_are_not_inverted(self) -> None:
        # Before the fix, sorted([0.5, nan, 0.25]) left the low value last,
        # so the summary reported duration=(0.5, 0.25) -- the minimum greater
        # than the maximum, which is false for any real data set.
        summary = build_summary(entries(("10", "0.5"), ("20", "nan"), ("30", "0.25")), top=5)
        self.assertEqual(summary.duration, (0.25, 0.5))
        low, high = summary.duration
        self.assertLessEqual(low, high)

    def test_corrupt_duration_is_excluded_from_slowest(self) -> None:
        ranked = slowest_entries(entries(("10", "0.5"), ("20", "nan")), 5)
        self.assertEqual([duration for _, duration in ranked], [0.5])

    def test_all_non_finite_leaves_the_default_range(self) -> None:
        summary = build_summary(entries(("10", "nan"), ("20", "inf")), top=5)
        self.assertEqual(summary.duration, (0.0, 0.0))
        self.assertEqual(summary.slowest, [])

    def test_report_never_renders_a_nan_duration(self) -> None:
        # The user-visible symptom: the report printed the line
        #     0.500s 200 /x
        #     nans   200 /x
        # because the format spec appended the unit to the text "nan".
        report = render_report(
            build_summary(entries(("10", "0.5"), ("20", "nan")), top=5),
            chart="none",
            logfile="access.log",
        )
        self.assertNotIn("nan", report.lower())
        self.assertNotIn("inf", report.lower())
        self.assertIn("0.500s", report)


class JsonPayloadTests(unittest.TestCase):
    """``--json`` must emit JSON that other tools can actually parse."""

    def payload(self) -> str:
        summary = build_summary(entries(("10", "0.5"), ("20", "nan")), top=5)
        return json.dumps(summary_to_dict(summary, top=5), indent=2, sort_keys=True)

    def test_payload_round_trips_with_non_finite_rejected(self) -> None:
        # json.loads' default leniency turns a bare NaN token into float('nan'),
        # so parsing alone proves nothing.  Re-dumping the result with
        # allow_nan=False is the real oracle: it raises on any non-finite
        # float, so a clean re-dump means no NaN survived into the document.
        # On the unfixed parser this call raises ValueError.
        payload = self.payload()
        json.dumps(json.loads(payload), allow_nan=False)

    def test_payload_reparses_without_lenient_extensions(self) -> None:
        # parse_constant fires on NaN/Infinity/-Infinity, the non-standard
        # tokens.  A clean round-trip means none of them survived into the
        # document, so a strict consumer such as node's JSON.parse will accept
        # it too.
        def reject(constant: str) -> float:
            raise ValueError(f"non-standard JSON constant: {constant}")

        parsed = json.loads(self.payload(), parse_constant=reject)
        self.assertEqual(parsed["total_requests"], 2)

    def test_no_bare_nan_or_infinity_tokens(self) -> None:
        payload = self.payload()
        for token in ("NaN", "Infinity", "-Infinity"):
            self.assertNotIn(token, payload)

    def test_entry_as_dict_is_json_serialisable(self) -> None:
        entry = parse_line(line("03", "nan"))
        json.dumps(entry.as_dict(), allow_nan=False)


class ChartTests(unittest.TestCase):
    """Chart helpers must not raise on non-finite input."""

    def test_sparkline_raises_without_the_parser_guard(self) -> None:
        # Not a fix -- a demonstration that the crash was reachable.  Charts
        # are public helpers and callers may hand them a NaN of their own
        # making; int(round(nan)) is a ValueError.
        with self.assertRaises(ValueError):
            sparkline([1, math.nan, 2])
        self.assertEqual(len(sparkline([1, 2, 3])), 3)

    def test_format_count_renders_plain_text_for_non_finite(self) -> None:
        # format_count is a formatter, not a validator: it must not raise.
        for value in (math.nan, math.inf, -math.inf):
            with self.subTest(value=value):
                self.assertIsInstance(format_count(value), str)

    def test_format_count_still_renders_finite_values(self) -> None:
        self.assertEqual(format_count(1234), "1,234")
        self.assertEqual(format_count(1234.5), "1,234.50")
        self.assertEqual(format_count(0), "0")

    def test_charts_survive_a_series_built_from_a_guarded_parse(self) -> None:
        # The end-to-end path: whatever the parser hands the chart is finite.
        series = [(f"{s}s", e.duration) for s, e in
                  zip(("10", "20"), entries(("10", "0.5"), ("20", "nan")))]
        finite = [(label, value) for label, value in series if value is not None]
        self.assertIsInstance(bar_chart([(p, 1) for p in ("/a", "/b")]), str)
        self.assertIsInstance(sparkline([v for _, v in finite]), str)
        self.assertIsInstance(render_sparkline(finite, width=40), str)


if __name__ == "__main__":
    unittest.main()