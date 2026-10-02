"""Tests for :mod:`clf_log_analyzer.aggregate`.

Every assertion here is against exact numbers, which doubles as a regression
net for the sample fixture: if the counts drift, these tests say so.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from clf_log_analyzer.aggregate import (
    Aggregate,
    byte_totals,
    build_summary,
    method_counts,
    per_minute_counts,
    slowest_entries,
    status_class_counts,
    summary_to_dict,
    top_clients,
    top_paths,
)
from clf_log_analyzer.parser import parse_lines

from .fixtures import SAMPLE_LOG


def entries_from(text: str = SAMPLE_LOG) -> list:
    """Parse *text* and return only the successfully parsed entries."""
    return parse_lines(text.splitlines()).entries


class StatusClassTests(unittest.TestCase):
    """Status classes count correctly and render in fixed order."""

    def test_counts_by_class(self) -> None:
        counts = dict(status_class_counts(entries_from()))
        self.assertEqual(counts, {"2xx": 4, "3xx": 2, "4xx": 3, "5xx": 1})

    def test_classes_render_in_fixed_order(self) -> None:
        labels = [label for label, _ in status_class_counts(entries_from())]
        self.assertEqual(labels, ["2xx", "3xx", "4xx", "5xx"])

    def test_absent_classes_are_omitted(self) -> None:
        counts = dict(status_class_counts(entries_from()))
        self.assertNotIn("1xx", counts)

    def test_empty_input_yields_no_classes(self) -> None:
        self.assertEqual(status_class_counts([]), [])


class TopNTests(unittest.TestCase):
    """Rankings are ordered by count with deterministic tie-breaking."""

    def test_top_paths_ranking(self) -> None:
        self.assertEqual(
            top_paths(entries_from(), 3),
            [("/index.html", 4), ("/style.css", 2), ("/admin", 1)],
        )

    def test_top_clients_ranking(self) -> None:
        self.assertEqual(
            top_clients(entries_from(), 3),
            [
                ("203.0.113.7", 4),
                ("198.51.100.5", 2),
                ("198.51.100.9", 2),
            ],
        )

    def test_ties_break_ascending_by_key(self) -> None:
        # /a and /b are both requested once, so the tie must resolve to /a.
        lines = [
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET /b HTTP/1.1" 200 1',
            '203.0.113.7 - - [12/Mar/2024:09:15:04 +0000] "GET /a HTTP/1.1" 200 1',
            '203.0.113.7 - - [12/Mar/2024:09:15:05 +0000] "GET /c HTTP/1.1" 200 1',
        ]
        self.assertEqual([path for path, _ in top_paths(entries_from("\n".join(lines)), 5)],
                         ["/a", "/b", "/c"])

    def test_top_zero_returns_no_rows(self) -> None:
        self.assertEqual(top_paths(entries_from(), 0), [])
        self.assertEqual(top_clients(entries_from(), 0), [])

    def test_top_larger_than_input_is_fine(self) -> None:
        self.assertEqual(len(top_paths(entries_from(), 999)), 6)

    def test_ranking_is_stable_across_repeated_calls(self) -> None:
        first = top_paths(entries_from(), 5)
        for _ in range(4):
            self.assertEqual(top_paths(entries_from(), 5), first)

    def test_method_counts_ranked_by_count(self) -> None:
        self.assertEqual(
            method_counts(entries_from())[:2], [("GET", 8), ("HEAD", 1)]
        )


class PerMinuteTests(unittest.TestCase):
    """One-minute bucketing, including across an hour boundary."""

    def test_buckets_from_the_sample(self) -> None:
        buckets = per_minute_counts(entries_from())
        self.assertEqual(
            [(minute.strftime("%H:%M"), count) for minute, count in buckets],
            [("09:15", 3), ("09:16", 2), ("09:17", 1), ("09:18", 2), ("09:19", 2)],
        )

    def test_buckets_are_sorted_ascending(self) -> None:
        minutes = [minute for minute, _ in per_minute_counts(entries_from())]
        self.assertEqual(minutes, sorted(minutes))

    def test_out_of_order_input_still_sorts(self) -> None:
        lines = [
            '203.0.113.7 - - [12/Mar/2024:10:05:00 +0000] "GET /late HTTP/1.1" 200 1',
            '203.0.113.7 - - [12/Mar/2024:09:55:00 +0000] "GET /early HTTP/1.1" 200 1',
        ]
        buckets = per_minute_counts(entries_from("\n".join(lines)))
        self.assertEqual(
            [(minute.strftime("%H:%M"), count) for minute, count in buckets],
            [("09:55", 1), ("10:05", 1)],
        )

    def test_buckets_across_an_hour_boundary(self) -> None:
        lines = [
            '203.0.113.7 - - [12/Mar/2024:09:59:58 +0000] "GET /a HTTP/1.1" 200 1',
            '203.0.113.7 - - [12/Mar/2024:10:00:01 +0000] "GET /b HTTP/1.1" 200 1',
            '203.0.113.7 - - [12/Mar/2024:10:00:59 +0000] "GET /c HTTP/1.1" 200 1',
        ]
        buckets = per_minute_counts(entries_from("\n".join(lines)))
        self.assertEqual(
            [(minute.strftime("%H:%M"), count) for minute, count in buckets],
            [("09:59", 1), ("10:00", 2)],
        )

    def test_buckets_across_a_midnight_boundary(self) -> None:
        lines = [
            '203.0.113.7 - - [11/Mar/2024:23:59:59 +0000] "GET /a HTTP/1.1" 200 1',
            '203.0.113.7 - - [12/Mar/2024:00:00:00 +0000] "GET /b HTTP/1.1" 200 1',
        ]
        buckets = per_minute_counts(entries_from("\n".join(lines)))
        self.assertEqual(len(buckets), 2)
        self.assertEqual(buckets[0][0].day, 11)
        self.assertEqual(buckets[1][0].day, 12)

    def test_different_offsets_share_a_bucket_when_instants_match(self) -> None:
        # 09:15+00:00 and 04:15-05:00 are the same instant, so one bucket.
        lines = [
            '203.0.113.7 - - [12/Mar/2024:09:15:30 +0000] "GET /a HTTP/1.1" 200 1',
            '198.51.100.1 - - [12/Mar/2024:04:15:45 -0500] "GET /b HTTP/1.1" 200 1',
        ]
        buckets = per_minute_counts(entries_from("\n".join(lines)))
        self.assertEqual(len(buckets), 1)
        self.assertEqual(buckets[0][1], 2)


class ByteTotalTests(unittest.TestCase):
    """Byte totals skip the "-" placeholder and average only real bodies."""

    def test_totals_from_the_sample(self) -> None:
        total, count, average = byte_totals(entries_from())
        self.assertEqual(total, 6076)
        self.assertEqual(count, 8)
        self.assertEqual(average, 759.5)

    def test_missing_size_is_excluded_from_the_average(self) -> None:
        lines = [
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET /a HTTP/1.1" 200 100',
            '203.0.113.7 - - [12/Mar/2024:09:15:04 +0000] "POST /b HTTP/1.1" 401 -',
        ]
        self.assertEqual(byte_totals(entries_from("\n".join(lines))), (100, 1, 100.0))

    def test_zero_byte_responses_count(self) -> None:
        lines = ['203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET /a HTTP/1.1" 301 0']
        self.assertEqual(byte_totals(entries_from("\n".join(lines))), (0, 1, 0.0))

    def test_empty_input_is_all_zeroes(self) -> None:
        self.assertEqual(byte_totals([]), (0, 0, 0.0))


class SlowestTests(unittest.TestCase):
    """Only entries with a recorded duration are ranked."""

    def test_slowest_are_sorted_descending(self) -> None:
        lines = [
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET /fast HTTP/1.1" 200 1 "-" "-" "0.010"',
            '203.0.113.7 - - [12/Mar/2024:09:15:04 +0000] "GET /slow HTTP/1.1" 200 1 "-" "-" "2.500"',
            '203.0.113.7 - - [12/Mar/2024:09:15:05 +0000] "GET /mid HTTP/1.1" 200 1 "-" "-" "0.900"',
        ]
        ranked = slowest_entries(entries_from("\n".join(lines)), 3)
        self.assertEqual([duration for _, duration in ranked], [2.5, 0.9, 0.01])

    def test_entries_without_duration_are_skipped(self) -> None:
        ranked = slowest_entries(entries_from(), 5)
        self.assertEqual(ranked, [])

    def test_ties_keep_file_order(self) -> None:
        lines = [
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET /first HTTP/1.1" 200 1 "-" "-" "1.0"',
            '203.0.113.7 - - [12/Mar/2024:09:15:04 +0000] "GET /second HTTP/1.1" 200 1 "-" "-" "1.0"',
        ]
        ranked = slowest_entries(entries_from("\n".join(lines)), 2)
        self.assertEqual([entry.path for entry, _ in ranked], ["/first", "/second"])

    def test_top_limits_results(self) -> None:
        lines = [
            f'203.0.113.7 - - [12/Mar/2024:09:15:0{second} +0000] '
            f'"GET /p{second} HTTP/1.1" 200 1 "-" "-" "0.0{second}"'
            for second in range(3)
        ]
        self.assertEqual(len(slowest_entries(entries_from("\n".join(lines)), 2)), 2)


class BuildSummaryTests(unittest.TestCase):
    """The full summary is internally consistent and empty-safe."""

    def test_summary_of_the_sample(self) -> None:
        result = parse_lines(SAMPLE_LOG.splitlines())
        summary = build_summary(result.entries, top=5, malformed_lines=len(result.errors))
        self.assertIsInstance(summary, Aggregate)
        self.assertEqual(summary.total_requests, 10)
        self.assertEqual(summary.total_lines, 11)
        self.assertEqual(summary.malformed_lines, 1)
        self.assertEqual(summary.unique_paths, 6)
        self.assertEqual(summary.unique_clients, 5)
        self.assertEqual(summary.bytes_total, 6076)

    def test_time_span_covers_first_and_last(self) -> None:
        summary = build_summary(entries_from())
        self.assertEqual(
            summary.first_seen, datetime(2024, 3, 12, 9, 15, 3, tzinfo=timezone.utc)
        )
        self.assertEqual(
            summary.last_seen, datetime(2024, 3, 12, 9, 19, 58, tzinfo=timezone.utc)
        )

    def test_status_codes_sorted_ascending(self) -> None:
        codes = [code for code, _ in build_summary(entries_from()).status_codes]
        self.assertEqual(codes, sorted(codes))
        self.assertEqual(codes, [200, 301, 304, 401, 403, 404, 500])
        self.assertEqual(dict(build_summary(entries_from()).status_codes)[200], 4)

    def test_empty_summary_is_zeroed_not_broken(self) -> None:
        summary = build_summary([])
        self.assertEqual(summary.total_requests, 0)
        self.assertIsNone(summary.first_seen)
        self.assertIsNone(summary.last_seen)
        self.assertEqual(summary.per_minute, [])
        self.assertEqual(summary.top_paths, [])
        self.assertEqual(summary.status_classes, [])
        self.assertEqual(summary.bytes_avg, 0.0)
        self.assertEqual(summary.duration, (0.0, 0.0))

    def test_top_argument_caps_stored_rows(self) -> None:
        summary = build_summary(entries_from(), top=2)
        self.assertEqual(len(summary.top_paths), 2)
        self.assertEqual(len(summary.top_clients), 2)

    def test_summary_dict_is_json_serialisable(self) -> None:
        import json

        payload = summary_to_dict(build_summary(entries_from(), top=3))
        text = json.dumps(payload)  # must not raise
        self.assertIn("total_requests", text)
        self.assertEqual(payload["status_classes"], {"2xx": 4, "3xx": 2, "4xx": 3, "5xx": 1})
        self.assertEqual(len(payload["top_paths"]), 3)
        self.assertEqual(payload["per_minute"][0]["minute"], "2024-03-12T09:15:00+00:00")

    def test_summary_dict_top_zero_omits_rankings(self) -> None:
        payload = summary_to_dict(build_summary(entries_from()), top=0)
        self.assertEqual(payload["top_paths"], [])
        self.assertEqual(payload["top_clients"], [])
        self.assertEqual(payload["slowest"], [])


if __name__ == "__main__":
    unittest.main()