"""Tests for :mod:`clf_log_analyzer.chart`.

Covers fixed-width rendering, determinism across repeated runs, the empty
input edge cases and label truncation.
"""

from __future__ import annotations

import unittest

from clf_log_analyzer.chart import (
    SPARK_CHARS,
    bar_chart,
    format_count,
    render_bars,
    render_sparkline,
    sparkline,
    truncate_label,
)

SERIES = [("09:15", 3), ("09:16", 2), ("09:17", 1), ("09:18", 2), ("09:19", 2)]


class SparklineTests(unittest.TestCase):
    """A sparkline renders one character per value, scaled to the peak."""

    def test_one_character_per_value(self) -> None:
        self.assertEqual(len(sparkline([1, 2, 3])), 3)

    def test_peak_maps_to_the_fullest_glyph(self) -> None:
        self.assertEqual(sparkline([5, 5])[0], SPARK_CHARS[-1])

    def test_smallest_value_maps_to_the_sparsest_glyph(self) -> None:
        # Scaling is relative to the peak, so a value far below it renders
        # as the first (blank) glyph rather than vanishing.
        self.assertEqual(sparkline([1, 100])[0], SPARK_CHARS[0])

    def test_mid_values_use_middle_glyphs(self) -> None:
        self.assertIn(sparkline([1, 100])[0], SPARK_CHARS)
        self.assertEqual(sparkline([50, 100])[0], sparkline([50, 100])[0])

    def test_all_zero_series_renders_without_dividing_by_zero(self) -> None:
        self.assertEqual(sparkline([0, 0, 0]), SPARK_CHARS[0] * 3)

    def test_single_value_renders(self) -> None:
        self.assertEqual(len(sparkline([7])), 1)

    def test_empty_series_returns_the_placeholder(self) -> None:
        self.assertEqual(sparkline([]), "(no data)")

    def test_empty_placeholder_is_configurable(self) -> None:
        self.assertEqual(sparkline([], empty="none"), "none")

    def test_rendering_is_deterministic(self) -> None:
        values = [3, 9, 1, 7, 4, 4, 2]
        first = sparkline(values)
        for _ in range(10):
            self.assertEqual(sparkline(values), first)

    def test_rendering_is_order_sensitive(self) -> None:
        self.assertNotEqual(sparkline([1, 9]), sparkline([9, 1]))


class RenderSparklineTests(unittest.TestCase):
    """The labelled block is fixed width and lists counts alongside."""

    def test_block_has_one_row_per_bucket(self) -> None:
        self.assertEqual(len(render_sparkline(SERIES).splitlines()), len(SERIES))

    def test_rows_include_labels_and_counts(self) -> None:
        block = render_sparkline(SERIES)
        self.assertIn("09:15", block)
        self.assertIn("3", block)

    def test_block_is_deterministic(self) -> None:
        first = render_sparkline(SERIES)
        for _ in range(5):
            self.assertEqual(render_sparkline(SERIES), first)

    def test_empty_series_returns_the_placeholder(self) -> None:
        self.assertEqual(render_sparkline([]), "(no data)")

    def test_long_series_collapses_to_the_requested_width(self) -> None:
        long_series = [(f"{index // 60:02d}:{index % 60:02d}", 1) for index in range(600)]
        for line in render_sparkline(long_series, width=40).splitlines():
            self.assertLessEqual(len(line), 60)

    def test_minimum_width_is_respected(self) -> None:
        self.assertTrue(render_sparkline(SERIES, width=1).splitlines())


class BarChartTests(unittest.TestCase):
    """Bar charts align labels, scale to the peak and tolerate empty input."""

    def test_one_row_per_item(self) -> None:
        self.assertEqual(len(bar_chart([("/a", 1), ("/b", 2)]).splitlines()), 2)

    def test_rows_are_left_aligned_to_equal_width(self) -> None:
        rows = [("/short", 1), ("/a-much-longer-path", 2)]
        widths = {len(line) for line in bar_chart(rows, width=10).splitlines()}
        self.assertEqual(len(widths), 1)

    def test_largest_value_fills_the_bar(self) -> None:
        chart = bar_chart([("/a", 1), ("/b", 10)], width=10)
        self.assertIn("█" * 10, chart)

    def test_zero_values_render_an_empty_bar_without_crashing(self) -> None:
        self.assertEqual(len(bar_chart([("/a", 0)]).splitlines()), 1)

    def test_all_zero_series_does_not_divide_by_zero(self) -> None:
        self.assertEqual(len(bar_chart([("/a", 0), ("/b", 0)]).splitlines()), 2)

    def test_empty_input_returns_empty_string(self) -> None:
        self.assertEqual(bar_chart([]), "")

    def test_ascii_mode_avoids_block_glyphs(self) -> None:
        chart = bar_chart([("/a", 1), ("/b", 2)], ascii_only=True)
        self.assertNotIn("█", chart)
        self.assertIn("#", chart)

    def test_rendering_is_deterministic(self) -> None:
        rows = [("/index.html", 3), ("/style.css", 2), ("/health", 1)]
        first = bar_chart(rows)
        for _ in range(5):
            self.assertEqual(bar_chart(rows), first)

    def test_counts_are_rendered_with_separators(self) -> None:
        self.assertIn("1,234", bar_chart([("/a", 1234)]))


class RenderBarsTests(unittest.TestCase):
    """The titled wrapper adds a heading and a peak footer."""

    def test_title_and_footer_present(self) -> None:
        block = render_bars([("/a", 4), ("/b", 8)], title="Top paths")
        lines = block.splitlines()
        self.assertEqual(lines[0], "Top paths")
        self.assertIn("peak: 8", lines[-1])

    def test_empty_rows_with_title_is_placeholder(self) -> None:
        self.assertEqual(render_bars([], title="Top paths"), "(no data)")

    def test_empty_rows_without_title_is_empty(self) -> None:
        self.assertEqual(render_bars([]), "")


class HelperTests(unittest.TestCase):
    """Small helpers behave predictably at their edges."""

    def test_format_count_uses_separators(self) -> None:
        self.assertEqual(format_count(1234567), "1,234,567")

    def test_format_count_rounds_floats_to_two_places(self) -> None:
        self.assertEqual(format_count(995.0), "995")
        self.assertEqual(format_count(12.345), "12.35")

    def test_format_count_normalises_negative_zero(self) -> None:
        self.assertEqual(format_count(-0.0), "0")

    def test_truncate_keeps_short_labels(self) -> None:
        self.assertEqual(truncate_label("/a", 10), "/a")

    def test_truncate_keeps_the_tail_of_a_long_path(self) -> None:
        self.assertEqual(truncate_label("/very/long/path/index.html", 12), "...ndex.html")

    def test_truncate_result_never_exceeds_width(self) -> None:
        for width in range(3, 20):
            self.assertLessEqual(len(truncate_label("/a/very/long/path", width)), width)

    def test_truncate_handles_degenerate_widths(self) -> None:
        self.assertEqual(truncate_label("/abcdef", 1), "...")
        self.assertEqual(truncate_label("/abcdef", 0), "...")


if __name__ == "__main__":
    unittest.main()