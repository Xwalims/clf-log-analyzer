"""End-to-end tests for the command-line interface.

Each test runs the module in a real subprocess against a real temporary log
file and asserts on the actual stdout, exit status and stderr, so the
documented exit-code contract is verified rather than assumed.
"""

from __future__ import annotations

import gzip
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from .fixtures import SAMPLE_LOG, write_sample_log

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODULE = "clf_log_analyzer.cli"


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the CLI in a subprocess from the project root.

    Args:
        *args: Arguments passed after the module name.

    Returns:
        The completed process, with decoded text output.
    """
    return subprocess.run(
        [sys.executable, "-m", MODULE, *args],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


class CliEndToEndTests(unittest.TestCase):
    """Real subprocess runs against real files on disk."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.tmp_path = Path(self.tmp.name)
        self.log = write_sample_log(self.tmp_path / "access.log")

    def test_help_exits_zero_and_lists_flags(self) -> None:
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0)
        for flag in ("--format", "--top", "--chart", "--json", "--strict"):
            self.assertIn(flag, result.stdout)
        self.assertIn("LOGFILE", result.stdout)

    def test_default_report_on_the_sample_log(self) -> None:
        result = run_cli(str(self.log))
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "")
        self.assertIn("clf-log-analyzer", result.stdout)
        self.assertIn("Requests", result.stdout)
        self.assertIn("10", result.stdout)
        self.assertIn("Status classes", result.stdout)
        self.assertIn("/index.html", result.stdout)

    def test_report_is_deterministic_across_runs(self) -> None:
        first = run_cli(str(self.log))
        second = run_cli(str(self.log))
        self.assertEqual(first.stdout, second.stdout)

    def test_malformed_lines_reported_but_exit_zero(self) -> None:
        result = run_cli(str(self.log))
        self.assertEqual(result.returncode, 0)
        self.assertIn("Malformed lines (1 shown)", result.stdout)
        self.assertIn("not a log line", result.stdout)

    def test_strict_mode_exits_one_on_malformed_lines(self) -> None:
        result = run_cli(str(self.log), "--strict")
        self.assertEqual(result.returncode, 1)
        self.assertIn("malformed line", result.stderr)

    def test_strict_mode_exits_zero_on_a_clean_log(self) -> None:
        clean = write_sample_log(
            self.tmp_path / "clean.log", SAMPLE_LOG.split("###")[0]
        )
        result = run_cli(str(clean), "--strict")
        self.assertEqual(result.returncode, 0)

    def test_json_output_is_valid_and_machine_readable(self) -> None:
        result = run_cli(str(self.log), "--json")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["total_requests"], 10)
        self.assertEqual(payload["malformed_lines"], 1)
        self.assertEqual(payload["status_classes"], {"2xx": 4, "3xx": 2, "4xx": 3, "5xx": 1})
        self.assertEqual(payload["bytes"]["total"], 6076)
        self.assertEqual(payload["error_count"], 1)
        self.assertEqual(len(payload["per_minute"]), 5)

    def test_json_output_is_deterministic(self) -> None:
        first = run_cli(str(self.log), "--json")
        second = run_cli(str(self.log), "--json")
        self.assertEqual(first.stdout, second.stdout)

    def test_top_limits_the_ranking_rows(self) -> None:
        text = run_cli(str(self.log), "--top", "2").stdout
        self.assertIn("Top 2 paths", text)
        payload = json.loads(run_cli(str(self.log), "--top", "2", "--json").stdout)
        self.assertEqual(len(payload["top_paths"]), 2)
        self.assertEqual(len(payload["top_clients"]), 2)

    def test_chart_none_omits_the_time_series(self) -> None:
        text = run_cli(str(self.log), "--chart", "none").stdout
        self.assertNotIn("Requests per minute", text)

    def test_chart_bars_renders_the_time_series(self) -> None:
        text = run_cli(str(self.log), "--chart", "bars").stdout
        self.assertIn("Requests per minute (5 buckets)", text)
        self.assertIn("09:15", text)

    def test_chart_sparkline_is_the_default(self) -> None:
        text = run_cli(str(self.log)).stdout
        self.assertIn("Requests per minute (5 buckets)", text)

    def test_gzip_log_is_analyzed_identically(self) -> None:
        gz_path = self.tmp_path / "access.log.gz"
        with gzip.open(gz_path, "wt", encoding="utf-8") as handle:
            handle.write(SAMPLE_LOG)
        plain = run_cli(str(self.log), "--json")
        compressed = run_cli(str(gz_path), "--json")
        self.assertEqual(compressed.returncode, 0)
        self.assertEqual(json.loads(plain.stdout)["total_requests"],
                         json.loads(compressed.stdout)["total_requests"])

    def test_empty_log_produces_a_report_and_exits_zero(self) -> None:
        empty = write_sample_log(self.tmp_path / "empty.log", "")
        result = run_cli(str(empty))
        self.assertEqual(result.returncode, 0)
        self.assertIn("Requests", result.stdout)
        payload = json.loads(run_cli(str(empty), "--json").stdout)
        self.assertEqual(payload["total_requests"], 0)
        self.assertIsNone(payload["first_seen"])

    def test_missing_file_exits_two(self) -> None:
        result = run_cli(str(self.tmp_path / "nope.log"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("no such file", result.stderr)

    def test_directory_argument_exits_two(self) -> None:
        result = run_cli(str(self.tmp_path))
        self.assertEqual(result.returncode, 2)
        self.assertIn("is a directory", result.stderr)

    def test_unknown_format_exits_two(self) -> None:
        result = run_cli(str(self.log), "-f", "bogus")
        self.assertEqual(result.returncode, 2)

    def test_missing_argument_exits_two(self) -> None:
        self.assertEqual(run_cli().returncode, 2)

    def test_negative_top_exits_two(self) -> None:
        result = run_cli(str(self.log), "--top", "-1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("must not be negative", result.stderr)

    def test_common_format_flag_rejects_combined_input(self) -> None:
        result = run_cli(str(self.log), "-f", "common", "--strict")
        self.assertEqual(result.returncode, 1)

    def test_version_flag_exits_zero(self) -> None:
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertIn("clf-log-analyzer", result.stdout)


class CliInProcessTests(unittest.TestCase):
    """Direct calls to main() so return codes can be asserted without a fork."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = write_sample_log(Path(self.tmp.name) / "access.log")

    def test_main_returns_zero_on_success(self) -> None:
        from clf_log_analyzer.cli import main

        self.assertEqual(main([str(self.log), "--chart", "none"]), 0)

    def test_main_returns_two_on_missing_file(self) -> None:
        from clf_log_analyzer.cli import main

        self.assertEqual(main([str(Path(self.tmp.name) / "absent.log")]), 2)

    def test_parser_defaults_are_documented(self) -> None:
        from clf_log_analyzer.cli import build_parser

        args = build_parser().parse_args(["x.log"])
        self.assertEqual(args.log_format, "auto")
        self.assertEqual(args.chart, "sparkline")
        self.assertEqual(args.top, 10)
        self.assertFalse(args.as_json)
        self.assertFalse(args.strict)


if __name__ == "__main__":
    unittest.main()