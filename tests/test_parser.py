"""Tests for :mod:`clf_log_analyzer.parser`.

Covers the happy path, quoted fields containing spaces, IPv6 clients, the
``-`` missing-size placeholder, malformed-line collection, timezone-aware
timestamps and gzip-transparent file reading.
"""

from __future__ import annotations

import gzip
import random
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from clf_log_analyzer.parser import (
    FORMAT_COMBINED,
    FORMAT_COMMON,
    Entry,
    MalformedLineError,
    MAX_OFFSET_MINUTES,
    ParseError,
    clean_host,
    detect_format,
    iter_entries,
    open_log,
    parse_file,
    parse_line,
    parse_lines,
)

COMMON_LINE = '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET /index.html HTTP/1.1" 200 512'
COMBINED_LINE = (
    '203.0.113.7 - frank [12/Mar/2024:09:15:03 -0500] "GET /a/b?q=1 HTTP/1.1" 200 512 '
    '"https://example.com/start" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"'
)
IPV6_LINE = (
    '2001:db8:85a3::8a2e:370:7334 - - [01/Jan/2025:23:59:59 +0000] '
    '"GET / HTTP/1.1" 200 1024 "-" "curl/8.5.0"'
)
NO_SIZE_LINE = (
    '198.51.100.22 - - [12/Mar/2024:09:16:10 +0000] "POST /api/v1/login HTTP/1.1" 401 - '
    '"-" "PostmanRuntime/7.37.0"'
)


class ParseLineHappyPathTests(unittest.TestCase):
    """A well-formed common-format line parses into every documented field."""

    def test_common_line_fields(self) -> None:
        entry = parse_line(COMMON_LINE, FORMAT_COMMON, line_number=1)
        self.assertIsInstance(entry, Entry)
        self.assertEqual(entry.ip, "203.0.113.7")
        self.assertEqual(entry.ident, "-")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/index.html")
        self.assertEqual(entry.protocol, "HTTP/1.1")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.size, 512)
        self.assertIsNone(entry.referer)
        self.assertIsNone(entry.user_agent)
        self.assertEqual(entry.line_number, 1)
        self.assertEqual(entry.raw, COMMON_LINE)

    def test_combined_line_fields(self) -> None:
        entry = parse_line(COMBINED_LINE, FORMAT_COMBINED)
        self.assertEqual(entry.ip, "203.0.113.7")
        self.assertEqual(entry.ident, "-")
        self.assertEqual(entry.method, "GET")
        self.assertEqual(entry.path, "/a/b?q=1")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.size, 512)
        self.assertEqual(entry.referer, "https://example.com/start")
        self.assertEqual(entry.user_agent, "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

    def test_trailing_newline_is_stripped_from_raw(self) -> None:
        entry = parse_line(COMMON_LINE + "\n")
        self.assertEqual(entry.raw, COMMON_LINE)

    def test_status_class_property(self) -> None:
        self.assertEqual(parse_line(COMMON_LINE).status_class, "2xx")
        self.assertEqual(parse_line(NO_SIZE_LINE).status_class, "4xx")

    def test_minute_property_truncates_seconds(self) -> None:
        entry = parse_line(COMMON_LINE)
        self.assertEqual(entry.minute, datetime(2024, 3, 12, 9, 15, tzinfo=timezone.utc))

    def test_as_dict_is_json_friendly(self) -> None:
        payload = parse_line(COMBINED_LINE).as_dict()
        self.assertEqual(payload["status"], 200)
        self.assertEqual(payload["status_class"], "2xx")
        self.assertEqual(payload["path"], "/a/b?q=1")


class QuotedFieldTests(unittest.TestCase):
    """Quoted fields containing spaces and escaped quotes survive intact."""

    def test_user_agent_with_spaces(self) -> None:
        line = (
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET / HTTP/1.1" 200 10 '
            '"-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/122.0"'
        )
        entry = parse_line(line)
        self.assertEqual(
            entry.user_agent,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/122.0",
        )

    def test_path_containing_escaped_quotes(self) -> None:
        line = (
            r'203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] '
            r'"GET /search?q=%22nginx%22 HTTP/1.1" 200 10 "-" "curl/8.5.0"'
        )
        entry = parse_line(line)
        self.assertEqual(entry.path, '/search?q=%22nginx%22')

    def test_literal_quote_inside_user_agent(self) -> None:
        line = (
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET / HTTP/1.1" 200 10 '
            '"-" "Agent \\"quoted\\" 1.0"'
        )
        self.assertEqual(parse_line(line).user_agent, 'Agent "quoted" 1.0')

    def test_nginx_hex_escape_is_decoded(self) -> None:
        line = (
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET / HTTP/1.1" 200 10 '
            '"-" "curl\\x2f8.5.0"'
        )
        self.assertEqual(parse_line(line).user_agent, "curl/8.5.0")

    def test_nginx_request_time_field_is_captured(self) -> None:
        line = COMMON_LINE + ' "-" "curl/8.5.0" "0.042"'
        entry = parse_line(line)
        self.assertEqual(entry.duration, 0.042)
        self.assertEqual(entry.user_agent, "curl/8.5.0")

    def test_request_time_after_a_common_line_is_ignored(self) -> None:
        # A common-format line with one extra quoted field is not combined;
        # auto mode reads the field but finds no referer/user-agent pair.
        entry = parse_line(COMMON_LINE + ' "0.042"')
        self.assertEqual(entry.duration, 0.042)
        self.assertIsNone(entry.referer)


class IPv6Tests(unittest.TestCase):
    """IPv6 clients parse bare and in Apache's bracketed form."""

    def test_bare_ipv6_client(self) -> None:
        entry = parse_line(IPV6_LINE)
        self.assertEqual(entry.ip, "2001:db8:85a3::8a2e:370:7334")
        self.assertEqual(entry.status, 200)
        self.assertEqual(entry.user_agent, "curl/8.5.0")

    def test_bracketed_ipv6_client_is_unwrapped(self) -> None:
        line = (
            '[2001:db8:85a3::8a2e:370:7334] - - [01/Jan/2025:23:59:59 +0000] '
            '"GET / HTTP/1.1" 200 1024 "-" "curl/8.5.0"'
        )
        self.assertEqual(parse_line(line).ip, "2001:db8:85a3::8a2e:370:7334")

    def test_clean_host_rejects_whitespace(self) -> None:
        self.assertEqual(clean_host("[::1]"), "::1")
        with self.assertRaises(MalformedLineError):
            clean_host("bad host")

    def test_ipv6_and_ipv4_clients_coexist(self) -> None:
        result = parse_lines([IPV6_LINE, COMMON_LINE])
        self.assertEqual([e.ip for e in result.entries], ["2001:db8:85a3::8a2e:370:7334", "203.0.113.7"])


class MissingSizeTests(unittest.TestCase):
    """A ``-`` byte count becomes ``None`` rather than zero."""

    def test_missing_size_is_none(self) -> None:
        entry = parse_line(NO_SIZE_LINE)
        self.assertIsNone(entry.size)
        self.assertEqual(entry.status, 401)

    def test_missing_referer_and_useragent_are_none(self) -> None:
        entry = parse_line(
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET / HTTP/1.1" 304 - "-" "-"'
        )
        self.assertIsNone(entry.referer)
        self.assertIsNone(entry.user_agent)

    def test_non_numeric_size_is_malformed(self) -> None:
        bad = COMMON_LINE.replace(" 200 512", " 200 abc")
        with self.assertRaises(MalformedLineError) as ctx:
            parse_line(bad)
        self.assertIn("not a number", str(ctx.exception))

    def test_dash_request_line_yields_placeholders(self) -> None:
        entry = parse_line(
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "-" 408 - "-" "curl/8.5.0"'
        )
        self.assertEqual((entry.method, entry.path, entry.protocol), ("-", "-", "-"))


class TimestampTests(unittest.TestCase):
    """Timestamps are timezone aware and offset-aware."""

    def test_positive_offset(self) -> None:
        entry = parse_line(COMBINED_LINE)
        self.assertEqual(entry.timestamp.utcoffset(), timedelta(hours=-5))
        self.assertEqual(
            entry.timestamp.astimezone(timezone.utc),
            datetime(2024, 3, 12, 14, 15, 3, tzinfo=timezone.utc),
        )

    def test_missing_offset_defaults_to_utc(self) -> None:
        entry = parse_line(
            '203.0.113.7 - - [12/Mar/2024:09:15:03] "GET / HTTP/1.1" 200 5'
        )
        self.assertEqual(entry.timestamp.tzinfo, timezone.utc)
        self.assertEqual(entry.timestamp.utcoffset(), timedelta(0))

    def test_compact_offset_form_is_accepted(self) -> None:
        entry = parse_line(
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +0200] "GET / HTTP/1.1" 200 5'
        )
        self.assertEqual(entry.timestamp.utcoffset(), timedelta(hours=2))

    def test_month_is_matched_case_insensitively(self) -> None:
        entry = parse_line(
            '203.0.113.7 - - [12/mar/2024:09:15:03 +0000] "GET / HTTP/1.1" 200 5'
        )
        self.assertEqual(entry.timestamp.month, 3)

    def test_unknown_month_is_malformed(self) -> None:
        with self.assertRaises(MalformedLineError):
            parse_line(COMBINED_LINE.replace("Mar", "Foo"))

    def test_impossible_day_is_malformed(self) -> None:
        with self.assertRaises(MalformedLineError):
            parse_line(COMBINED_LINE.replace("12/Mar", "31/Feb"))

    def test_leap_day_is_accepted(self) -> None:
        entry = parse_line(
            '203.0.113.7 - - [29/Feb/2024:23:59:59 +0000] "GET / HTTP/1.1" 200 5'
        )
        self.assertEqual(entry.timestamp.day, 29)

    def test_epoch_is_preserved_exactly(self) -> None:
        entry = parse_line(
            '203.0.113.7 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.1" 200 5'
        )
        self.assertEqual(
            entry.timestamp.astimezone(timezone.utc),
            datetime(2000, 10, 10, 20, 55, 36, tzinfo=timezone.utc),
        )


class MalformedLineTests(unittest.TestCase):
    """Malformed lines are collected, never raised, in non-strict mode."""

    def test_errors_are_collected_not_raised(self) -> None:
        result = parse_lines([COMMON_LINE, "this is not a log line", COMBINED_LINE])
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(len(result.errors), 1)
        self.assertIsInstance(result.errors[0], ParseError)
        self.assertEqual(result.errors[0].line_number, 2)
        self.assertEqual(result.errors[0].raw, "this is not a log line")

    def test_total_lines_counts_parsed_plus_failed(self) -> None:
        result = parse_lines([COMMON_LINE, "garbage", "", "   ", COMBINED_LINE])
        self.assertEqual(result.total_lines, 3)
        self.assertEqual(len(result), 2)

    def test_blank_lines_are_skipped_silently(self) -> None:
        result = parse_lines(["", "   ", "\n"])
        self.assertEqual(result.entries, [])
        self.assertEqual(result.errors, [])

    def test_strict_mode_raises_on_first_bad_line(self) -> None:
        with self.assertRaises(MalformedLineError) as ctx:
            parse_lines([COMMON_LINE, "nonsense", COMBINED_LINE], strict=True)
        self.assertEqual(ctx.exception.line_number, 2)

    def test_bad_status_code_is_rejected(self) -> None:
        with self.assertRaises(MalformedLineError):
            parse_line(COMMON_LINE.replace("200 512", "20x 512"))

    def test_missing_status_field_is_rejected(self) -> None:
        with self.assertRaises(MalformedLineError):
            parse_line('203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET / HTTP/1.1"')

    def test_unterminated_quote_is_rejected(self) -> None:
        with self.assertRaises(MalformedLineError):
            parse_line('203.0.113.7 - - [12/Mar/2024:09:15:03 +0000] "GET / HTTP/1.1 200 5')

    def test_common_format_rejects_combined_line(self) -> None:
        with self.assertRaises(MalformedLineError) as ctx:
            parse_line(COMBINED_LINE, FORMAT_COMMON)
        self.assertIn("combined fields present", str(ctx.exception))

    def test_combined_format_requires_extras(self) -> None:
        with self.assertRaises(MalformedLineError):
            parse_line(COMMON_LINE, FORMAT_COMBINED)

    def test_unexpected_trailing_content_is_rejected(self) -> None:
        with self.assertRaises(MalformedLineError):
            parse_line(COMBINED_LINE + " junk junk")

    def test_iter_entries_skips_malformed(self) -> None:
        entries = list(iter_entries([COMMON_LINE, "nope", COMBINED_LINE]))
        self.assertEqual(len(entries), 2)


class DetectFormatTests(unittest.TestCase):
    """Format sniffing is structural and stable."""

    def test_common_line_detected(self) -> None:
        self.assertEqual(detect_format(COMMON_LINE), FORMAT_COMMON)

    def test_combined_line_detected(self) -> None:
        self.assertEqual(detect_format(COMBINED_LINE), FORMAT_COMBINED)

    def test_detection_is_deterministic(self) -> None:
        self.assertEqual([detect_format(COMBINED_LINE) for _ in range(5)], [FORMAT_COMBINED] * 5)


class FileReadingTests(unittest.TestCase):
    """Files and gzip-compressed files are both read transparently."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "access.log"
        self.gz_path = Path(self.tmp.name) / "access.log.gz"

    def test_parse_plain_file(self) -> None:
        self.path.write_text(COMMON_LINE + "\n" + COMBINED_LINE + "\n", encoding="utf-8")
        result = parse_file(self.path)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.errors, [])

    def test_parse_gzip_file_transparently(self) -> None:
        with gzip.open(self.gz_path, "wt", encoding="utf-8") as handle:
            handle.write(COMBINED_LINE + "\n")
            handle.write(COMMON_LINE + "\n")
        with open_log(self.gz_path) as handle:
            result = parse_lines(handle)
        self.assertEqual(len(result.entries), 2)
        self.assertEqual(result.entries[0].ip, "203.0.113.7")

    def test_gzip_detected_by_magic_not_extension(self) -> None:
        misnamed = Path(self.tmp.name) / "plain.log"
        with gzip.open(self.gz_path, "wt", encoding="utf-8") as handle:
            handle.write(COMMON_LINE + "\n")
        misnamed.write_bytes(self.gz_path.read_bytes())
        self.assertEqual(len(parse_file(misnamed).entries), 1)

    def test_open_log_reports_missing_file(self) -> None:
        with self.assertRaises(FileNotFoundError):
            open_log(Path(self.tmp.name) / "does-not-exist.log")

    def test_invalid_utf8_byte_does_not_crash(self) -> None:
        self.path.write_bytes(
            COMMON_LINE.encode("utf-8") + b"\xff\xfe\n" + COMBINED_LINE.encode("utf-8") + b"\n"
        )
        result = parse_file(self.path)
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(len(result.errors), 1)


class NonDecimalDigitTests(unittest.TestCase):
    """Numeric-looking characters that ``int()`` rejects are malformed lines.

    ``str.isdigit()`` is true for superscripts, circled digits and the other
    numeric-number characters, but ``int()`` refuses them.  Guarding with
    ``isdigit()`` therefore turned a corrupt log line into an unhandled
    ``ValueError`` that aborted the whole analysis, which is exactly what this
    tool promises never to do.
    """

    #: One representative of every block of Unicode characters for which
    #: ``isdigit()`` is true but ``int()`` raises -- 128 codepoints in ten
    #: blocks.  Escapes rather than literals so the file stays pure ASCII.
    LIARS = [
        "\U000000b2",  # superscript two
        "\U00001369",  # Ethiopic digit one
        "\U000019da",  # New Tai Lue digit five
        "\U00002070",  # superscript zero
        "\U00002460",  # circled digit one
        "\U00002776",  # dingbat negative circled digit one
        "\U00010a40",  # Kharoshthi digit one
        "\U00010e60",  # Rumi digit one
        "\U00011052",  # Brahmi digit one
        "\U0001f100",  # digit zero full stop
    ]

    def line_with(self, field: str, token: str) -> str:
        """Return a valid line with *token* substituted into *field*."""
        base = '203.0.113.7 - - [12/Mar/2024:09:15:03 {off}] "GET / HTTP/1.1" {status} {size}'
        return base.format(off=token if field == "offset" else "+0000",
                           status=token if field == "status" else "200",
                           size=token if field == "size" else "512")

    def test_isdigit_is_the_wrong_guard(self) -> None:
        """The premise: ``isdigit()`` accepts what ``int()`` rejects."""
        for liar in self.LIARS:
            with self.subTest(character=liar):
                self.assertTrue(liar.isdigit())
                with self.assertRaises(ValueError):
                    int(liar)

    def test_status_with_non_decimal_digit_is_collected(self) -> None:
        for liar in self.LIARS:
            with self.subTest(character=liar):
                result = parse_lines([self.line_with("status", liar + "00"), COMMON_LINE])
                self.assertEqual(len(result.entries), 1)
                self.assertEqual(len(result.errors), 1)

    def test_size_with_non_decimal_digit_is_collected(self) -> None:
        for liar in self.LIARS:
            with self.subTest(character=liar):
                result = parse_lines([self.line_with("size", liar * 3), COMMON_LINE])
                self.assertEqual(len(result.entries), 1)
                self.assertEqual(len(result.errors), 1)

    def test_offset_with_non_decimal_digit_is_collected(self) -> None:
        for liar in self.LIARS:
            with self.subTest(character=liar):
                result = parse_lines([self.line_with("offset", "+00" + liar * 2), COMMON_LINE])
                self.assertEqual(len(result.entries), 1)
                self.assertEqual(len(result.errors), 1)

    def test_timestamp_with_non_decimal_digit_is_collected(self) -> None:
        for liar in self.LIARS:
            with self.subTest(character=liar):
                line = f'203.0.113.7 - - [{liar * 2}/Mar/2024:09:15:03 +0000] "GET / HTTP/1.1" 200 512'
                result = parse_lines([line, COMMON_LINE])
                self.assertEqual(len(result.entries), 1)
                self.assertEqual(len(result.errors), 1)

    def test_every_liar_is_rejected_by_the_parser_directly(self) -> None:
        """``parse_line`` itself must raise the library's own error type."""
        for liar in self.LIARS:
            for field in ("status", "size", "offset"):
                with self.subTest(character=liar, field=field):
                    with self.assertRaises(MalformedLineError):
                        parse_line(self.line_with(field, liar + "00" if field == "status" else liar * 4))


class FullDayOffsetTests(unittest.TestCase):
    """A 24-hour offset is rejected by ``datetime``, so the parser must not
    hand it over.

    ``timezone()`` accepts strictly less than 24 hours, so ``+2400`` used to
    escape as an unhandled ``ValueError`` instead of becoming a malformed line.
    """

    def test_full_day_offset_is_malformed_not_a_crash(self) -> None:
        for sign in ("+", "-"):
            with self.subTest(sign=sign):
                line = f'203.0.113.7 - - [12/Mar/2024:09:15:03 {sign}2400] "GET / HTTP/1.1" 200 512'
                result = parse_lines([line, COMMON_LINE])
                self.assertEqual(len(result.entries), 1)
                self.assertEqual(len(result.errors), 1)
                self.assertIn("UTC offset", result.errors[0].message)

    def test_boundary_offset_is_still_accepted(self) -> None:
        """+2359 is the widest offset Python allows; it must still parse."""
        entry = parse_line(
            '203.0.113.7 - - [12/Mar/2024:09:15:03 +2359] "GET / HTTP/1.1" 200 512'
        )
        self.assertEqual(entry.timestamp.utcoffset(), timedelta(minutes=1439))

    def test_rejection_boundary_matches_the_construction(self) -> None:
        """Every offset above the limit fails; every one at or below succeeds."""
        for minutes in range(0, 24 * 60 + 1, 7):
            hh, mm = divmod(minutes, 60)
            token = f"+{hh:02d}{mm:02d}"
            with self.subTest(offset=token):
                line = f'203.0.113.7 - - [12/Mar/2024:09:15:03 {token}] "GET / HTTP/1.1" 200 512'
                if minutes <= MAX_OFFSET_MINUTES:
                    self.assertEqual(len(parse_lines([line]).entries), 1)
                else:
                    self.assertEqual(len(parse_lines([line]).errors), 1)

    def test_const_is_what_the_limit_needs_to_be(self) -> None:
        self.assertEqual(MAX_OFFSET_MINUTES, 1439)
        with self.assertRaises(ValueError):
            timezone(timedelta(minutes=MAX_OFFSET_MINUTES + 1))


class NeverFatalFuzzTests(unittest.TestCase):
    """The headline promise -- a bad line never aborts the analysis -- is
    property-based.

    ``parse_lines`` only catches :class:`MalformedLineError`, so any other
    exception escaping a single corrupt line is a real defect: it aborts a
    multi-gigabyte analysis over one bad byte.  The corpus is generated from a
    fixed seed so a failure is reproducible.
    """

    SEED = 20261003
    #: Deliberately nasty ingredients: every one has crashed something.
    ALPHABET = (
        list(' -"[]\\/:\t0123456789') + ["²", "①", "+2400", "-2400", "\x00", "\x7f", "é", "𝟘"]
    )

    def parse_or_note(self, line: str) -> None:
        """A line must parse or be collected -- never raise anything else.

        A whitespace-only line is the one documented exception: the parser
        skips blank lines without counting them, so nothing is expected back.
        """
        if not line.strip():
            self.assertEqual(parse_lines([line]).total_lines, 0)
            return
        try:
            result = parse_lines([line])
        except MalformedLineError:
            return  # only parse_lines, never parse_line, may raise this
        except Exception as exc:  # noqa: BLE001
            self.fail(f"line {line!r} escaped as {type(exc).__name__}: {exc}")
        self.assertEqual(
            len(result.entries) + len(result.errors), 1, f"line {line!r} vanished"
        )

    def test_random_soup(self) -> None:
        rng = random.Random(self.SEED)
        for _ in range(4000):
            length = rng.randint(0, 90)
            self.parse_or_note("".join(rng.choice(self.ALPHABET) for _ in range(length)))

    def test_mutations_of_a_real_line(self) -> None:
        rng = random.Random(self.SEED)
        for _ in range(4000):
            chars = list(COMBINED_LINE)
            for _ in range(rng.randint(1, 4)):
                index = rng.randrange(len(chars))
                action = rng.randint(0, 2)
                if action == 0:
                    chars[index] = rng.choice(self.ALPHABET)
                elif action == 1:
                    del chars[index]
                else:
                    chars.insert(index, rng.choice(self.ALPHABET))
            self.parse_or_note("".join(chars))

    def test_every_whole_hour_offset(self) -> None:
        """Sweep the offset field across its whole accepted and rejected span."""
        for sign in ("+", "-"):
            for hours in range(0, 100):
                line = f'203.0.113.7 - - [12/Mar/2024:09:15:03 {sign}{hours:02d}00] "GET / HTTP/1.1" 200 512'
                self.parse_or_note(line)

    def test_a_full_corrupt_file_still_reports_every_line(self) -> None:
        """A file of nothing but garbage yields one error per line, no crash."""
        rng = random.Random(self.SEED)
        garbage = [
            "".join(rng.choice(self.ALPHABET) for _ in range(rng.randint(1, 60)))
            for _ in range(500)
        ]
        # Blank lines are skipped by design, so drop the whitespace-only ones.
        garbage = [line for line in garbage if line.strip()]
        self.assertGreaterEqual(len(garbage), 490)
        result = parse_lines([*garbage, COMMON_LINE])
        self.assertEqual(len(result.entries), 1)
        self.assertEqual(len(result.errors), len(garbage))


if __name__ == "__main__":
    unittest.main()