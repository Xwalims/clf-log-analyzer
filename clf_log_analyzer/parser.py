"""Parser for Apache/nginx access logs in Common and Combined Log Format.

The parser is deliberately tolerant: a line that cannot be understood is
recorded as a :class:`ParseError` instead of raising, so a single corrupt
line never aborts an analysis of a multi-gigabyte log file.  Callers that
want fail-fast behaviour pass ``strict=True`` or call :func:`parse_line`
directly and catch :class:`MalformedLineError`.

Supported line shapes::

    host ident authuser [date] "request" status bytes
    host ident authuser [date] "request" status bytes "referer" "user-agent"

An optional further quoted field holding a request duration in seconds
(popular with nginx ``$request_time``) is recognised and stored on
:attr:`Entry.duration`.
"""

from __future__ import annotations

import gzip
import math
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import IO, Iterable, Iterator, Literal, Sequence

__all__ = [
    "Entry",
    "ParseError",
    "ParseResult",
    "MalformedLineError",
    "LogFormat",
    "FORMAT_AUTO",
    "FORMAT_COMMON",
    "FORMAT_COMBINED",
    "MONTHS",
    "MAX_OFFSET_MINUTES",
    "detect_format",
    "parse_line",
    "parse_lines",
    "iter_entries",
    "open_log",
    "parse_file",
    "format_errors",
]

LogFormat = Literal["auto", "common", "combined"]

FORMAT_AUTO = "auto"
FORMAT_COMMON = "common"
FORMAT_COMBINED = "combined"

#: Month abbreviations used by CLF timestamps, keyed lower-case.
MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

#: CLF placeholder meaning "field not applicable / not recorded".
MISSING = "-"

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\"}


class MalformedLineError(ValueError):
    """Raised by :func:`parse_line` when a single line cannot be parsed.

    Attributes:
        message: Human readable explanation.
        raw: The offending line, stripped of its trailing newline.
        line_number: 1-based line number when known, else ``0``.
    """

    def __init__(self, message: str, raw: str = "", line_number: int = 0) -> None:
        super().__init__(message)
        self.message = message
        self.raw = raw
        self.line_number = line_number

    def __str__(self) -> str:
        where = f"line {self.line_number}: " if self.line_number else ""
        return f"{where}{self.message}: {self.raw!r}"


@dataclass(frozen=True, slots=True)
class Entry:
    """A single successfully parsed access-log record.

    ``ident`` holds the second CLF field, ``referer``/``user_agent`` hold the
    combined-format extras (``None`` when absent or ``-``) and ``size`` is
    ``None`` when the server logged ``-`` for a response with no body.
    """

    ip: str
    ident: str
    timestamp: datetime
    method: str
    path: str
    protocol: str
    status: int
    size: int | None
    referer: str | None
    user_agent: str | None
    raw: str
    line_number: int = 0
    duration: float | None = None

    @property
    def status_class(self) -> str:
        """The HTTP status class label, e.g. ``"2xx"``, or ``"other"``."""
        if 100 <= self.status <= 599:
            return f"{self.status // 100}xx"
        return "other"

    @property
    def minute(self) -> datetime:
        """The timestamp truncated to the minute, timezone preserved."""
        return self.timestamp.replace(second=0, microsecond=0)

    def as_dict(self) -> dict[str, object]:
        """Return a JSON-serialisable mapping of every field."""
        return {
            "ip": self.ip,
            "ident": self.ident,
            "timestamp": self.timestamp.isoformat(),
            "method": self.method,
            "path": self.path,
            "protocol": self.protocol,
            "status": self.status,
            "status_class": self.status_class,
            "size": self.size,
            "referer": self.referer,
            "user_agent": self.user_agent,
            "duration": self.duration,
            "line_number": self.line_number,
        }


@dataclass(frozen=True, slots=True)
class ParseError:
    """A line that could not be parsed, retained for reporting."""

    line_number: int
    message: str
    raw: str

    def __str__(self) -> str:
        return f"line {self.line_number}: {self.message}: {self.raw!r}"


@dataclass(slots=True)
class ParseResult:
    """Entries parsed from an input plus every line that failed to parse."""

    entries: list[Entry] = field(default_factory=list)
    errors: list[ParseError] = field(default_factory=list)

    @property
    def total_lines(self) -> int:
        """Number of input lines seen, parsed and malformed combined."""
        return len(self.entries) + len(self.errors)

    def __len__(self) -> int:
        return len(self.entries)


class _Scanner:
    """Character cursor with the small set of token helpers the parser needs."""

    __slots__ = ("text", "pos")

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0

    def skip_spaces(self) -> None:
        """Advance past any run of spaces and tabs."""
        text = self.text
        pos = self.pos
        while pos < len(text) and text[pos] in " \t":
            pos += 1
        self.pos = pos

    def at_end(self) -> bool:
        """Return ``True`` when only whitespace remains."""
        self.skip_spaces()
        return self.pos >= len(self.text)

    def peek(self) -> str:
        """Return the character at the cursor, or ``""`` at end of input."""
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def take_while_not(self, stop: str) -> str:
        """Consume and return the characters up to the next one in *stop*."""
        text = self.text
        start = self.pos
        while self.pos < len(text) and text[self.pos] not in stop:
            self.pos += 1
        return text[start : self.pos]

    def expect(self, char: str) -> None:
        """Consume *char* or raise :class:`MalformedLineError`."""
        self.skip_spaces()
        if self.peek() != char:
            raise MalformedLineError(f"expected {char!r}")
        self.pos += 1

    def token(self) -> str:
        """Consume and return the next whitespace-delimited token."""
        self.skip_spaces()
        return self.take_while_not(" \t")

    def quoted(self) -> str:
        """Consume a double-quoted field, resolving backslash escapes.

        Supports ``\\"``, ``\\\\``, nginx's ``\\xHH`` hexadecimal escapes and
        the ``\\n``/``\\t``/``\\r`` shorthands.
        """
        self.skip_spaces()
        if self.peek() != '"':
            raise MalformedLineError("expected a quoted field")
        self.pos += 1
        text = self.text
        out: list[str] = []
        while True:
            if self.pos >= len(text):
                raise MalformedLineError("unterminated quoted field")
            char = text[self.pos]
            if char == "\\":
                if self.pos + 1 >= len(text):
                    raise MalformedLineError("dangling escape in quoted field")
                nxt = text[self.pos + 1]
                if nxt == "x":
                    digits = text[self.pos + 2 : self.pos + 4]
                    if len(digits) != 2:
                        raise MalformedLineError("truncated \\xHH escape")
                    try:
                        out.append(chr(int(digits, 16)))
                    except ValueError:
                        raise MalformedLineError("invalid \\xHH escape") from None
                    self.pos += 4
                else:
                    out.append(_ESCAPES.get(nxt, nxt))
                    self.pos += 2
            elif char == '"':
                self.pos += 1
                return "".join(out)
            else:
                out.append(char)
                self.pos += 1


def _duration(token: str) -> float | None:
    """Return a finite request duration, or ``None`` for anything else.

    ``float()`` accepts ``nan``, ``inf``, ``-inf`` and overflowing literals such
    as ``1e400``.  Those are not durations, and letting one through poisons every
    statistic downstream: ``nan`` renders as the text ``nans`` in the report,
    sorts unpredictably so ``duration=(0.5, 0.25)`` with the low before the high,
    and ``json.dumps`` emits a bare ``NaN`` token that RFC 8259 parsers reject
    outright.  A non-finite field is corrupt log data, so it is treated the same
    way as an unparsable one: recorded as "no duration recorded".
    """
    try:
        value = float(token)
    except ValueError:
        return None
    return value if math.isfinite(value) else None


def _optional(value: str) -> str | None:
    """Return ``None`` for the CLF "no value" placeholder, else the value."""
    if value == "" or value == MISSING:
        return None
    return value


#: ``datetime.timezone`` refuses any offset of exactly 24 hours, so a CLF
#: ``+2400`` offset has to be rejected here rather than handed to it.  The
#: widest real-world offset is +1400; anything past +2300 is a corrupt log.
MAX_OFFSET_MINUTES = 23 * 60 + 59


def _decimal(token: str) -> bool:
    """Return ``True`` when *token* is one or more base-10 digits.

    ``str.isdigit`` is the wrong guard: it also accepts superscripts, circled
    digits and other numeric-looking characters that ``int()`` then refuses to
    convert, which turned a malformed line into an unhandled ``ValueError``.
    ``str.isdecimal`` is exactly the set ``int()`` accepts.
    """
    return token.isdecimal()


def parse_timestamp(field_text: str) -> datetime:
    """Parse ``10/Oct/2000:13:55:36 -0700`` into a timezone-aware datetime.

    A missing UTC offset is interpreted as UTC.  Month names are matched
    case-insensitively against a fixed table, so results never depend on the
    process locale.

    Raises:
        MalformedLineError: If the timestamp does not match the CLF layout.
    """
    text = field_text.strip()
    if not text:
        raise MalformedLineError("empty timestamp")
    date_part, _, offset_part = text.rpartition(" ")
    if not date_part:  # no offset present at all
        date_part, offset_part = text, ""
    day, _, rest = date_part.partition("/")
    month_name, _, rest2 = rest.partition("/")
    year, _, rest3 = rest2.partition(":")
    hour, _, rest4 = rest3.partition(":")
    minute, _, second = rest4.partition(":")
    if not (_decimal(day) and _decimal(year)):
        raise MalformedLineError(f"unrecognised timestamp {field_text!r}")
    month = MONTHS.get(month_name.strip().lower())
    if month is None:
        raise MalformedLineError(f"unknown month in timestamp {field_text!r}")
    if not (_decimal(hour) and _decimal(minute) and _decimal(second)):
        raise MalformedLineError(f"unrecognised timestamp {field_text!r}")
    tzinfo = timezone.utc
    if offset_part:
        sign, digits = offset_part[0], offset_part[1:].replace(":", "")
        if sign not in "+-" or not _decimal(digits) or len(digits) not in (2, 4):
            raise MalformedLineError(f"unrecognised UTC offset {offset_part!r}")
        if len(digits) == 2:
            digits += "00"
        minutes = int(digits[:2]) * 60 + int(digits[2:])
        if minutes > MAX_OFFSET_MINUTES:
            raise MalformedLineError(f"unrecognised UTC offset {offset_part!r}")
        delta = timedelta(minutes=minutes)
        tzinfo = timezone(-delta if sign == "-" else delta)
    try:
        return datetime(
            int(year), month, int(day), int(hour), int(minute), int(second), tzinfo=tzinfo
        )
    except ValueError as exc:  # e.g. 31/Feb, hour 99
        raise MalformedLineError(f"invalid timestamp {field_text!r}: {exc}") from None


def parse_request(request: str) -> tuple[str, str, str]:
    """Split a quoted request field into ``(method, path, protocol)``.

    A request field of ``-`` yields ``("-", "-", "-")``.  A request with no
    protocol (``"GET /"``) reports the protocol as ``-``.
    """
    if request == MISSING or not request.strip():
        return (MISSING, MISSING, MISSING)
    parts = request.split(None, 2)
    if len(parts) == 3:
        return (parts[0], parts[1], parts[2])
    if len(parts) == 2:
        return (parts[0], parts[1], MISSING)
    return (parts[0], MISSING, MISSING)


def parse_size(token: str) -> int | None:
    """Return a byte count, or ``None`` for the ``-`` placeholder.

    Raises:
        MalformedLineError: If the token is neither ``-`` nor a number.
    """
    if token == MISSING:
        return None
    if not _decimal(token):
        raise MalformedLineError(f"size {token!r} is not a number")
    return int(token)


def parse_status(token: str) -> int:
    """Return an HTTP status code, requiring exactly three digits.

    Raises:
        MalformedLineError: If the token is not a three-digit code.
    """
    if not _decimal(token) or len(token) != 3:
        raise MalformedLineError(f"status {token!r} is not a three-digit code")
    return int(token)


def clean_host(token: str) -> str:
    """Normalise a client address, unwrapping Apache's bracketed IPv6 form.

    Raises:
        MalformedLineError: If the address is empty or contains whitespace.
    """
    host = token.strip()
    if not host:
        raise MalformedLineError("missing client address")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host or any(char.isspace() for char in host):
        raise MalformedLineError(f"invalid client address {token!r}")
    return host


def detect_format(line: str) -> str:
    """Guess ``"common"`` or ``"combined"`` for *line* by counting quoted fields.

    The guess is structural (three quoted fields means combined) and never
    inspects field contents, so it is stable for a given line.
    """
    scanner = _Scanner(line.strip())
    quoted = 0
    while not scanner.at_end():
        if scanner.peek() == '"':
            scanner.quoted()
            quoted += 1
        else:
            scanner.take_while_not('"')
    return FORMAT_COMBINED if quoted >= 3 else FORMAT_COMMON


def parse_line(line: str, log_format: LogFormat = FORMAT_AUTO, line_number: int = 0) -> Entry:
    """Parse one access-log line into an :class:`Entry`.

    Args:
        line: The raw line, with or without a trailing newline.
        log_format: ``"auto"`` accepts either shape, ``"common"`` rejects
            combined-only trailing fields and ``"combined"`` requires the
            referer and user-agent fields.
        line_number: 1-based line number recorded on the entry.

    Returns:
        The parsed :class:`Entry`.

    Raises:
        MalformedLineError: If the line does not match the expected shape.
    """
    raw = line.rstrip("\r\n")
    stripped = raw.strip()
    if not stripped:
        raise MalformedLineError("blank line", raw, line_number)

    scanner = _Scanner(stripped)
    ip = clean_host(scanner.token())
    # CLF writes three leading tokens: host, ident and authuser.  Only ident is
    # retained on Entry; authuser is consumed so the timestamp brackets line up.
    ident = scanner.token()
    scanner.token()
    scanner.expect("[")
    timestamp = parse_timestamp(scanner.take_while_not("]"))
    scanner.expect("]")
    request = scanner.quoted()
    status = parse_status(scanner.token())
    size = parse_size(scanner.token())

    referer: str | None = None
    user_agent: str | None = None
    duration: float | None = None

    # Collect every remaining quoted field.  Combined logs carry exactly two
    # (referer, user-agent); nginx may append $request_time as a third.
    extras: list[str] = []
    while not scanner.at_end():
        if scanner.peek() != '"':
            raise MalformedLineError("unexpected trailing content", raw, line_number)
        extras.append(scanner.quoted())

    if log_format == FORMAT_COMMON and extras:
        raise MalformedLineError(
            "common format expected but combined fields present", raw, line_number
        )
    if log_format == FORMAT_COMBINED and len(extras) < 2:
        raise MalformedLineError(
            "combined format requires a referer and a user-agent", raw, line_number
        )
    if len(extras) > 3:
        raise MalformedLineError("unexpected trailing content", raw, line_number)

    if len(extras) >= 2:
        referer = _optional(extras[0])
        user_agent = _optional(extras[1])
        if log_format == FORMAT_COMBINED and (referer is None or user_agent is None):
            raise MalformedLineError(
                "combined format requires a referer and a user-agent", raw, line_number
            )
    if len(extras) == 3:
        # A numeric third field is nginx's $request_time; anything else is
        # kept as an unknown extra and simply ignored.
        duration = _duration(extras[2])
    elif len(extras) == 1:
        # A lone trailing field can only be a request time.
        duration = _duration(extras[0])

    method, path, protocol = parse_request(request)
    return Entry(
        ip=ip,
        ident=ident or MISSING,
        timestamp=timestamp,
        method=method,
        path=path,
        protocol=protocol,
        status=status,
        size=size,
        referer=referer,
        user_agent=user_agent,
        raw=raw,
        line_number=line_number,
        duration=duration,
    )


def parse_lines(
    lines: Iterable[str],
    log_format: LogFormat = FORMAT_AUTO,
    strict: bool = False,
) -> ParseResult:
    """Parse many lines, collecting failures instead of raising.

    Blank lines are skipped and are not counted as errors.

    Args:
        lines: Any iterable of raw log lines.
        log_format: Format constraint forwarded to :func:`parse_line`.
        strict: When ``True`` the first malformed line raises
            :class:`MalformedLineError` instead of being collected.

    Returns:
        A :class:`ParseResult` with the parsed entries and collected errors.
    """
    result = ParseResult()
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            result.entries.append(parse_line(line, log_format, line_number))
        except MalformedLineError as exc:
            if strict:
                raise MalformedLineError(exc.message, exc.raw or line.strip(), line_number) from None
            result.errors.append(ParseError(line_number, exc.message, exc.raw or line.strip()))
    return result


def iter_entries(lines: Iterable[str], log_format: LogFormat = FORMAT_AUTO) -> Iterator[Entry]:
    """Yield parsed entries, skipping malformed lines.

    Convenient for streaming very large logs where per-line error reporting is
    not needed; use :func:`parse_lines` to inspect failures.
    """
    yield from parse_lines(lines, log_format).entries


def open_log(path: str | os.PathLike[str]) -> IO[str]:
    """Open a log file for reading, decompressing gzip data transparently.

    The gzip magic bytes decide rather than the file name, so a compressed
    file named ``access.log`` is handled too.  Decoding is UTF-8 with
    ``errors="replace"`` so one bad byte cannot abort a large scan.

    Raises:
        OSError: If the file cannot be opened.
    """
    file_path = os.fspath(path)
    with open(file_path, "rb") as probe:
        magic = probe.read(2)
    if magic == b"\x1f\x8b":
        return gzip.open(file_path, "rt", encoding="utf-8", errors="replace")
    return open(file_path, "r", encoding="utf-8", errors="replace")


def parse_file(
    path: str | os.PathLike[str],
    log_format: LogFormat = FORMAT_AUTO,
    strict: bool = False,
) -> ParseResult:
    """Parse every line of a log file, decompressing gzip transparently.

    Raises:
        OSError: If the file cannot be opened.
        MalformedLineError: In *strict* mode, on the first malformed line.
    """
    with open_log(path) as handle:
        return parse_lines(handle, log_format, strict)


def format_errors(errors: Sequence[ParseError], limit: int = 5) -> list[str]:
    """Render up to *limit* errors as printable strings."""
    return [str(error) for error in errors[:limit]]