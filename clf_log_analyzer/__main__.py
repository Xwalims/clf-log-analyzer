"""Allow ``python3 -m clf_log_analyzer`` as a shorthand for the CLI.

``python3 -m clf_log_analyzer.cli`` also works and is what the test suite and
README use.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())