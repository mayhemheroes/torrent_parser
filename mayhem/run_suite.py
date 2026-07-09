#!/usr/bin/env python3
"""run_suite.py -- run torrent_parser's own unittest suite and print a summary.

This is the behavioral oracle driver. It loads the project's real unittest
modules under tests/ (known-answer bencode parse/encode assertions, md5
round-trip checks against real .torrent files), executes them ALL in one run
(continuing past failures so the counts are complete), and prints a single line

    RESULT tests=<N> passed=<P> failed=<F> skipped=<S>

that mayhem/test.sh parses into a CTRF report. Exit status is non-zero iff any
test failed/errored, so a no-op PATCH that neuters torrent_parser breaks the
assertions and fails the oracle (anti-reward-hacking).
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# The project's test modules (tests/ package).
SUITES = (
    "test_create", "test_decode", "test_decoding_error", "test_encode",
    "test_hash_field", "test_hash_raw", "test_info_hash", "test_parse",
)


def main() -> int:
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in SUITES:
        suite.addTests(loader.loadTestsFromName("tests." + name))

    runner = unittest.TextTestRunner(verbosity=1, buffer=True)
    result = runner.run(suite)

    total = result.testsRun
    failed = len(result.failures) + len(result.errors)
    skipped = len(getattr(result, "skipped", []))
    passed = total - failed - skipped
    print("RESULT tests=%d passed=%d failed=%d skipped=%d" % (total, passed, failed, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
