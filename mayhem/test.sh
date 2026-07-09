#!/usr/bin/env bash
#
# mayhem/test.sh -- RUN torrent_parser's own unittest suite (atheris already
# installed, torrent_parser on PYTHONPATH by mayhem/build.sh) and emit a CTRF
# (ctrf.io) summary. exit 0 iff failed==0.
# PATCH-grade oracle: a no-op patch that neuters torrent_parser breaks the suite's
# known-answer bencode / md5 round-trip assertions, so it FAILS here
# (anti-reward-hacking).
#
# It does NOT compile -- build.sh installed atheris into the in-image site dir and
# compiled the torrent_parser_run_tests ELF wrapper. We only RUN the suite
# (mayhem/run_suite.py loads the project's tests/ package). The suite is routed
# through that compiled NON-system wrapper so the gate's sabotage check (neuter
# non-system binaries to exit(0)) actually perturbs the run (the CPython
# interpreter under a system path would otherwise be spared).
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"

SRC="${SRC:-/mayhem}"
cd "$SRC"

# Put the in-image site dir (atheris) + the torrent_parser source root on PYTHONPATH.
PY_PREFIX=/opt/toolchains/python
# shellcheck disable=SC1091
[ -f "$PY_PREFIX/env.sh" ] && source "$PY_PREFIX/env.sh"
export PYTHONPATH="$PY_PREFIX/site:$SRC${PYTHONPATH:+:$PYTHONPATH}"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

RUNNER="$SRC/torrent_parser_run_tests"
if [ ! -x "$RUNNER" ]; then
  echo "test.sh: $RUNNER missing/not executable -- mayhem/build.sh must build it first" >&2
  emit_ctrf "torrent_parser-unittest" 0 1 0
  exit 1
fi

# Run the suite via the compiled wrapper -> python3 mayhem/run_suite.py.
LOG="$(mktemp)"
"$RUNNER" "$SRC/mayhem/run_suite.py" 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}

# run_suite.py prints a single machine-readable summary: "RESULT tests=N passed=P failed=F skipped=S".
line="$(grep -E '^RESULT tests=' "$LOG" | tail -1)"
get() { echo "$line" | grep -oE "$1=[0-9]+" | grep -oE '[0-9]+$' | head -1; }
passed="$(get passed)";  passed="${passed:-0}"
failed="$(get failed)";  failed="${failed:-0}"
skipped="$(get skipped)"; skipped="${skipped:-0}"
rm -f "$LOG"

# If the driver produced no summary at all (e.g. neutered under sabotage, or a crash
# before any test ran) AND it exited non-zero, report a failure so the oracle is not
# silently green.
if [ "$(( passed + failed + skipped ))" -eq 0 ] && [ "$rc" -ne 0 ]; then
  emit_ctrf "torrent_parser-unittest" 0 1 0
  exit 1
fi

emit_ctrf "torrent_parser-unittest" "$passed" "$failed" "$skipped"
