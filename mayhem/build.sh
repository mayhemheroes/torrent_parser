#!/usr/bin/env bash
#
# mayhem/build.sh -- build the torrent_parser Atheris fuzz harness + its standalone
# reproducer, and prepare the project's own unittest suite. Runs inside the commit
# image (mayhem/Dockerfile) as `mayhem` in /mayhem. Python adaptation of the C/C++
# template.
#
# What it does (must be idempotent + air-gapped on re-run -- SPEC item 9 / 6.5):
#   1. Populate / reuse an in-image wheelhouse under /opt/toolchains/python
#      (HOME-independent), then install atheris OFFLINE from that wheelhouse into a
#      fixed site dir on PYTHONPATH. The first (CI, online) build fills the
#      wheelhouse; the air-gapped PATCH re-run resolves entirely from it
#      (pip --no-index --find-links). torrent_parser itself has NO runtime deps and
#      is consumed as the editable source tree at the repo root ($SRC on
#      PYTHONPATH), so a PATCH agent's edits to torrent_parser.py take effect with
#      no reinstall.
#   2. Build a private static CPython (cached under /opt/toolchains/python/cpython;
#      the source tarball is kept next to the wheelhouse so the air-gapped re-run
#      never downloads) and compile launcher.c -> the ELF Mayhem target
#      `torrent_parser_fuzzer`, statically linking libpython. Mayhem needs an ELF
#      cmd, the gate needs DWARF < 4, and the cloud coverage tracer only measures
#      the MAIN executable -- so the interpreter must live inside the target binary
#      (an exec wrapper or .so-based embedder records 0 edges cloud-side).
#   3. Build the same launcher as the standalone (run-once) reproducer
#      `torrent_parser_fuzzer-standalone`.
#   4. Compile run_tests.c -> the ELF test wrapper that drives the unittest oracle.
#
# The base image exports the build contract (CC, SANITIZER_FLAGS, DEBUG_FLAGS, ...).
# We only need DEBUG_FLAGS here (the launcher embeds CPython -- sanitizing
# it would just instrument the wrapper, not the fuzzed Python; Atheris instruments
# the torrent_parser module itself at import time).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
export DEBUG_FLAGS CC MAYHEM_JOBS

SRC="${SRC:-/mayhem}"
cd "$SRC"

# -- Python toolchain caches at a FIXED, $HOME-independent prefix (SPEC item 8) --
PY_PREFIX=/opt/toolchains/python
WHEELHOUSE="$PY_PREFIX/wheelhouse"
SITE="$PY_PREFIX/site"
mkdir -p "$WHEELHOUSE" "$SITE"

# -- Private static CPython (interpreter INSIDE the target ELF; see header note 2) --
CPY_VER=3.13.5
CPY_PREFIX="$PY_PREFIX/cpython"
CPY_SRC_DIR="$PY_PREFIX/src"
CPY_TARBALL="$CPY_SRC_DIR/Python-$CPY_VER.tar.xz"
if [ ! -x "$CPY_PREFIX/bin/python3" ]; then
  mkdir -p "$CPY_SRC_DIR"
  if [ ! -f "$CPY_TARBALL" ]; then
    echo ">> downloading CPython $CPY_VER source (online, first build only)"
    curl -fsSL --retry 3 -o "$CPY_TARBALL" "https://www.python.org/ftp/python/$CPY_VER/Python-$CPY_VER.tar.xz"
  fi
  echo ">> building static CPython $CPY_VER into $CPY_PREFIX (SanCov-instrumented, cached for re-runs)"
  builddir=$(mktemp -d)
  tar -C "$builddir" -xf "$CPY_TARBALL"
  # -fsanitize=fuzzer-no-link: the interpreter IS the fuzzed code -- its inline
  # 8-bit counters + PC table end up in the launcher ELF, so libFuzzer (and
  # Mayhem's cloud coverage) sees real native edges for every Python execution.
  (cd "$builddir/Python-$CPY_VER" \
     && ./configure --prefix="$CPY_PREFIX" CC="$CC" \
          CFLAGS="$DEBUG_FLAGS -O2 -fsanitize=fuzzer-no-link" \
          LDFLAGS="-fsanitize=fuzzer-no-link" >configure.log 2>&1 \
     && make -j"$MAYHEM_JOBS" >make.log 2>&1 \
     && make install >install.log 2>&1)
  rm -rf "$builddir"
else
  echo ">> static CPython already built -- reusing $CPY_PREFIX (idempotent re-run path)"
fi
PY="$CPY_PREFIX/bin/python3"
PYCONF="$CPY_PREFIX/bin/python3-config"

# 1) Wheelhouse: download the fuzzing runtime dependency ONCE (online). On the
#    air-gapped re-run the directory is already populated, so pip never reaches the
#    network. atheris ships a prebuilt manylinux wheel for this CPython, so no
#    compilation is needed. torrent_parser has NO runtime deps and its tests use
#    only the stdlib + unittest, so atheris is the only wheel we need.
PKGS=(atheris)
need_download=0
"$PY" -c "import os,glob,sys; sys.exit(0 if glob.glob(os.path.join('$WHEELHOUSE','atheris-*.whl')) else 1)" || need_download=1
if [ "$need_download" -eq 1 ]; then
  echo ">> populating wheelhouse (online) at $WHEELHOUSE"
  "$PY" -m pip download --dest "$WHEELHOUSE" "${PKGS[@]}"
else
  echo ">> wheelhouse already populated -- reusing $WHEELHOUSE (air-gapped re-run path)"
fi

# 2) Install atheris into the fixed site dir, OFFLINE from the wheelhouse.
#    --no-index + --find-links guarantees no PyPI access (works on the air-gapped
#    re-run). Idempotent: once the site dir holds atheris we SKIP the reinstall.
if "$PY" -c "import os,glob,sys; sys.exit(0 if glob.glob(os.path.join('$SITE','atheris*')) else 1)"; then
  echo ">> deps already installed in $SITE -- skipping (idempotent re-run)"
else
  echo ">> installing deps (offline) into $SITE"
  "$PY" -m pip install --no-index --find-links="$WHEELHOUSE" --target "$SITE" "${PKGS[@]}"
fi

# torrent_parser itself stays the editable source tree at the repo root: $SRC holds
# torrent_parser.py, so $SRC on PYTHONPATH makes `import torrent_parser` resolve to
# the live source (PATCH edits take effect with no reinstall). atheris comes from
# the site dir.
PYRUN="$SITE:$SRC"

# Record the site dir + interpreter for test.sh / the launcher to consume.
cat > "$PY_PREFIX/env.sh" <<EOF
export PYTHONPATH="$PYRUN\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHON_BIN="$PY"
EOF

# Sanity: the harness imports must resolve offline now.
PYTHONPATH="$PYRUN" "$PY" -c 'import atheris, torrent_parser; print("imports OK")'

# 3) Compile the ELF launcher target + the standalone reproducer (DWARF < 4 via
#    $DEBUG_FLAGS). The launcher is itself the libFuzzer main: it embeds the private
#    SanCov-instrumented CPython and calls the harness module in-process; PYTHONPATH
#    comes from the env (the Dockerfile sets ENV PYTHONPATH), so the Python side finds
#    atheris + torrent_parser.
PY_CFLAGS="$("$PYCONF" --embed --cflags)"
# -rdynamic: C extension modules (stdlib .so's, atheris' native.so) resolve libpython
# symbols from the main executable, so the statically-linked interpreter must export
# them. -fsanitize=fuzzer supplies libFuzzer's main + the SanCov runtime consuming
# the instrumented interpreter's counters.
PY_LDFLAGS="-rdynamic $("$PYCONF" --embed --ldflags)"
LAUNCHER_DEFS=(-DHARNESS_DIR="\"$SRC/mayhem\"" -DHARNESS_MOD="\"differential_fuzz\"" -DPYHOME="\"$CPY_PREFIX\"")
echo ">> compiling torrent_parser_fuzzer (+ standalone) with DEBUG_FLAGS=$DEBUG_FLAGS"
$CC $DEBUG_FLAGS -fsanitize=fuzzer $PY_CFLAGS "${LAUNCHER_DEFS[@]}" \
    "$SRC/mayhem/launcher.c" -o "$SRC/torrent_parser_fuzzer" $PY_LDFLAGS
# The standalone reproducer is the same launcher: libFuzzer runs a single input file
# once when the binary is given a file path (no fuzzing loop), which is exactly the
# run-once reproducer contract.
$CC $DEBUG_FLAGS -fsanitize=fuzzer $PY_CFLAGS "${LAUNCHER_DEFS[@]}" \
    "$SRC/mayhem/launcher.c" -o "$SRC/torrent_parser_fuzzer-standalone" $PY_LDFLAGS

# 4) The unittest oracle runs through a compiled NON-system ELF wrapper so the
#    gate's anti-reward-hack sabotage check (which neuters non-system binaries to
#    exit(0)) actually bites the suite -- a test.sh that shelled straight to the
#    system python would be spared and look reward-hackable.
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" "$SRC/mayhem/run_tests.c" -o "$SRC/torrent_parser_run_tests"

echo ">> build.sh complete"
ls -la "$SRC/torrent_parser_fuzzer" "$SRC/torrent_parser_fuzzer-standalone" "$SRC/torrent_parser_run_tests"
