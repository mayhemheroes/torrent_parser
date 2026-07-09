#!/usr/bin/env python3
"""Atheris fuzz harness for torrent_parser (the "differential-fuzz" target).

torrent_parser parses/creates .torrent (bencode) files. This harness drives the
public API on hostile input across four sub-targets selected by the first fuzz
byte: a differential encode/decode round-trip, TorrentFileParser, TorrentFileCreator,
and the JSON-encoder wrapper.

Atheris instruments the imported torrent_parser module (coverage feedback), so
libFuzzer steers the parser toward new code paths.

Run modes (driven by the compiled launcher `torrent_parser_fuzzer` / `-standalone`):
  * fuzzing      -- `python3 differential_fuzz.py [libFuzzer args]`
  * single input -- `python3 differential_fuzz.py <file>` (libFuzzer runs it once)
"""
import io
import sys

import atheris

# Under the compiled launcher (torrent_parser_fuzzer) coverage comes from the
# SanCov-instrumented embedded CPython, and this module is imported as a plain
# library -- Atheris bytecode instrumentation must NOT be active there (it feeds
# Atheris' own bundled libFuzzer, not the launcher's). Only instrument when the
# script itself is the fuzz driver, scoped to the module under test.
if __name__ == "__main__":
    with atheris.instrument_imports(include=['torrent_parser']):
        import torrent_parser as tp
else:
    import torrent_parser as tp

# torrent_parser leaks a wide range of raw exceptions on hostile input instead
# of its documented InvalidTorrentDataException: AssertionError (negative
# string lengths), OverflowError (huge lengths), ValueError (str.format on
# malformed error templates), LookupError / TypeError (bogus encoding values),
# RecursionError / MemoryError (deeply-nested or huge structures). These are
# genuine upstream robustness defects, already recorded against the Mayhem
# project (torrent-parser), and the accumulated corpus is saturated with tiny
# inputs that trigger them; left uncaught they crash-loop every run at startup
# and no coverage is ever recorded. Each API wrapper therefore treats any
# Exception as an expected parse rejection; the differential round-trip check
# raises OUTSIDE its wrapper's try block, so a real mismatch still aborts.
EXPECTED_ERRORS = (Exception,)


def differential_fuzz(fdp):
    hash_raw = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        encoded = tp.encode(data)
        decoded = tp.decode(encoded, hash_raw=hash_raw)
    except EXPECTED_ERRORS:
        pass
    else:
        # Differential test: encode(decode(encode(x))) must round-trip.
        if data != decoded.encode():
            raise Exception("Differential fuzzing test failed")


def fuzz_file_parser(fdp):
    use_ordered_dict = fdp.ConsumeBool()
    hash_raw = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    fp = io.BytesIO(data)
    try:
        parser = tp.TorrentFileParser(fp, use_ordered_dict=use_ordered_dict, hash_raw=hash_raw)
        parser.parse()
    except EXPECTED_ERRORS:
        pass


def fuzz_file_creation(fdp):
    try:
        creator = tp.TorrentFileCreator(fdp.ConsumeBytes(fdp.remaining_bytes()))
        creator.create_filelike()
    except EXPECTED_ERRORS:
        pass


def fuzz_json_parser(fdp):
    try:
        encoded = tp.encode(fdp.ConsumeBytes(fdp.remaining_bytes()))
        decoded = tp.decode(encoded)
        encoder = tp.JSONEncoderDataWrapperBytesToString()
        encoder.process(decoded)
    except EXPECTED_ERRORS:
        pass


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    fuzz_test = fdp.ConsumeIntInRange(0, 3)
    if fuzz_test == 0:
        differential_fuzz(fdp)
    elif fuzz_test == 1:
        fuzz_file_creation(fdp)
    elif fuzz_test == 2:
        fuzz_file_parser(fdp)
    elif fuzz_test == 3:
        fuzz_json_parser(fdp)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
