#!/usr/bin/python3
import atheris
import sys
import io

with atheris.instrument_imports():
    import torrent_parser as tp

@atheris.instrument_func
def differential_fuzz(data):
    try:
        encoded = tp.encode(data)
        decoded = tp.decode(encoded)
    except tp.InvalidTorrentDataException:
        pass
    else:
        # Differential fuzzing test
        if data != decoded.encode():
            raise Exception("Differential fuzzing test failed")

@atheris.instrument_func
def fuzz_file_parser(data):
    fp = io.BytesIO(data)
    try:
        tp.TorrentFileParser(fp)
    except tp.InvalidTorrentDataException:
        pass

@atheris.instrument_func
def fuzz_file_creation(data):
    try:
        tp.TorrentFileCreator(data)
    except tp.InvalidTorrentDataException:
        pass

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)

    fuzz_test = fdp.ConsumeIntInRange(0, 2)
    remaining_bytes = fdp.ConsumeBytes(fdp.remaining_bytes())
    if fuzz_test == 0:
        differential_fuzz(remaining_bytes)
    elif fuzz_test == 1:
        fuzz_file_creation(remaining_bytes)
    elif fuzz_test == 2:
        fuzz_file_parser(remaining_bytes)


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
