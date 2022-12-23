#!/usr/bin/python3
import atheris
import sys
import io

with atheris.instrument_imports():
    import torrent_parser as tp


@atheris.instrument_func
def differential_fuzz(fdp: atheris.FuzzedDataProvider):
    hash_raw = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    try:
        encoded = tp.encode(data)
        decoded = tp.decode(encoded, hash_raw=hash_raw)
    except tp.InvalidTorrentDataException:
        pass
    else:
        # Differential fuzzing test
        if data != decoded.encode():
            raise Exception("Differential fuzzing test failed")


@atheris.instrument_func
def fuzz_file_parser(fdp: atheris.FuzzedDataProvider):
    use_ordered_dict = fdp.ConsumeBool()
    hash_raw = fdp.ConsumeBool()
    data = fdp.ConsumeBytes(fdp.remaining_bytes())
    fp = io.BytesIO(data)
    try:
        parser = tp.TorrentFileParser(fp, use_ordered_dict=use_ordered_dict, hash_raw=hash_raw)
        parser.parse()
    except tp.InvalidTorrentDataException:
        pass


@atheris.instrument_func
def fuzz_file_creation(fdp: atheris.FuzzedDataProvider):
    try:
        creator = tp.TorrentFileCreator(fdp.ConsumeBytes(fdp.remaining_bytes()))
        creator.create_filelike()
    except tp.InvalidTorrentDataException:
        pass


@atheris.instrument_func
def fuzz_json_parser(fdp: atheris.FuzzedDataProvider):
    try:
        encoded = tp.encode(fdp.ConsumeBytes(fdp.remaining_bytes()))
        decoded = tp.decode(encoded)
        encoder = tp.JSONEncoderDataWrapperBytesToString()
        encoder.process(decoded)
    except tp.InvalidTorrentDataException:
        pass


@atheris.instrument_func
def TestOneInput(data):
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


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
