FROM fuzzers/atheris:2.0.7-python3.9

ADD . /torrent_parser

# Build
WORKDIR /torrent_parser
RUN pip3 install .

CMD ["/torrent_parser/mayhem/differential_fuzz.py"]
