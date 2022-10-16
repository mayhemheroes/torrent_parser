FROM fuzzers/atheris:2.0.7-python3.9

ADD . /mail-parser

# Build
WORKDIR /mail-parser
RUN python3 setup.py install

CMD ["/mail-parser/mayhem/fuzz_mail_parsing.py"]
