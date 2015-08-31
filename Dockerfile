FROM ubuntu:15.04
MAINTAINER tom@tom-fitzhenry.me.uk

RUN apt-get update
RUN apt-get install -y ca-certificates wget libpq5 libgmp10 netbase

RUN wget -q https://github.com/certificate-transparency-watch/hs-certificate-transparency/releases/download/0.23/hs-certificate-transparency

RUN chmod u+x hs-certificate-transparency

CMD ["./hs-certificate-transparency"]
