FROM ubuntu:12.04
MAINTAINER tom@tom-fitzhenry.me.uk

RUN echo "deb http://archive.ubuntu.com/ubuntu precise main universe" > /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y ca-certificates wget postgresql-server-dev-all

RUN wget -q https://github.com/certificate-transparency-watch/hs-certificate-transparency/releases/download/0.12/hs-certificate-transparency

RUN chmod u+x hs-certificate-transparency

CMD ./hs-certificate-transparency
