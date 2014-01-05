FROM ubuntu:12.04
MAINTAINER tom@tom-fitzhenry.me.uk

WORKDIR /src

RUN echo "deb http://archive.ubuntu.com/ubuntu precise main universe" > /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y ghc cabal-install postgresql-server-dev-all ca-certificates
RUN /bin/sh -c "cabal update || true"


ADD hs-certificate-transparency.cabal /src/
RUN cabal install --only-dependencies
ADD . /src
RUN cabal install

CMD ["/.cabal/bin/hs-certificate-transparency"]
