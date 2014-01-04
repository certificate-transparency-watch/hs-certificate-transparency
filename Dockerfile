FROM ubuntu
MAINTAINER tom@tom-fitzhenry.me.uk


RUN echo "deb http://archive.ubuntu.com/ubuntu precise main universe" > /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y ghc cabal-install postgresql-server-dev-all
RUN cabal update
RUN cabal install cabal-dev

WORKDIR /src

ADD hs-certificate-transparency.cabal /src/
RUN /.cabal/bin/cabal-dev install-deps
ADD . /src
RUN /.cabal/bin/cabal-dev install

ENTRYPOINT ["./cabal-dev/bin/hs-certificate-transparency"]
