FROM ubuntu:15.10
RUN apt-get install -y ca-certificates wget libpq5 libgmp10 netbase
ADD $HOME/.local/bin/hs-certificate-transparency
RUN chmod u+x hs-certificate-transparency
CMD ["./hs-certificate-transparency"]
