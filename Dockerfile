FROM ubuntu:15.10
RUN apt-get install -y ca-certificates wget libpq5 libgmp10 netbase
RUN wget -q https://github.com/certificate-transparency-watch/hs-certificate-transparency/releases/download/0.25/hs-certificate-transparency
RUN chmod u+x hs-certificate-transparency
CMD ["./hs-certificate-transparency"]
