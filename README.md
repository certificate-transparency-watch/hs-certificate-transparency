# hs-certificate-transparency

Haskell implementation of [Certificate Transparency (CT)](http://www.certificate-transparency.org/), a proposal by Google to solve the [The Certificate Authority Problem](http://blog.cryptographyengineering.com/2012/02/how-to-fix-internet.html). CT is an experimental RFC: [RFC 6962](http://tools.ietf.org/html/rfc6962).

## How much of CT does this library implement?

Not much:

1. Consistency proofs: that is, checking that CT log servers are append-only.

## Who uses this library?

Me. I run a CT auditor to check consistency proofs in Google's pilot log server, `https://ct.googleapis.com/pilot/`.

### How can I build and run the CT auditor?
The source for this auditor is in this repository for convenience. Once the library matures, I'll move the auditor out of the library. Until then, to build and run the auditor:

    apt-get install cabal-install postgresql-server-dev-all # or equivalent
    ghc --version # ensure >= 7.6.2
    cabal install cabal-dev
    git clone https://github.com/tomfitzhenry/hs-certificate-transparency.git
    cd hs-certificate-transparency
    cabal-dev install
    ./cabal-dev/bin/hs-certificate-transparency

#### FreeBSD

1. Install [ca\_root\_nss](http://www.freshports.org/security/ca_root_nss/)
2. Follow the above steps, but when executing `hs-certificate-transparency` set the environment variable `SYSTEM_CERTIFICATE_PATH` to be `/usr/local/share/certs/`

    SYSTEM\_CERTIFICATE\_PATH=/usr/local/share/certs/ ./cabal-dev/bin/hs-certificate-transparency

See [issue #5](https://github.com/tomfitzhenry/hs-certificate-transparency/issues/5) for more details.
