# hs-certificate-transparency

Haskell implementation of [Certificate Transparency (CT)](http://www.certificate-transparency.org/), a proposal by Google to solve the [The Certificate Authority Problem](http://blog.cryptographyengineering.com/2012/02/how-to-fix-internet.html). CT is an experimental RFC: [RFC 6962](http://tools.ietf.org/html/rfc6962).

## How to build

    cabal test # warning: takes minutes
    cabal install

## How to setup environment
1. Set up a postgres DB `ct-watch`
2. Set up postgres user with credentials `docker`:`docker`
3. Execute the schema migration scripts: `psql -Udocker ct-watch < misc/schema/*.sql`
