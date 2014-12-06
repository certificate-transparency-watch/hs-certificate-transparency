# hs-certificate-transparency

Haskell implementation of [Certificate Transparency (CT)](http://www.certificate-transparency.org/), a proposal by Google to solve the [The Certificate Authority Problem](http://blog.cryptographyengineering.com/2012/02/how-to-fix-internet.html). CT is an experimental RFC: [RFC 6962](http://tools.ietf.org/html/rfc6962).

## How to build

    cabal sandbox init
    cabal install

## How to setup
Create a DB: `misc/db-creation`
Execute the schema migration scripts: `misc/schema-*.sql`

## How to run
    .cabal-sandbox/bin/hs-certificate-transparency
