# hs-certificate-transparency

Haskell implementation of [Certificate Transparency (CT)](http://www.certificate-transparency.org/), a proposal by Google to solve the [The Certificate Authority Problem](http://blog.cryptographyengineering.com/2012/02/how-to-fix-internet.html). CT is an experimental RFC: [RFC 6962](http://tools.ietf.org/html/rfc6962).

## How to build

    cabal test # warning: takes minutes
    cabal install

## How to setup environment
1. Set up a postgres DB `ct-watch`
2. Set up postgres user with credentials `docker`:`docker`
3. Execute the schema migration scripts: `psql -Udocker ct-watch < misc/schema/*.sql`

## How to add a new log server
1. Insert record to `log_server` and `log_entry` ( https://github.com/certificate-transparency-watch/hs-certificate-transparency/commit/8fe620deb3042d1d5980333fb6166a52fedf4bfc )
2. Restart `hs-certificate-transparency` (because it caches which log servers exist in memory)
3. Set the first of the STH to be verified
4. Note that STHs with the same treesize as the first STH won't pass STH consistency checks, due to a bug (issue #12), so delete them
5. Update health checks ( https://github.com/certificate-transparency-watch/ct-watch-http/commit/15e24d7be3b3da854b47436e4c2ff9a085c6d5ed )
6. Update website ( https://github.com/certificate-transparency-watch/ct-watch-www/commit/98682f516e9d47a79ede700ff9dbb037c534f1fb )
