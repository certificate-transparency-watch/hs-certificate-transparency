# hs-certificate-transparency

Haskell implementation of [Certificate Transparency (CT)](http://www.certificate-transparency.org/), a proposal by Google to solve the [The Certificate Authority Problem](http://blog.cryptographyengineering.com/2012/02/how-to-fix-internet.html). CT is an experimental RFC: [RFC 6962](http://tools.ietf.org/html/rfc6962).

## How much of CT does this library implement?

Not much:

1. Consistency proofs: that is, checking that CT log servers are append-only.

## Who uses this library?

Me. I run a CT auditor to check consistency proofs in Google's pilot log server, `https://ct.googleapis.com/pilot/`.
