{ haskellPackages ? (import <nixpkgs> {}).haskellPackages }:
let
  inherit (haskellPackages) cabal cabalInstall_1_20_0_3
    aeson asn1Encoding asn1Types async base64Bytestring
    binary x509 cryptohash hunit hslogger httpConduit
    httpTypes monadLoops network postgresqlSimple text
    tasty tastyHunit tastyQuickcheck tastyTh;

in cabal.mkDerivation (self: {
  pname = "project-name";
  version = "1.0.0";
  src = ./.;
  buildDepends = [
    aeson asn1Encoding asn1Types async base64Bytestring
    binary x509 cryptohash hslogger httpConduit
    httpTypes monadLoops network postgresqlSimple text
    tasty tastyHunit tastyQuickcheck tastyTh
  ];
  buildTools = [ cabalInstall_1_20_0_3 ];
  enableSplitObjs = false;
})
