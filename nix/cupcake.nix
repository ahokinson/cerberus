# Pinned release binaries, the same approach as tirith.nix: every dependency
# cerberus shells out to is vendored here, so a build never depends on an
# upstream flake or on nixpkgs happening to carry a working copy.
#
# The release tarball also bundles an opa. It's left out on purpose: cerberus
# wraps its own pinned opa (see opa.nix) onto PATH, and one copy is the point.
{ lib, stdenv, fetchurl, autoPatchelfHook }:

let
  version = "0.5.1";

  targets = {
    aarch64-darwin = {
      target = "aarch64-apple-darwin";
      hash = "sha256-3gb5j4kWUXofl5EjQ5q95DHbvvv965EYMhplGm2TlNs=";
    };
    x86_64-linux = {
      target = "x86_64-unknown-linux-gnu";
      hash = "sha256-N3qm8CE82nMsiz14kv6FhcWFwjK+dTvxmdTTZEOlR+o=";
    };
    aarch64-linux = {
      target = "aarch64-unknown-linux-gnu";
      hash = "sha256-12Qc13608cq8b3O4Z+ORiv/H/3Roxi9LcL9qdbLoi8U=";
    };
  };

  plat = targets.${stdenv.hostPlatform.system}
    or (throw "cupcake: unsupported system ${stdenv.hostPlatform.system}");
in
stdenv.mkDerivation {
  pname = "cupcake";
  inherit version;

  src = fetchurl {
    url = "https://github.com/eqtylab/cupcake/releases/download/v${version}/cupcake-v${version}-${plat.target}.tar.gz";
    hash = plat.hash;
  };

  sourceRoot = "cupcake-v${version}-${plat.target}";

  nativeBuildInputs = lib.optional stdenv.hostPlatform.isLinux autoPatchelfHook;

  # Rust release binaries dynamically link libgcc_s.so.1 and libm;
  # autoPatchelfHook needs this in buildInputs to find and relink them.
  buildInputs = lib.optional stdenv.hostPlatform.isLinux stdenv.cc.cc.lib;

  installPhase = ''
    runHook preInstall
    install -Dm755 bin/cupcake $out/bin/cupcake
    runHook postInstall
  '';

  meta = {
    description = "policy enforcement layer for AI coding agents";
    homepage = "https://github.com/eqtylab/cupcake";
    license = lib.licenses.asl20;
    mainProgram = "cupcake";
    platforms = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
  };
}
