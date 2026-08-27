# Upstream's own flake.nix fails to build on darwin (references a removed
# darwin.apple_sdk_11_0 nixpkgs stub - see flake.nix). They publish signed
# release binaries for every platform we need, so fetch those directly
# instead, the same way nixpkgs packages claude-code.
#
# Lives in cerberus's repo because cerberus is the only consumer: the
# judgement head shells out to tirith, and postInstall wraps it onto PATH.
# Exposed as `packages.<system>.tirith` so a consumer that also wants tirith
# standalone gets the same single pinned copy rather than a second one.
{ lib, stdenv, fetchurl, autoPatchelfHook }:

let
  version = "0.3.3";

  targets = {
    aarch64-darwin = {
      target = "aarch64-apple-darwin";
      hash = "sha256-cg7UY30W/tkIwtJo/R2oVGMqFdWc50w9eJA8WpLMvBw=";
    };
    x86_64-linux = {
      target = "x86_64-unknown-linux-gnu";
      hash = "sha256-bNvjXo+cz0LnCtlbUByTzSGKwYIBw9+VjVT2ug2ZXOI=";
    };
    aarch64-linux = {
      target = "aarch64-unknown-linux-gnu";
      hash = "sha256-x4QjMIMAOmoVM9ueu6MLGnu3zvqiOdtsoSFZizhMyho=";
    };
  };

  plat = targets.${stdenv.hostPlatform.system}
    or (throw "tirith: unsupported system ${stdenv.hostPlatform.system}");
in
stdenv.mkDerivation {
  pname = "tirith";
  inherit version;

  src = fetchurl {
    url = "https://github.com/sheeki03/tirith/releases/download/v${version}/tirith-${plat.target}.tar.gz";
    hash = plat.hash;
  };

  sourceRoot = ".";

  nativeBuildInputs = lib.optional stdenv.hostPlatform.isLinux autoPatchelfHook;

  # Rust release binaries dynamically link libgcc_s.so.1; autoPatchelfHook
  # needs this in buildInputs to find and relink it.
  buildInputs = lib.optional stdenv.hostPlatform.isLinux stdenv.cc.cc.lib;

  installPhase = ''
    runHook preInstall
    install -Dm755 tirith $out/bin/tirith
    runHook postInstall
  '';

  meta = {
    description = "pre-execution security gate for terminal commands and AI agents";
    homepage = "https://github.com/sheeki03/tirith";
    mainProgram = "tirith";
    platforms = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
  };
}
