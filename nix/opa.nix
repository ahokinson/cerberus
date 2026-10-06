# Pinned release binary, the same approach as tirith.nix. nixpkgs' own
# open-policy-agent builds from source and its test suite is broken (a
# missing fixture), which used to need a `doCheck = false` override. These
# are the upstream static builds: no build, no tests, no dynamic libraries.
{ lib, stdenvNoCC, fetchurl }:

let
  version = "1.19.1";

  targets = {
    aarch64-darwin = {
      asset = "opa_darwin_arm64_static";
      hash = "sha256-gFzj8zYVQVC+9zuvotq4gGYxhRvMx8rpW+9G/6vfj8M=";
    };
    x86_64-linux = {
      asset = "opa_linux_amd64_static";
      hash = "sha256-yfmFzg00X1SEAGreLGle2ePzCOREETnkZpXFwYKsCDk=";
    };
    aarch64-linux = {
      asset = "opa_linux_arm64_static";
      hash = "sha256-Gdy1GG/TlMMgI5GMU+qs2lX4NauwXhPg+adm3RQpSU8=";
    };
  };

  plat = targets.${stdenvNoCC.hostPlatform.system}
    or (throw "opa: unsupported system ${stdenvNoCC.hostPlatform.system}");
in
stdenvNoCC.mkDerivation {
  pname = "opa";
  inherit version;

  src = fetchurl {
    url = "https://github.com/open-policy-agent/opa/releases/download/v${version}/${plat.asset}";
    hash = plat.hash;
  };

  dontUnpack = true;
  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 $src $out/bin/opa
    runHook postInstall
  '';

  meta = {
    description = "general-purpose policy engine; cupcake's Rego evaluator";
    homepage = "https://www.openpolicyagent.org";
    license = lib.licenses.asl20;
    mainProgram = "opa";
    platforms = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
  };
}
