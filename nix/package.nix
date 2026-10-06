{
  lib,
  rustPlatform,
  makeWrapper,
  git,
  opa,
  tirith,
  cupcake,
}:

rustPlatform.buildRustPackage {
  pname = "cerberus";
  version = "0.1.3";

  # An explicit allowlist, never a raw `../.`: Nix's directory copy has no
  # notion of `.gitignore`, and the repo root holds plenty that has nothing
  # to do with the package (docs, CI config, the fuzz crate, editor and
  # agent state). Editing any of those then doesn't rebuild the package.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../crates
    ];
  };

  cargoHash = "sha256-TW7WtepZ6DHqCsnyuIRVkfxzXPlbecwcvBDnhNFf0Tk=";

  cargoBuildFlags = [
    "-p"
    "cerberus"
  ];
  cargoTestFlags = [
    "-p"
    "cerberus"
  ];

  nativeBuildInputs = [ makeWrapper ];

  # The git-safety rule is verified against real git behavior rather than a
  # mock: its tests build actual repos in temp dirs, some with a second bare
  # repo standing in as a remote. They set repo-local user.name/user.email
  # themselves, so git on PATH is the only thing the checkPhase adds.
  nativeCheckInputs = [ git ];

  postInstall = ''
    # The judgement head reads these from disk at runtime rather than from
    # the binary, and an empty rules dir counts as degraded. `cerberus init`
    # writes them imperatively, but it also rewrites Claude Code's
    # settings.json, which is awkward where that file is managed
    # declaratively. Shipping them here lets a consumer deploy the rules
    # straight from the package, always matching this binary's version.
    install -Dm444 -t $out/share/cerberus/rules crates/cerberus/rules/*.rhai

    # Same reasoning for the `policy` head's Rego. The binary embeds these
    # and `cerberus init` writes them into cupcake's global store, but a
    # consumer that manages that store declaratively can't run init against
    # it - shipping them here is the path that doesn't need the imperative
    # step. A missing policy head counts as degraded, same as the rules.
    install -Dm444 -t $out/share/cerberus/policies/cupcake crates/cerberus/policies/cupcake/*.rego

    # cerberus resolves these three by name off PATH, and a head whose
    # binary is missing counts as degraded, which makes `cerberus gate` deny
    # every Bash call until it's repaired. Wrapping PATH means installing
    # cerberus on its own is enough to get a guard that actually enforces,
    # rather than one that fails closed on first use.
    wrapProgram $out/bin/cerberus \
      --prefix PATH : ${lib.makeBinPath [ tirith cupcake opa ]}
  '';

  meta = {
    description = "Three-headed guard for Claude Code's Bash tool: risk scanning, policy evaluation, and scripted situational checks";
    homepage = "https://github.com/ahokinson/cerberus";
    mainProgram = "cerberus";
  };
}
