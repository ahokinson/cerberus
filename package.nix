{
  lib,
  rustPlatform,
  makeWrapper,
  git,
  open-policy-agent,
  tirith,
  cupcake,
  src,
}:

rustPlatform.buildRustPackage {
  pname = "cerberus";
  version = "0.1.2";

  inherit src;

  cargoHash = "sha256-OYmckjRonW0rzt4hxGxSG71+qYrfI63DdsYD/VUDG5o=";

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
    install -Dm444 -t $out/share/cerberus/rules rules/*.rhai

    # Same reasoning for the `policy` head's Rego. The binary embeds these
    # and `cerberus init` writes them into cupcake's global store, but a
    # consumer that manages that store declaratively can't run init against
    # it - shipping them here is the path that doesn't need the imperative
    # step. A missing policy head counts as degraded, same as the rules.
    install -Dm444 -t $out/share/cerberus/policies/cupcake policies/cupcake/*.rego

    # Same for the risk head's tirith overlay, applied only in repos with no
    # .tirith/policy.yaml of their own. Missing it degrades the head, which
    # fail-closes every guarded tool.
    install -Dm444 -t $out/share/cerberus/policies/tirith policies/tirith/policy.yaml

    # cerberus resolves these three by name off PATH, and a head whose
    # binary is missing counts as degraded, which makes `cerberus gate` deny
    # every Bash call until it's repaired. Wrapping PATH means installing
    # cerberus on its own is enough to get a guard that actually enforces,
    # rather than one that fails closed on first use.
    wrapProgram $out/bin/cerberus \
      --prefix PATH : ${lib.makeBinPath [ tirith cupcake open-policy-agent ]}
  '';

  meta = {
    description = "Three-headed guard for Claude Code's Bash tool: risk scanning, policy evaluation, and scripted situational checks";
    homepage = "https://github.com/ahokinson/cerberus";
    mainProgram = "cerberus";
  };
}
