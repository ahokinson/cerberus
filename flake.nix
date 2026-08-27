{
  description = "Three-headed guard for Claude Code's Bash tool: risk scanning, policy evaluation, and scripted situational checks";

  inputs = {
    cupcake = {
      url = "github:eqtylab/cupcake";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, cupcake, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      forEachSystem = nixpkgs.lib.genAttrs systems;

      # nixpkgs' own open-policy-agent test suite is broken (missing test
      # fixture), unrelated to the shipped binary. cerberus wraps opa onto
      # its PATH, so building cerberus builds opa and trips that check —
      # and a consumer's identical override is not in scope here, only in
      # theirs. Without this, `nix build github:ahokinson/cerberus` fails
      # for anyone who isn't already carrying the same workaround.
      opaFor = pkgs: pkgs.open-policy-agent.overrideAttrs (_: { doCheck = false; });

      tirithFor = pkgs: pkgs.callPackage ./nix/tirith.nix { };

      cupcakeFor = system: cupcake.packages.${system}.cupcake-cli;

      cerberusFor = pkgs: system: pkgs.callPackage ./package.nix {
        src = self;
        tirith = tirithFor pkgs;
        cupcake = cupcakeFor system;
        open-policy-agent = opaFor pkgs;
      };
    in
    {
      packages = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          cerberus = cerberusFor pkgs system;
        in
        {
          inherit cerberus;
          # Vended alongside cerberus so a consumer that wants either of
          # these standalone shares this flake's single pinned copy instead
          # of adding a second, independently-drifting one.
          tirith = tirithFor pkgs;
          cupcake = cupcakeFor system;
          default = cerberus;
        });

      overlays.default = final: _prev: {
        cerberus = cerberusFor final final.stdenv.hostPlatform.system;
        tirith = tirithFor final;
        cupcake = cupcakeFor final.stdenv.hostPlatform.system;
      };
    };
}
