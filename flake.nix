{
  description = "Three-headed guard for Claude Code's Bash tool: risk scanning, policy evaluation, and scripted situational checks";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" "aarch64-linux" ];
      forEachSystem = nixpkgs.lib.genAttrs systems;

      # The three binaries the heads shell out to are vendored from pinned
      # upstream release binaries (nix/tirith.nix, nix/cupcake.nix,
      # nix/opa.nix) rather than taken from an upstream flake or from
      # nixpkgs. A build then depends on neither one working, and a
      # consumer can't end up with a different version than the one the
      # tests ran against.
      tirithFor = pkgs: pkgs.callPackage ./nix/tirith.nix { };
      cupcakeFor = pkgs: pkgs.callPackage ./nix/cupcake.nix { };
      opaFor = pkgs: pkgs.callPackage ./nix/opa.nix { };

      cerberusFor = pkgs: pkgs.callPackage ./nix/package.nix {
        tirith = tirithFor pkgs;
        cupcake = cupcakeFor pkgs;
        opa = opaFor pkgs;
      };
    in
    {
      packages = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          cerberus = cerberusFor pkgs;
        in
        {
          inherit cerberus;
          # Vended alongside cerberus so a consumer that wants any of these
          # standalone shares this flake's single pinned copy instead of
          # adding a second, independently-drifting one.
          tirith = tirithFor pkgs;
          cupcake = cupcakeFor pkgs;
          opa = opaFor pkgs;
          default = cerberus;
        });

      # Everything `bun run check` and `bun run coverage` need, plus the
      # three binaries the heads shell out to, so the tests that exercise
      # them for real run here instead of skipping.
      devShells = forEachSystem (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            BIOME_BINARY = "${pkgs.biome}/bin/biome";
            LLVM_COV = "${pkgs.llvm}/bin/llvm-cov";
            LLVM_PROFDATA = "${pkgs.llvm}/bin/llvm-profdata";
            packages = [
              pkgs.biome
              pkgs.bun
              pkgs.cargo
              pkgs.cargo-llvm-cov
              pkgs.clippy
              pkgs.git
              pkgs.llvm
              pkgs.rust-analyzer
              pkgs.rustc
              pkgs.rustfmt
              (tirithFor pkgs)
              (cupcakeFor pkgs)
              (opaFor pkgs)
            ];
          };
        });

      # Not `opa`: an overlay attribute of that name would shadow nixpkgs'
      # own for every consumer, which is a larger claim than cerberus makes.
      overlays.default = final: _prev: {
        cerberus = cerberusFor final;
        tirith = tirithFor final;
        cupcake = cupcakeFor final;
      };
    };
}
