{
  description = "Extract and verify the Happ Android subscription body key table";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable-small";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = {flake-parts, ...} @ inputs:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem = {pkgs, ...}: let
        pythonEnv = pkgs.python3.withPackages (ps: [
          ps.unicorn
          ps.pycryptodome
          ps.pillow
          ps.zstandard
          ps.androguard
          ps.cryptography
          ps.pytest
        ]);

        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            ./happ_keys
            ./tests
            ./pyproject.toml
          ];
        };

        # Offline only: tests needing release APKs skip without HAPP_APK_CACHE.
        runInSrc = name: nativeBuildInputs: script:
          pkgs.runCommand name {inherit nativeBuildInputs;} ''
            cp -r ${src} src && chmod -R u+w src && cd src
            export HOME=$TMPDIR RUFF_CACHE_DIR=$TMPDIR/ruff
            ${script}
            touch $out
          '';
      in {
        devShells.default = pkgs.mkShell {
          name = "happ-key-extractor-dev";
          packages = [pythonEnv pkgs.ruff pkgs.actionlint pkgs.shellcheck pkgs.uv];
          shellHook = ''
            export PYTHONPATH="$PWD:$PYTHONPATH"
          '';
        };

        checks = {
          ruff = runInSrc "happ-key-extractor-ruff" [pkgs.ruff] ''
            ruff check .
            ruff format --check .
          '';
          pytest = runInSrc "happ-key-extractor-pytest" [pythonEnv] ''
            python -m pytest -q -p no:cacheprovider
          '';
        };

        formatter = pkgs.alejandra;
      };
    };
}
