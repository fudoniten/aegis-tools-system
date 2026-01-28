{
  description = "Aegis System Administration Tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        python = pkgs.python3.withPackages
          (ps: with ps; [ typer pyyaml tomli tomli-w pytest pytest-cov ]);

        # Kerberos scripts
        scripts = ./scripts;

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            python
            pkgs.age
            pkgs.ssh-to-age
            pkgs.openssh
            pkgs.git
            # Kerberos tools
            pkgs.ruby
            pkgs.krb5
          ];

          shellHook = ''
            export PYTHONPATH="$PWD:$PYTHONPATH"
            export AEGIS_SCRIPTS="${scripts}"
            echo "Aegis System Tools development environment"
            echo ""
            echo "Run: python -m aegis.cli --help"
            echo "Run tests: pytest"
          '';
        };

        packages.default = pkgs.writeShellScriptBin "aegis" ''
          export AEGIS_SCRIPTS="${scripts}"
          exec ${python}/bin/python -m aegis.cli "$@"
        '';
      });
}
