{
  description = "Aegis System Administration Tools";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    flake-utils.url = "github:numtide/flake-utils";
    nexus = {
      url = "github:fudoniten/nexus";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, nexus }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        pythonPkgs = pkgs.python3.withPackages
          (ps: with ps; [ typer pyyaml tomli tomli-w pytest pytest-cov ]);

        # Kerberos scripts
        scripts = ./scripts;

        # Build the Python package
        aegisPackage = pkgs.python3Packages.buildPythonApplication {
          pname = "aegis-tools-system";
          version = "0.1.0";
          pyproject = true;

          src = ./.;

          nativeBuildInputs = with pkgs.python3Packages; [ setuptools wheel ];

          propagatedBuildInputs = with pkgs.python3Packages; [
            typer
            pyyaml
            tomli
            tomli-w
          ];

          # Don't run tests during build
          doCheck = false;
        };

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            pythonPkgs
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
            echo "Run: aegis --help"
            echo "Run tests: pytest"
          '';
        };

        packages = {
          default = self.packages.${system}.aegis;

          # The main CLI package with all runtime dependencies
          aegis = pkgs.writeShellApplication {
            name = "aegis";
            runtimeInputs = [
              aegisPackage
              pkgs.age
              pkgs.ssh-to-age
              pkgs.openssh
              pkgs.ruby
              pkgs.krb5
              nexus.packages.${system}.nexus-keygen
            ];
            text = ''
              export AEGIS_SCRIPTS="${scripts}"
              exec aegis "$@"
            '';
          };
        };

        # Overlay for use in NixOS configurations
        overlays.default = final: prev: {
          aegis = self.packages.${system}.aegis;
        };
      }) // {
        # System-independent outputs
        overlays.default = final: prev: {
          aegis = self.packages.${prev.system}.aegis;
        };

        # NOTE: NixOS modules are in the separate 'aegis' repo at /net/projects/niten/aegis
        # This repo (aegis-tools-system) is for admin CLI tools only.
      };
}
