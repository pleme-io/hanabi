{
  description = "Hanabi - Web server and BFF (Backend for Frontend) platform service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/d6c71932130818840fc8fe9509cf50be8c64634f";

    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    fenix,
    crate2nix,
    ...
  }: let
    systems = ["aarch64-darwin" "x86_64-linux" "aarch64-linux"];
    linuxSystems = ["x86_64-linux" "aarch64-linux"];
    forAllSystems = f:
      nixpkgs.lib.genAttrs systems (system:
        f {
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };
          inherit system;
        });
    forLinuxSystems = f:
      nixpkgs.lib.genAttrs linuxSystems (system:
        f {
          pkgs = import nixpkgs {
            inherit system;
            config.allowUnfree = true;
          };
          inherit system;
        });
  in {
    # Binary and Docker image packages are Linux-only (Docker images target Linux)
    packages = forLinuxSystems ({
      pkgs,
      system,
    }: let
      muslTarget = "x86_64-unknown-linux-musl";
      targetEnvNameUpper = "X86_64_UNKNOWN_LINUX_MUSL";

      cargoNix = self + "/Cargo.nix";
      hasCargoNix = builtins.pathExists cargoNix;

      project =
        if hasCargoNix
        then
          import cargoNix {
            inherit pkgs;
            defaultCrateOverrides =
              pkgs.defaultCrateOverrides
              // {
                hanabi = oldAttrs: {
                  nativeBuildInputs = (oldAttrs.nativeBuildInputs or []) ++ (with pkgs; [cmake perl git]);
                  CARGO_BUILD_TARGET = muslTarget;
                  "CARGO_TARGET_${targetEnvNameUpper}_RUSTFLAGS" = "-C target-feature=+crt-static -C link-arg=-s";
                };
              };
          }
        else null;

      serviceBinary =
        if project != null
        then
          (
            if project ? workspaceMembers
            then project.workspaceMembers.hanabi.build
            else project.rootCrate.build
          )
        else null;

      hanabiImage =
        if serviceBinary != null
        then
          pkgs.dockerTools.buildLayeredImage {
            name = "ghcr.io/pleme-io/hanabi";
            tag = "latest";
            contents = [serviceBinary pkgs.cacert];
            config = {
              Entrypoint = ["${serviceBinary}/bin/hanabi"];
              Env = [
                "RUST_LOG=info,hanabi=debug"
                "LOG_FORMAT=json"
                "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
              ];
              ExposedPorts = {
                "3000/tcp" = {};
              };
              Labels = {
                "org.opencontainers.image.title" = "hanabi";
                "org.opencontainers.image.description" = "Web server and BFF platform service";
                "org.opencontainers.image.source" = "https://github.com/pleme-io/hanabi";
                "org.opencontainers.image.vendor" = "Pleme";
              };
            };
          }
        else null;
    in
      nixpkgs.lib.optionalAttrs (serviceBinary != null) {
        hanabi = serviceBinary;
      }
      // nixpkgs.lib.optionalAttrs (hanabiImage != null) {
        hanabi-image = hanabiImage;
      });

    apps = forAllSystems ({
      pkgs,
      system,
    }: let
      crate2nixPkg = crate2nix.packages.${system}.default;
    in {
      "regen" = {
        type = "app";
        program = toString (pkgs.writeShellScript "regen-hanabi" ''
          export SERVICE_DIR="."
          export CARGO="${pkgs.cargo}/bin/cargo"
          export CRATE2NIX="${crate2nixPkg}/bin/crate2nix"
          cd "$(git rev-parse --show-toplevel)"
          ${crate2nixPkg}/bin/crate2nix generate
        '');
      };
    });
  };
}
