{
  description = "Hanabi - Web server and BFF (Backend for Frontend) platform service";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
    };
    forge = {
      url = "github:pleme-io/forge";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
      inputs.substrate.follows = "substrate";
      inputs.crate2nix.follows = "crate2nix";
    };
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fenix, substrate, forge, crate2nix, ... }: let
    systems = ["aarch64-darwin" "x86_64-linux" "aarch64-linux"];
    eachSystem = f: nixpkgs.lib.genAttrs systems f;

    mkOutputs = system: let
      rustService = import "${substrate}/lib/rust-service.nix" {
        inherit system nixpkgs;
        nixLib = substrate;
        crate2nix = crate2nix.packages.${system}.default;
        forge = forge.packages.${system}.default;
      };
    in rustService {
      serviceName = "hanabi";
      src = self;
      registry = "ghcr.io/pleme-io/hanabi";
      packageName = "hanabi";
      namespace = "hanabi-system";
      architectures = ["amd64" "arm64"];
      ports = { graphql = 80; health = 8080; metrics = 8080; };
    };
  in {
    packages = eachSystem (system: (mkOutputs system).packages);
    devShells = eachSystem (system: (mkOutputs system).devShells);
    apps = eachSystem (system: (mkOutputs system).apps);

    homeManagerModules.default = import ./module {
      hmHelpers = import "${substrate}/lib/hm-service-helpers.nix" { lib = nixpkgs.lib; };
    };
    nixosModules.default = import ./module/nixos.nix;
    overlays.default = final: prev: {
      hanabi = self.packages.${final.system}.default;
    };
  };
}
