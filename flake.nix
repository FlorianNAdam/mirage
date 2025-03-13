{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    flake-utils.url = "github:numtide/flake-utils";

    naersk = {
      url = "github:nix-community/naersk";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      flake-utils,
      naersk,
      nixpkgs,
      ...
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = (import nixpkgs) {
          inherit system;
        };

        naersk-lib = pkgs.callPackage naersk { };

        mirage = naersk-lib.buildPackage {
          src = ./.;
          buildInputs = with pkgs; [
            pkg-config
            fuse3
          ];
        };
      in
      {
        packages = {
          inherit mirage;
        };

        defaultPackage = self.packages.${system}.mirage;

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            fuse3
          ];

          nativeBuildInputs = with pkgs; [
            pkg-config
          ];

          packages = with pkgs; [
            rust-analyzer
          ];
        };
      }
    );
}
