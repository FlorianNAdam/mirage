{
  description = "Mirage FUSE filesystem with configurable file content";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    naersk.url = "github:nix-community/naersk/master";
  };

  outputs =
    {
      self,
      nixpkgs,
      naersk,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems =
        f:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = f system;
          }) systems
        );

      mirageFileOptions =
        { lib, ... }:
        {
          options = {
            path = lib.mkOption {
              type = lib.types.str;
              description = "File path to overlay.";
            };

            content = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Static content to replace the file content.";
            };

            exec = lib.mkOption {
              type = lib.types.nullOr lib.types.str;
              default = null;
              description = "Command to execute for generating file content.";
            };

            replaceRegex = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "List of pattern=replacement pairs for regex-based replacement.";
            };

            replaceExec = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [ ];
              description = "List of pattern=command pairs for command-based replacement.";
            };

            allowOther = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Allow other users to access the mounted filesystem.";
            };
          };
        };

      generateMirageServices =
        pkgs: lib: type: files:
        lib.listToAttrs (
          map (fileConfig: {
            name = "mirage-${lib.replaceStrings [ "/" ] [ "-" ] fileConfig.path}";
            value = {
              description = "Mirage ${type} Service for ${fileConfig.path}";
              wantedBy = [ "multi-user.target" ];
              serviceConfig = {
                ExecStart = lib.concatStringsSep " " [
                  "${self.packages.${pkgs.system}.mirage}/bin/mirage"
                  "${fileConfig.path}"
                  "--shell ${pkgs.bash}/bin/sh"
                  (lib.optionalString (fileConfig.content != null) "--content '${fileConfig.content}'")
                  (lib.optionalString (fileConfig.exec != null) "--exec '${fileConfig.exec}'")
                  (lib.concatMapStringsSep " " (r: "--replace-regex '${r}'") fileConfig.replaceRegex)
                  (lib.concatMapStringsSep " " (r: "--replace-exec '${r}'") fileConfig.replaceExec)
                  (lib.optionalString fileConfig.allowOther "--allow-other")
                ];
                Restart = "always";
              };
            };
          }) files
        );
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          naersk-lib = pkgs.callPackage naersk { };
        in
        {
          mirage = naersk-lib.buildPackage {
            src = ./.;
            buildInputs = with pkgs; [
              pkg-config
              fuse3
            ];
          };
        }
      );

      defaultPackage = forAllSystems (system: self.packages.${system}.mirage);

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        pkgs.mkShell {
          buildInputs = with pkgs; [
            cargo
            rustc
            rustfmt
            rust-analyzer
            fuse3
          ];
          nativeBuildInputs = with pkgs; [ pkg-config ];
        }
      );

      nixosModules.mirage =
        {
          config,
          pkgs,
          lib,
          ...
        }:
        {
          options.mirage = {
            enable = lib.mkEnableOption "Enable the mirage service";
            files = lib.mkOption {
              type = lib.types.listOf (lib.types.submodule mirageFileOptions);
              default = [ ];
              description = "List of file configurations for mirage, each with one method of content replacement.";
            };
          };

          config = lib.mkIf config.mirage.enable {
            systemd.services = generateMirageServices pkgs lib "System" config.mirage.files;

            assertions = map (fileConfig: {
              assertion = (
                let
                  optionsUsed = lib.length (
                    lib.filter (x: x != null && x != [ ]) [
                      fileConfig.content
                      fileConfig.exec
                      fileConfig.replaceRegex
                      fileConfig.replaceExec
                    ]
                  );
                in
                optionsUsed == 1
              );
              message = "Exactly one of 'content', 'exec', 'replaceRegex', or 'replaceExec' must be set for each file at ${fileConfig.path}.";
            }) config.mirage.files;
          };
        };
    };
}
