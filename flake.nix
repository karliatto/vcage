{
  description = "vcage: VeraCrypt volumes unlocked with a Trezor-backed age keyfile";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          config = {
            # VeraCrypt is unfree; allow only that package.
            allowUnfreePredicate = pkg: builtins.elem (lib.getName pkg) [ "veracrypt" ];
            # trezor-agent depends on python-ecdsa, which nixpkgs flags for
            # CVE-2024-23342 (a timing side channel when *signing* with
            # python-ecdsa). trezor-agent only uses it for public-key
            # operations; private keys stay on the Trezor. See README.
            allowInsecurePredicate =
              pkg: lib.getName pkg == "ecdsa" && lib.hasPrefix "python3" (pkg.name or "");
          };
        };
      forAllSystems = f: lib.genAttrs systems (system: f (pkgsFor system));
    in
    {
      packages = forAllSystems (pkgs: rec {
        vcage = pkgs.rustPlatform.buildRustPackage {
          pname = "vcage";
          version = (lib.importTOML ./Cargo.toml).package.version;
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./src
              ./tests
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ pkgs.makeWrapper ];
          # Integration tests use a plain age X25519 identity, no hardware.
          nativeCheckInputs = [ pkgs.age ];

          # sudo is deliberately not wrapped: it must be the system's setuid
          # sudo (/run/wrappers/bin/sudo on NixOS).
          postInstall = ''
            wrapProgram $out/bin/vcage --prefix PATH : ${
              lib.makeBinPath [
                pkgs.age
                pkgs.trezor-agent
                pkgs.veracrypt
              ]
            }
          '';

          meta = {
            description = "VeraCrypt volumes unlocked with a Trezor-backed age keyfile";
            license = with lib.licenses; [
              mit
              asl20
            ];
            platforms = lib.platforms.linux;
            mainProgram = "vcage";
          };
        };
        default = vcage;
      });

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            age
            trezor-agent
            veracrypt
          ];
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      });

      checks = forAllSystems (pkgs: {
        vcage = self.packages.${pkgs.stdenv.hostPlatform.system}.vcage;
        fmt = pkgs.runCommand "vcage-fmt" { nativeBuildInputs = [ pkgs.cargo pkgs.rustfmt ]; } ''
          cd ${self}
          cargo fmt --check
          touch $out
        '';
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
    };
}
