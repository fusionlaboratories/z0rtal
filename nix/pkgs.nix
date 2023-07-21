let
  nixpkgs-src = builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/0d1b9472176bb31fa1f9a7b86ccbb20c656e6792.tar.gz"; # haskell-updates 23/03/23
    sha256 = "sha256:0j7y0s691xjs2146pkssz5wd3dc5qkvzx106m911anvzd08dbx9f";
  };

  config = {
    packageOverrides = pkgs: with pkgs.haskell.lib;
      let
        # https://github.com/NixOS/nixpkgs/issues/140774#issuecomment-1371565125
        # https://github.com/NixOS/nixpkgs/issues/220647
        fixCyclicReference = drv: overrideCabal drv (_: { enableSeparateBinOutput = false; });
      in {
        haskell = pkgs.haskell // {
          packages = pkgs.haskell.packages // {
            ghc94 = pkgs.haskell.packages.ghc94.override(old: {
              overrides = pkgs.lib.composeExtensions (old.overrides or (_: _: {})) (self: super: {
                ghcid = fixCyclicReference(dontCheck super.ghcid); # some tests are non-reproducible from measuring time
                z0rtal = self.callCabal2nix "z0rtal" ../. {};

                # https://github.com/protolude/protolude/pull/143#issuecomment-1589406228
                protolude = overrideCabal (self.callHackage "protolude" "0.3.3" {}) (_: {
                  revision = "1";
                  editedCabalFile = "sha256-W06ZNxNaF2EdBwmwVsRHC+APa64QBq4r2zQwCwbSDh4=";
                });

                # https://github.com/serokell/galois-field/pull/2
                galois-field = doJailbreak (self.callCabal2nix "galois-field" (pkgs.fetchFromGitHub {
                  owner = "serokell";
                  repo = "galois-field";
                  rev = "6fb4511eebbd3363baa9e02cbb51d91642d02740";
                  sha256 = "sha256-vlBmOT+jzW+txBRUZsj5vfXx5f51iECxZzPvrVs2cUU=";
                }) {});

                # https://github.com/serokell/elliptic-curve/pull/1
                elliptic-curve = doJailbreak (self.callCabal2nix "elliptic-curve" (pkgs.fetchFromGitHub {
                  owner = "serokell";
                  repo = "elliptic-curve";
                  rev = "6982573859ca72b53412ea31ba0109a051b1adf2";
                  sha256 = "sha256-8zZGfdIIuUGsMvTusQA3NMKBpjyMMhkebNGTB3UPTjI=";
                }) {});

                # https://github.com/serokell/pairing/pull/1
                pairing = doJailbreak (self.callCabal2nix "pairing" (pkgs.fetchFromGitHub {
                  owner = "serokell";
                  repo = "pairing";
                  rev = "5758deb5567c2ea90a0d4ee6e3f37fcb1e715841";
                  sha256 = "sha256-W/xyVIid4rcdWa5fCxTqwyKO5YFlC1UgY+MGwHZfOK8=";
                }) {});
              });
            });
          };
        };
    };
  };

  nixpkgs = import nixpkgs-src { inherit config; };

  shell = nixpkgs.haskell.packages.ghc94.shellFor {
    strictDeps = true;
    packages = p: [ p.z0rtal ];
    withHoogle = true;
    nativeBuildInputs =
      let hask = with nixpkgs.haskell.packages.ghc94; [
        (import ./cabal-multi-repl.nix).cabal-install
        ghcid
        (haskell-language-server.overrideAttrs(finalAttrs: previousAttrs: { propagatedBuildInputs = []; buildInputs = previousAttrs.propagatedBuildInputs; }))
      ];
      in with nixpkgs; hask ++ [
        zlib
        rustc
        miden
      ];
  };

  miden = nixpkgs.rustPlatform.buildRustPackage rec {
    pname = "miden";
    # version = "0.5.0";
    version = "0.6.1";
    src = nixpkgs.fetchFromGitHub {
      owner = "0xPolygonMiden";
      repo = "miden-vm";
      rev = "v${version}";
      # sha256 = "sha256-bDILZ8vvxjB/JN6tyhTNKxjQB/35M47grxFqToesH9E=";
      sha256 = "sha256-8DPZNcmE1yMTDsxuaZFTOLfjwRlsWZPFDtfVRLMSL7U=";
    };
    cargoLock.lockFile = ./miden_cargo.lock;
    postPatch = ''
      ln -s ${./miden_cargo.lock} Cargo.lock
    '';
    buildType = "release";
    buildFeatures = [ "executable" "concurrent" ];
    nativeBuildInputs = with nixpkgs; [ rustc ];
    doCheck = false;
  };
in

{ inherit nixpkgs shell miden;
  inherit (nixpkgs.haskell.packages.ghc94) z0rtal;
}
