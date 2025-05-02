{
  description = "Android DevShell FHS Environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; config = {
          allowUnfree = true;
        };};
        rustEnv = pkgs.rust-bin.stable.latest.default.override {
          targets = [ "aarch64-linux-android" ];
          extensions = [ "rust-std" "rust-src" ];
        };
      in {
        devShell = pkgs.mkShell {
          buildInputs = [
            rustEnv
            pkgs.android-tools
            pkgs.cargo-ndk
            pkgs.autoPatchelfHook
            pkgs.zlib
            pkgs.libxml2
            pkgs.lldb
            pkgs.wireshark
            pkgs.lldb
          ];
        };
      });
}
