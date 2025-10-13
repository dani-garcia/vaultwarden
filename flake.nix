{
  inputs = {
    nixpkgs.url = "nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      utils,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs.outPath {
          inherit system;
        };
      in
      {
        devShells.default = pkgs.mkShell rec {
          RUST_BACKTRACE = "full";
          LD_LIBRARY_PATH = "${pkgs.lib.makeLibraryPath buildInputs}";

          buildInputs = with pkgs; [
            pkg-config
            openssl
            libpq
            libmysqlclient
          ];

          packages = with pkgs; [
            git

            nil
            nixfmt-rfc-style

            rustc
            cargo
            clippy
            rustfmt
            rust-analyzer

            nodePackages.prettier
            nodePackages.yaml-language-server
            nodePackages.vscode-langservers-extracted
            markdownlint-cli
            nodePackages.markdown-link-check
            marksman
            taplo
          ];
        };
      }
    );
}
