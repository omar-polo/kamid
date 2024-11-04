{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    autoreconfHook bison pkg-config aflplusplus
  ];

  buildInputs = with pkgs; [
    libevent libressl readline
  ];
}
