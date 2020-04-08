# LSD - The Librestack Daemon

LSD is a complete 2.0 rewrite of GLADD to make it more modular and efficient.

LSD is a (pre)forking network daemon, which uses modules to handle requests.  It
aims to be small, simple, fast and secure.  External dependencies are kept to a
minimum.  By using a modular approach, code-paths are kept short, the attack
surface small, and yet it is flexible and extensible.

The rewrite is a work in progress, and GLADD has a bunch of features that are
not yet available in LSD.

LSD was created to work with and be the basis for various other Librestack /
Librecast projects.

## Modules

- http.so - simple https 1.1 webserver module with websockets support
