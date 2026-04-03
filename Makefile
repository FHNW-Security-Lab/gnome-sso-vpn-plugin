VERSION ?= 2.0.0

.PHONY: arch deb nix

arch:
	@./build-arch.sh

deb:
	@./build.sh $(VERSION)

nix:
	@nix build .#networkmanager-ms-sso
