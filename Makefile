VERSION ?= 2.0.0

.PHONY: deb nix

deb:
	@./build.sh $(VERSION)

nix:
	@nix build .#networkmanager-ms-sso
