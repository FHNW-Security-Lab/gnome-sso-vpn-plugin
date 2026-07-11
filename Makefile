VERSION ?= 2.0.3

.PHONY: arch deb nix test

arch:
	@./build-arch.sh

deb:
	@./build.sh $(VERSION)

nix:
	@nix build .#networkmanager-ms-sso

test:
	@PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
