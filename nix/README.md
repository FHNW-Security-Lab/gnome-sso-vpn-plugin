# Nix Packaging

Build all plugin-related packages:

```bash
nix build "path:$PWD#networkmanager-ms-sso"
```

Available package attributes:

- `ms-sso-openconnect-core`
- `networkmanager-ms-sso`

NixOS module is available as `nixosModules.default` from `flake.nix`.
