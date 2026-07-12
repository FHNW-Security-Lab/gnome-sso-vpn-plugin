{ config, lib, pkgs, ... }:

let
  cfg = config.services.gnome-ms-sso-plugin;
  cleanupScript = pkgs.writeShellScript "nm-ms-sso-cleanup" ''
    export PATH=${lib.makeBinPath [
      pkgs.networkmanager
      pkgs.iproute2
      pkgs.systemd
      pkgs.openresolv
      pkgs.glibc.bin
      pkgs.coreutils
      pkgs.gnused
      pkgs.gawk
      pkgs.gnugrep
      pkgs.util-linux
    ]}
    exec ${pkgs.networkmanager-ms-sso}/libexec/nm-ms-sso-recover-network "$@"
  '';
  stopStaleScript = pkgs.writeShellScript "nm-ms-sso-stop-stale" ''
    if ! ${lib.getExe' pkgs.procps "pgrep"} -f nm-ms-sso-service >/dev/null 2>&1; then
      exit 0
    fi
    ${lib.getExe' pkgs.procps "pkill"} -TERM -f nm-ms-sso-service || true
    attempt=0
    while ${lib.getExe' pkgs.procps "pgrep"} -f nm-ms-sso-service >/dev/null 2>&1 \
      && [ "$attempt" -lt 120 ]; do
      attempt=$((attempt + 1))
      ${lib.getExe' pkgs.coreutils "sleep"} 0.25
    done
    ${lib.getExe' pkgs.procps "pkill"} -KILL -f nm-ms-sso-service \
      >/dev/null 2>&1 || true
  '';
in
{
  options.services.gnome-ms-sso-plugin = {
    enable = lib.mkEnableOption "GNOME MS SSO NetworkManager plugin";

    withOverlay = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Add the local overlay that provides networkmanager-ms-sso.";
    };

    autoKillStale = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Kill stale nm-ms-sso-service processes on NetworkManager restart.";
    };

    autoCleanupDns = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Clean up DNS entries on VPN disconnect.";
    };
  };

  config = lib.mkMerge [
    {
      nixpkgs.overlays = lib.optionals cfg.withOverlay [
        (import ./overlay.nix)
      ];
    }
    (lib.mkIf cfg.enable {
      networking.networkmanager.plugins = lib.mkAfter [
        pkgs.networkmanager-ms-sso
      ];

      services.dbus.packages = [
        pkgs.networkmanager-ms-sso
      ];

      systemd.services.NetworkManager.serviceConfig.ExecStartPre =
        lib.optional cfg.autoKillStale
          "-${stopStaleScript}";

      networking.networkmanager.dispatcherScripts = lib.optional cfg.autoCleanupDns {
        source = cleanupScript;
        type = "basic";
      };

      systemd.tmpfiles.rules = pkgs.networkmanager-ms-sso.networkManagerTmpfilesRules or [ ];
    })
  ];
}
