{ config, lib, pkgs, ... }:

let
  cfg = config.services.gnome-ms-sso-plugin;
  cleanupScript = pkgs.writeShellScript "nm-ms-sso-cleanup" ''
    export PATH=${lib.makeBinPath [
      pkgs.networkmanager
      pkgs.iproute2
      pkgs.nftables
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
      description = "Deprecated compatibility option; secure teardown is always enabled.";
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

      # NetworkManager snapshots DNS policy when an activation begins. Migrate
      # persistent profiles after NM starts so the first VPN activation already
      # has exclusive negative priority on non-resolved backends as well.
      systemd.services.nm-ms-sso-dns-policy = {
        description = "Migrate MS SSO VPN profiles to exclusive DNS";
        wantedBy = [ "multi-user.target" ];
        wants = [ "NetworkManager.service" ];
        after = [ "NetworkManager.service" ];
        path = [ pkgs.networkmanager pkgs.gawk pkgs.coreutils ];
        serviceConfig.Type = "oneshot";
        script = ''
          ${pkgs.networkmanager-ms-sso}/libexec/nm-ms-sso-migrate-dns-policy
        '';
      };

      # This dispatcher also removes the crash-safe IPv6 kill route. Security
      # teardown must not be disabled by the legacy DNS-cleanup option.
      networking.networkmanager.dispatcherScripts = [
        {
          source = cleanupScript;
          type = "basic";
        }
      ];

      systemd.tmpfiles.rules = pkgs.networkmanager-ms-sso.networkManagerTmpfilesRules or [ ];
    })
  ];
}
