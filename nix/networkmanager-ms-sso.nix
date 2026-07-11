{ lib
, python3Packages
, meson
, ninja
, pkg-config
, wrapGAppsHook4
, networkmanager
, gtk4
, glib
, libadwaita
, libsecret
, openconnect
, vpnc-scripts
, writeShellScriptBin
, iproute2
, procps
, systemd
, openresolv
, coreutils
, kmod
, util-linux
, playwright-driver
, ms-sso-openconnect-core
}:

let
  openconnectWrapped = writeShellScriptBin "openconnect" ''
    exec ${lib.getExe openconnect} --script ${lib.getExe' vpnc-scripts "vpnc-script"} "$@"
  '';
  runtimeTmpfilesRules =
    lib.filter (rule: rule != "")
      (lib.splitString "\n" (builtins.readFile ../data/networkmanager-ms-sso.tmpfiles));
  nixRuntimeTmpfilesRules =
    map
      (rule:
        if lib.hasPrefix "d /var/cache/ms-playwright " rule
        then "L+ /var/cache/ms-playwright - - - - ${playwright-driver.browsers}"
        else rule)
      runtimeTmpfilesRules;
in
python3Packages.buildPythonApplication rec {
  pname = "networkmanager-ms-sso";
  version = "2.0.3";
  format = "other";

  src = lib.cleanSource ../.;

  nativeBuildInputs = [
    meson
    ninja
    pkg-config
    wrapGAppsHook4
  ];

  buildInputs = [
    networkmanager
    gtk4
    glib
    libadwaita
    libsecret
    playwright-driver
  ];

  pythonPath = with python3Packages; [
    pygobject3
    dbus-python
    keyring
    secretstorage
    playwright
    ms-sso-openconnect-core
  ];

  makeWrapperArgs = [
    "--prefix" "PATH" ":" (lib.makeBinPath [
      openconnectWrapped
      openconnect
      iproute2
      procps
      systemd
      openresolv
      coreutils
      kmod
      util-linux
    ])
    "--set" "PLAYWRIGHT_BROWSERS_PATH" "${playwright-driver.browsers}"
    "--set" "MS_SSO_GP_HIP_REPORT_WRAPPER" "${placeholder "out"}/libexec/nm-ms-sso-gp-hipreport"
    "--set" "MS_SSO_GP_HIP_REPORT_BASE" "${openconnect}/libexec/openconnect/hipreport.sh"
    "--prefix" "GI_TYPELIB_PATH" ":" (lib.makeSearchPath "lib/girepository-1.0" [
      networkmanager
      gtk4
      libadwaita
      libsecret
      glib
    ])
  ];

  PKG_CONFIG_LIBNM_VPNSERVICEDIR = "${placeholder "out"}/lib/NetworkManager/VPN";

  dontWrapGApps = true;
  preFixup = ''
    makeWrapperArgs+=("''${gappsWrapperArgs[@]}")
  '';

  postFixup = ''
    wrapPythonProgramsIn "$out/libexec" "$out $pythonPath"
  '';

  postInstall = ''
    substituteInPlace $out/lib/NetworkManager/VPN/nm-ms-sso-service.name \
      --replace /usr/libexec "$out/libexec" \
      --replace "plugin=libnm-vpn-plugin-ms-sso-editor.so" \
        "plugin=$out/lib/NetworkManager/libnm-vpn-plugin-ms-sso-editor.so"
  '';

  passthru = {
    networkManagerPlugin = "VPN/nm-ms-sso-service.name";
    networkManagerRuntimeDeps = [
      openconnect
      vpnc-scripts
      iproute2
      procps
      util-linux
    ];
    networkManagerTmpfilesRules = nixRuntimeTmpfilesRules;
  };

  doCheck = false;

  meta = with lib; {
    description = "NetworkManager VPN plugin for MS SSO OpenConnect";
    homepage = "https://github.com/FHNW-Security-Lab/gnome-ms-sso-plugin";
    license = licenses.gpl2Plus;
    platforms = platforms.linux;
  };
}
