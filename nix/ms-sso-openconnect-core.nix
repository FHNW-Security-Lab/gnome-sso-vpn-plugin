{ lib, python3Packages }:

python3Packages.buildPythonPackage rec {
  pname = "ms-sso-openconnect-core";
  version = "2.0.2";
  format = "other";

  src = lib.cleanSource ../src/python/core;

  dontBuild = true;

  propagatedBuildInputs = with python3Packages; [
    keyring
    platformdirs
    playwright
    secretstorage
  ];

  installPhase = ''
    runHook preInstall
    mkdir -p $out/${python3Packages.python.sitePackages}
    cp -r . $out/${python3Packages.python.sitePackages}/core
    runHook postInstall
  '';

  pythonImportsCheck = [ "core" ];
  doCheck = false;

  meta = with lib; {
    description = "Core library for MS SSO OpenConnect";
    homepage = "https://github.com/FHNW-Security-Lab/gnome-ms-sso-plugin";
    license = licenses.mit;
    platforms = platforms.linux;
  };
}
