#!/usr/bin/env bash
#
# Build Debian package for network-manager-ms-sso
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_NAME="network-manager-ms-sso"
VERSION="2.0.6"
MIN_OPENCONNECT_VERSION="9.12"

BUILD_DEPENDENCIES=(
    dpkg-dev
    debhelper
    meson
    ninja-build
    pkg-config
    libnm-dev
    libgtk-4-dev
    libglib2.0-dev
    libsecret-1-dev
)

RUNTIME_DEPENDENCIES=(
    network-manager
    openconnect
    iproute2
    nftables
    python3
    python3-pip
    python3-gi
    python3-dbus
    python3-keyring
    python3-platformdirs
    procps
    util-linux
    gir1.2-nm-1.0
    gir1.2-gtk-4.0
    gir1.2-adw-1
    gir1.2-secret-1
    libasound2t64
    libatk-bridge2.0-0t64
    libnss3
    libxcomposite1
)

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $0"
    echo "Builds Debian package for the GNOME NetworkManager plugin."
    exit 0
fi

echo "=== Building Debian Package for $PACKAGE_NAME ==="
echo ""

# Check both build and runtime dependencies. Runtime dependencies are checked so
# a package built for the local machine can also be installed and exercised
# immediately; they remain declared in debian/control for other target systems.
MISSING_DEPENDENCIES=()

check_dependencies() {
    local dependency_type="$1"
    shift
    local all_present=1
    local pkg package_status

    echo "Checking $dependency_type dependencies..."
    for pkg in "$@"; do
        package_status="$(dpkg-query -W -f='${db:Status-Status}' "$pkg" 2>/dev/null || true)"
        if [[ "$package_status" != "installed" ]]; then
            echo "  Missing: $pkg"
            MISSING_DEPENDENCIES+=("$pkg")
            all_present=0
        fi
    done

    if ((all_present)); then
        echo "All $dependency_type dependencies present."
    fi
    echo ""
}

check_minimum_package_version() {
    local pkg="$1"
    local minimum_version="$2"
    local installed_version

    installed_version="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
    if [[ -z "$installed_version" ]]; then
        return
    fi
    if dpkg --compare-versions "$installed_version" ge "$minimum_version"; then
        echo "$pkg version $installed_version satisfies >= $minimum_version."
        echo ""
        return
    fi

    echo "  Too old: $pkg $installed_version (requires >= $minimum_version)"
    MISSING_DEPENDENCIES+=("$pkg")
    echo ""
}

check_dependencies "build" "${BUILD_DEPENDENCIES[@]}"
check_dependencies "runtime" "${RUNTIME_DEPENDENCIES[@]}"
check_minimum_package_version "openconnect" "$MIN_OPENCONNECT_VERSION"

if ((${#MISSING_DEPENDENCIES[@]} > 0)); then
    echo ""
    echo "Install missing dependencies with:"
    printf "  sudo apt install"
    printf " %q" "${MISSING_DEPENDENCIES[@]}"
    printf "\n"
    exit 1
fi

# Create build directory
BUILD_DIR="$SCRIPT_DIR/deb-build"
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Create source directory with version
SRC_DIR="$BUILD_DIR/${PACKAGE_NAME}-${VERSION}"
mkdir -p "$SRC_DIR"

# Copy source files
echo "Copying source files..."
cp -r "$SCRIPT_DIR/src" "$SRC_DIR/"
# Never package interpreter caches from a developer checkout.
find "$SRC_DIR/src" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$SRC_DIR/src" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
cp -r "$SCRIPT_DIR/data" "$SRC_DIR/"
cp "$SCRIPT_DIR/meson.build" "$SRC_DIR/"
cp "$SCRIPT_DIR/README.md" "$SRC_DIR/"
cp "$SCRIPT_DIR/install-dev.sh" "$SRC_DIR/"
cp "$SCRIPT_DIR/build.sh" "$SRC_DIR/"
cp "$SCRIPT_DIR/build-deb.sh" "$SRC_DIR/"
cp "$SCRIPT_DIR/Makefile" "$SRC_DIR/"

# Copy debian directory from packaging metadata
cp -r "$SCRIPT_DIR/packaging/debian" "$SRC_DIR/debian"

# Add source format
mkdir -p "$SRC_DIR/debian/source"
echo "3.0 (native)" > "$SRC_DIR/debian/source/format"

# Build the package
echo ""
echo "Building package..."
cd "$SRC_DIR"
dpkg-buildpackage -us -uc -b

# Move the built packages to output directory
echo ""
echo "Moving packages to output directory..."
mkdir -p "$SCRIPT_DIR/dist"
BUILT_PACKAGES=("$BUILD_DIR"/"${PACKAGE_NAME}_"*.deb)
if [[ ! -e "${BUILT_PACKAGES[0]}" ]]; then
    echo "ERROR: dpkg-buildpackage did not create a $PACKAGE_NAME .deb file." >&2
    exit 1
fi
INSTALL_PACKAGE="${BUILT_PACKAGES[0]##*/}"
mv "${BUILT_PACKAGES[@]}" "$SCRIPT_DIR/dist/"
mv "$BUILD_DIR"/*.ddeb "$SCRIPT_DIR/dist/" 2>/dev/null || true
mv "$BUILD_DIR"/*.changes "$SCRIPT_DIR/dist/" 2>/dev/null || true
mv "$BUILD_DIR"/*.buildinfo "$SCRIPT_DIR/dist/" 2>/dev/null || true

# Cleanup
rm -rf "$BUILD_DIR"

echo ""
echo "=== Build Complete ==="
echo ""
echo "Package(s) created in: $SCRIPT_DIR/dist/"
ls -la "$SCRIPT_DIR/dist/"
echo ""
echo "Install with:"
echo "  sudo apt install \"$SCRIPT_DIR/dist/$INSTALL_PACKAGE\""
echo ""
