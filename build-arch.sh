#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$SCRIPT_DIR/packaging/arch"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
    echo "Usage: $0 [makepkg args...]"
    echo "Builds and installs the Arch package from packaging/arch/."
    echo "Examples:"
    echo "  $0"
    echo "  $0 --noconfirm"
    exit 0
fi

cd "$PKG_DIR"
exec makepkg -si --syncdeps --cleanbuild "$@"
