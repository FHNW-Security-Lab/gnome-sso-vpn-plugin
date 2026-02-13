#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$SCRIPT_DIR"

"$REPO_ROOT/build-deb.sh" "$@"

echo "GNOME plugin artifacts collected under: $REPO_ROOT/dist/"
