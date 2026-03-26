#!/bin/bash
set -euo pipefail

REPO="clawfortify/clawfortify"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

detect_platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"

    case "$os" in
        Linux)  os="unknown-linux-gnu" ;;
        Darwin) os="apple-darwin" ;;
        *)      echo "Unsupported OS: $os"; exit 1 ;;
    esac

    case "$arch" in
        x86_64|amd64)   arch="x86_64" ;;
        aarch64|arm64)  arch="aarch64" ;;
        *)              echo "Unsupported architecture: $arch"; exit 1 ;;
    esac

    echo "${arch}-${os}"
}

get_latest_version() {
    curl -sL "https://api.github.com/repos/${REPO}/releases/latest" | \
        grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
}

main() {
    echo "Installing ClawFortify..."

    local platform version url tmp

    platform="$(detect_platform)"
    version="${1:-$(get_latest_version)}"

    if [ -z "$version" ]; then
        echo "Error: Could not determine latest version"
        exit 1
    fi

    url="https://github.com/${REPO}/releases/download/${version}/clawfortify-${platform}.tar.gz"
    tmp="$(mktemp -d)"

    echo "Downloading ${version} for ${platform}..."
    curl -fsSL "$url" | tar xz -C "$tmp"

    echo "Installing to ${INSTALL_DIR}/clawfortify..."
    sudo install -m 755 "${tmp}/clawfortify" "${INSTALL_DIR}/clawfortify"

    rm -rf "$tmp"
    echo "ClawFortify ${version} installed successfully."
    echo "Run 'clawfortify --help' to get started."
}

main "$@"
