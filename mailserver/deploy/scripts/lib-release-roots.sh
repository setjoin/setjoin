#!/usr/bin/env bash
# Release trust roots for `setjoin-updater adopt-current-layout` (#507).
# The updater authenticates an existing managed `current` release against the
# vendor's PUBLIC release roots (not secret). The release package ships them as
# server-rust/release-roots.json (built from SETJOIN_RELEASE_TRUST_ROOTS, see
# scripts/package-server-release.sh); this installs them root-owned 0644 BEFORE
# adoption runs, on first install and on every upgrade. Sourced by install.sh;
# needs die/info from the caller.

# install_release_roots PACKAGE_COPY DEST INSTALL_DIR
install_release_roots() {
  local src=$1 dest=$2 install_dir=$3 tmp
  if [ -f "$src" ] && [ ! -L "$src" ]; then
    [ -s "$src" ] || die "release trust roots in the package ($src) are empty."
    install -d -m 0755 -o root -g root "$(dirname -- "$dest")"
    tmp=$(mktemp "$dest.XXXXXXXX") || die "cannot stage release trust roots next to $dest."
    install -m 0644 -o root -g root "$src" "$tmp" && mv -f -- "$tmp" "$dest" \
      || { rm -f -- "$tmp"; die "could not install release trust roots to $dest."; }
    info "Release trust roots installed at $dest."
    return 0
  fi
  if [ -f "$dest" ] && [ ! -L "$dest" ] && [ "$(stat -c %u -- "$dest")" = 0 ]; then
    info "Using operator-provisioned release trust roots at $dest."
    return 0
  fi
  if [ -L "$install_dir/current" ]; then
    die "this install already runs a managed release, and adopting it requires the vendor release trust roots, which this package does not contain. Place the vendor's release-roots.json (public keys, root-owned, mode 0644) at $dest, or use a release package built with SETJOIN_RELEASE_TRUST_ROOTS, then re-run the installer."
  fi
  info "No release trust roots present (first install of a flat layout needs none)."
}
