#!/bin/sh
# Fetch the Supabase CLI pinned in toolkit/support-matrix.json (TK-SCP-001), verify the archive
# and binary digests, and print the binary's path for MAZ_SUPABASE_BIN. The environment tests and
# the env-tests CI job both use this script, so the matrix stays the single source.
#
#   toolkit/tools/fetch-supabase-cli.sh [DEST_DIR]    # default: scratch/tools/sbcli (survives reboots)
#   export MAZ_SUPABASE_BIN="$(toolkit/tools/fetch-supabase-cli.sh)"
#
# A binary already in DEST_DIR is reused when its digest matches. Otherwise the archive is fetched and
# unpacked in a temporary directory inside DEST_DIR, and the binary is moved to DEST_DIR/supabase only
# after both digests matched: a failed or interrupted fetch leaves no DEST_DIR/supabase behind (TK-SUP-002).
# The matrix pins the Linux x86_64 build only. Progress goes to stderr; stdout carries only the path.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
dest=${1:-"$repo/scratch/tools/sbcli"}
matrix="$repo/toolkit/support-matrix.json"

os=$(uname -s); arch=$(uname -m)
if [ "$os" != Linux ] || { [ "$arch" != x86_64 ] && [ "$arch" != amd64 ]; }; then
  echo "fetch-supabase-cli: the support matrix pins the Linux x86_64 build only; this machine is $os $arch" >&2
  exit 1
fi

field() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["tools"]["supabase-cli"][sys.argv[2]])' "$matrix" "$1"; }
ver=$(field version); archive_sha=$(field archive_sha256); binary_sha=$(field binary_sha256)

mkdir -p "$dest"
bin="$dest/supabase"
if [ -f "$bin" ] && echo "$binary_sha  $bin" | sha256sum -c --status -; then
  echo "supabase-cli $ver already in $dest (digest verified)" >&2
else
  rm -f "$bin"  # not the pinned binary: never left where MAZ_SUPABASE_BIN would find it
  tmp=$(mktemp -d "$dest/.fetch.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  echo "fetching supabase-cli $ver into $dest" >&2
  curl -fsSL -o "$tmp/cli.tar.gz" "https://github.com/supabase/cli/releases/download/v$ver/supabase_linux_amd64.tar.gz"
  echo "$archive_sha  $tmp/cli.tar.gz" | sha256sum -c - >&2
  tar -xzf "$tmp/cli.tar.gz" -C "$tmp" supabase
  echo "$binary_sha  $tmp/supabase" | sha256sum -c - >&2
  mv -f "$tmp/supabase" "$bin"  # same directory tree, so the verified binary appears in one step
fi
echo "$bin"
