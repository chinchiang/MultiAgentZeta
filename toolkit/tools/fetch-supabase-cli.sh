#!/bin/sh
# Fetch the Supabase CLI pinned in toolkit/support-matrix.json (TK-SCP-001), verify the archive
# and binary digests, and print the binary's path for MAZ_SUPABASE_BIN. The environment tests and
# the env-tests CI job both use this script, so the matrix stays the single source.
#
#   toolkit/tools/fetch-supabase-cli.sh [DEST_DIR]    # default: scratch/tools/sbcli (survives reboots)
#   export MAZ_SUPABASE_BIN="$(toolkit/tools/fetch-supabase-cli.sh)"
#
# A binary already in DEST_DIR is reused when its digest matches. Progress goes to stderr; stdout
# carries only the path.
set -eu
repo=$(cd "$(dirname "$0")/../.." && pwd)
dest=${1:-"$repo/scratch/tools/sbcli"}
matrix="$repo/toolkit/support-matrix.json"
field() { python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["tools"]["supabase-cli"][sys.argv[2]])' "$matrix" "$1"; }
ver=$(field version); archive_sha=$(field archive_sha256); binary_sha=$(field binary_sha256)

mkdir -p "$dest"
bin="$dest/supabase"
if [ -f "$bin" ] && echo "$binary_sha  $bin" | sha256sum -c --status -; then
  echo "supabase-cli $ver already in $dest (digest verified)" >&2
else
  echo "fetching supabase-cli $ver into $dest" >&2
  curl -fsSL -o "$dest/cli.tar.gz" "https://github.com/supabase/cli/releases/download/v$ver/supabase_linux_amd64.tar.gz"
  echo "$archive_sha  $dest/cli.tar.gz" | sha256sum -c - >&2
  tar -xzf "$dest/cli.tar.gz" -C "$dest" supabase
  rm "$dest/cli.tar.gz"
  echo "$binary_sha  $bin" | sha256sum -c - >&2
fi
echo "$bin"
