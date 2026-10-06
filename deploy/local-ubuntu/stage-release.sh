#!/usr/bin/env bash
# Copy reviewed code into a trusted release before the root service executes it.
set -euo pipefail
[[ $EUID = 0 && $# = 3 ]] || { echo 'Usage: sudo stage-release.sh SOURCE BINARY RELEASE_ID' >&2; exit 1; }
source_dir=$(realpath "$1")
binary=$(realpath "$2")
release=$3
[[ $release =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$ ]] || { echo 'Invalid release ID.' >&2; exit 1; }
[[ -f $binary && -x $binary && -f $source_dir/scripts/disposable-runtime.py ]] || exit 1
destination=/opt/agentic-sandbox/releases/$release
[[ ! -e $destination ]] || { echo 'Release already exists; select a new ID.' >&2; exit 1; }
install -d -m 0755 /opt/agentic-sandbox/releases "$destination"
for folder in scripts images deploy/local-ubuntu; do
  install -d "$destination/$folder"
  rsync -r --exclude '__pycache__' --exclude '*.pyc' --exclude 'target' \
    "$source_dir/$folder/" "$destination/$folder/"
done
# rsync -r intentionally rejects source symlinks instead of copying link targets.
install -m 0755 "$binary" "$destination/agentic-management"
chown -R root:root "$destination"
chmod -R go-w "$destination"
find "$destination/scripts" "$destination/deploy/local-ubuntu" -type f -name '*.sh' -exec chmod 0755 {} +
ln -sfn "$destination" /opt/agentic-sandbox/current
echo "Trusted release staged: $release"
