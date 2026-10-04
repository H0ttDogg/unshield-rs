#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
if [ ! -d upstream/unshield ]; then
    git clone https://github.com/twogood/unshield.git upstream/unshield
fi
git -C upstream/unshield checkout --detach cbed3d19ef9cdf4e5fb86b9d65e48f1bf8d539db
