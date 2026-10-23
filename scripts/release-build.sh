#!/bin/bash

# Builds a release from a clean checkout into release/: the packaged circuits and their manifest,
# release.patch (what the build changed in tracked files) and build-info.json

set -euo pipefail

cd "$(dirname "$0")/.."

# Number of circuits to compile in parallel. Override with e.g.
# `JOBS=8 scripts/release-build.sh`.
JOBS="${JOBS:-20}"

OUT=release

fail() {
  echo "Error: $1" >&2
  exit 1
}

if [ -n "$(git status --porcelain)" ]; then
  fail "the checkout has local changes, which would end up in release.patch"
fi
for dir in target "$OUT"; do
  if [ -e "$dir" ]; then
    fail "$dir/ exists; a release is built from a clean checkout"
  fi
done
if [ ! -d src/solidity/lib/zkpassport-packages/packages ]; then
  fail "src/solidity/lib/zkpassport-packages is empty; run git submodule update --init"
fi

nargo_expected=$(node -p "require('./package.json').dependencies['@noir-lang/noir_js'].replace('^', '')")
bb_expected=$(node -p "require('./package.json').dependencies['@aztec/bb.js']")
nargo_installed=$(nargo --version | sed -n 's/^nargo version = //p')
bb_installed=$(bb --version | sed 's/^v//')
if [ "$nargo_installed" != "$nargo_expected" ]; then
  fail "nargo is $nargo_installed but package.json pins $nargo_expected"
fi
if [ "$bb_installed" != "$bb_expected" ]; then
  fail "bb is $bb_installed but package.json pins $bb_expected"
fi

durations=()
step() {
  local name=$1
  shift
  echo "=== $name"
  local started=$SECONDS
  "$@"
  durations+=("$name=$((SECONDS - started))")
}

step install npm ci
step compile npx tsx src/ts/scripts/circuit-builder.ts generate compile force --concurrency="$JOBS"
step format nargo fmt
step package npm run package-circuits
step fixtures npm run generate-fixtures
step test npm test
step test-contracts npm run test-contracts

mkdir "$OUT"
cp -R target/packaged "$OUT/packaged"

# The checkout started clean, so resetting after the diff leaves the index as it was
git add --all
git diff --cached --binary > "$OUT/release.patch"
git reset --quiet

durations_json=$(printf '%s\n' "${durations[@]}" | jq -R 'split("=") | {(.[0]): (.[1] | tonumber)}' | jq -s add)
jq -n \
  --arg commit "$(git rev-parse HEAD)" \
  --arg nargo "$nargo_installed" \
  --arg bb "$bb_installed" \
  --argjson durations "$durations_json" \
  --slurpfile manifest "$OUT/packaged/manifest.json" \
  '$manifest[0] as $m | {
    commit: $commit,
    version: $m.version,
    root: $m.root,
    nargo: $nargo,
    bb: $bb,
    outerEvmVkeyHashes: ($m.circuits | with_entries(select(.key | startswith("outer_evm_count_"))) | map_values(.hash)),
    durations: $durations
  }' > "$OUT/build-info.json"

echo "Release written to $OUT/"
