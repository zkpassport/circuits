set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ANVIL_RPC="${ANVIL_RPC:-http://localhost:8546}"
# Anvil's #0
ANVIL_PRIVATE_KEY="${ANVIL_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

CIRCUIT_VERSION_SEMVER="0.18.0"
CIRCUIT_VERSION=$(printf "0x%04x%04x%04x%052d" ${CIRCUIT_VERSION_SEMVER//./ } 0)
echo "Circuit version: ${CIRCUIT_VERSION_SEMVER} -> ${CIRCUIT_VERSION}"

# OPRF global key hash pinned on-chain. By default it's left unset (bytes32(0)) — the stack
# deploys without a running OPRF node, but salted/OPRF proofs fail closed. Set FETCH_OPRF_KEY=true
# to fetch the local OPRF node's public key for OPRF_KEY_ID and hash it (Poseidon2(pk.x, pk.y));
# that's the key the OPRF network signs with, required for salted verification to pass.
FETCH_OPRF_KEY="${FETCH_OPRF_KEY:-false}"
OPRF_NODE_URL="${OPRF_NODE_URL:-http://127.0.0.1:10000}"
OPRF_KEY_ID="${OPRF_KEY_ID:-1}"
if [[ "${FETCH_OPRF_KEY}" == "true" ]]; then
  PK_HASH=$(OPRF_NODE_URL="$OPRF_NODE_URL" OPRF_KEY_ID="$OPRF_KEY_ID" npx tsx -e '
import { poseidon2HashAsync } from "@zkpassport/poseidon2"
;(async () => {
  const res = await fetch(`${process.env.OPRF_NODE_URL}/oprf_pub/${process.env.OPRF_KEY_ID}`)
  if (!res.ok) throw new Error(`OPRF node returned ${res.status}`)
  const { key } = await res.json()
  const h = await poseidon2HashAsync([BigInt(key[0]), BigInt(key[1])])
  console.log("0x" + h.toString(16).padStart(64, "0"))
})()
')
  if [[ -z "${PK_HASH}" ]]; then
    echo "ERROR: failed to read OPRF pubkey from ${OPRF_NODE_URL}/oprf_pub/${OPRF_KEY_ID}" >&2
    exit 1
  fi
  echo "OPRF pk hash (key id ${OPRF_KEY_ID}): ${PK_HASH}"
else
  PK_HASH="0x0000000000000000000000000000000000000000000000000000000000000000"
  echo "OPRF pk hash: unset (FETCH_OPRF_KEY!=true) — salted proofs will fail closed"
fi

echo "Deploying verifier stack to ${ANVIL_RPC}..."
cd "$ROOT/src/solidity"

GLOBAL_OPRF_PK_HASH="${PK_HASH}" CIRCUIT_VERSION="${CIRCUIT_VERSION}" forge script script/DeployAnvil.s.sol \
  --rpc-url "${ANVIL_RPC}" \
  --broadcast \
  --private-key "${ANVIL_PRIVATE_KEY}" \
  -vv

# anvil only advances block.timestamp when it mines, so an idle node's clock drifts behind real
# time and on-chain verification fails the proof validity-period check (DateUtils.isDateValid).
# Run this to make anvil mine every second so block.timestamp tracks real time:
echo
echo "To keep anvil's clock current (avoids the proof validity-period revert), run:"
echo "  cast rpc evm_setIntervalMining 10 --rpc-url ${ANVIL_RPC}"
