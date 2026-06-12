set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

ANVIL_RPC="${ANVIL_RPC:-http://localhost:8546}"
# Anvil's #0
ANVIL_PRIVATE_KEY="${ANVIL_PRIVATE_KEY:-0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80}"

CIRCUIT_VERSION_SEMVER="0.18.0"
CIRCUIT_VERSION=$(printf "0x%04x%04x%04x%052d" ${CIRCUIT_VERSION_SEMVER//./ } 0)
echo "Circuit version: ${CIRCUIT_VERSION_SEMVER} -> ${CIRCUIT_VERSION}"

# Read the protocol-default global OPRF public key hash (Poseidon2(pk.x, pk.y)) from @zkpassport/utils.
PK_HASH=$(npx tsx -e 'import { DEFAULT_OPRF_PUB_KEY_HASH } from "@zkpassport/utils"; console.log("0x" + DEFAULT_OPRF_PUB_KEY_HASH.toString(16).padStart(64, "0"))')
if [[ -z "${PK_HASH}" ]]; then
  echo "ERROR: failed to read OPRF pubkey hash from @zkpassport/utils" >&2
  exit 1
fi
echo "OPRF pk hash: ${PK_HASH}"

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
echo "  cast rpc evm_setIntervalMining 1 --rpc-url ${ANVIL_RPC}"
