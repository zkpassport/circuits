#!/bin/bash

LOCAL_DIR=${1:-null}
PORT=8545

# Note: got a crazy bug where foundry wouldnt deploy to anvil unless i changed the chain id
export CHAIN_ID=1337

SCRIPT_DIR=$(pwd)/$(dirname "$0")

# If the local directory is not null, use it, otherwise clone the zkpassport-packages repo
if [ "$LOCAL_DIR" = "null" ]; then
  git clone https://github.com/zkpassport/zkpassport-packages.git
  cd zkpassport-packages
  bun i
  bun run build
else
  cd $LOCAL_DIR
fi

# Move to the registry contracts directory
cd packages/registry-contracts

# Make sure the port is not in use
lsof -ti:${PORT} | xargs kill -9

# Start anvil in the background if it's not already running
anvil --port ${PORT} --chain-id $CHAIN_ID > /dev/null 2>&1 &

# Give anvil a moment to start
sleep 2

# Make the deploy and update-roots scripts executable
chmod +x script/bash/deploy.sh
chmod +x script/bash/update-roots.sh

# Deploy the contracts and capture the ROOT_REGISTRY_ADDRESS
DEPLOY_OUTPUT=$(script/bash/deploy.sh)
# Get the ROOT_REGISTRY_ADDRESS from the deploy output
export ROOT_REGISTRY_ADDRESS=$(echo "$DEPLOY_OUTPUT" | grep "RootRegistry deployed at:" | head -1 | awk '{print $NF}' | tr -d '\n\r')

# Get the certificate and circuit registry roots from the public inputs of the fixtures
export CERTIFICATE_REGISTRY_ROOT=$(jq -r '.inputs[0]' $SCRIPT_DIR/test/fixtures/all_subproofs_public_inputs.json)
export CIRCUIT_REGISTRY_ROOT=$(jq -r '.inputs[1]' $SCRIPT_DIR/test/fixtures/all_subproofs_public_inputs.json)
export SANCTIONS_REGISTRY_ROOT=0x06caac33440d8a83b838f07ba0e2bbe7e9889f10915efcb37396534f1feadac5

echo "Updating roots..."
echo "Root Registry: $ROOT_REGISTRY_ADDRESS"
echo "Certificate Registry Root: $CERTIFICATE_REGISTRY_ROOT"
echo "Circuit Registry Root: $CIRCUIT_REGISTRY_ROOT"
echo "Sanctions Registry Root: $SANCTIONS_REGISTRY_ROOT"

# Update the roots
script/bash/update-roots.sh

# Move back to the verifier contracts directory
cd $SCRIPT_DIR

# Run the tests
forge test --rpc-url http://localhost:${PORT} -vv

# Kill the anvil process
lsof -ti:${PORT} | xargs kill -9

echo "Tests completed successfully"

# If the tests were run based off a fresh clone of the zkpassport-packages repo, remove it
if [ "$LOCAL_DIR" = "null" ]; then
  rm -rf zkpassport-packages
fi