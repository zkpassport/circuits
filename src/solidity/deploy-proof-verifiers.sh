#!/bin/bash

# Load environment variables from .env file if it exists
if [ -f .env ]; then
  echo "Loading environment variables from .env file..."
  set -o allexport
  source .env
  set +o allexport
fi

# Default to anvil if no network is specified
NETWORK=${1:-anvil}

# The script we'll be using
DEPLOY_SCRIPT="script/DeployProofVerifiers.s.sol"

echo "Deploying proof verifiers to $NETWORK..."

if [ "$NETWORK" = "anvil" ]; then
  # Start anvil in the background if it's not already running
  export ETHERSCAN_API_KEY=""

  # Check if SEPOLIA_RPC_URL is set for forking
  if [ -z "$SEPOLIA_RPC_URL" ]; then
    echo "Error: SEPOLIA_RPC_URL not set for forking"
    echo "Please set SEPOLIA_RPC_URL in your .env file or environment"
    echo "You can copy .env.example to .env and fill in your values"
    exit 1
  fi

  if ! nc -z localhost 8545 &>/dev/null; then
    echo "Starting Anvil node forked from Sepolia..."
    anvil --fork-url $SEPOLIA_RPC_URL --chain-id 31337 &
    ANVIL_PID=$!
    # Give anvil a moment to start
    sleep 2
    echo "Anvil started with PID: $ANVIL_PID"

    # Use a default private key for Anvil
    export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  else
    echo "Anvil is already running"
    echo "Note: Existing Anvil instance might not be forking from Sepolia"
    # Use a default private key for Anvil
    export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  fi

  # Check if deployment file exists for the current chain
  DEPLOYMENT_FILE="./deployments/deployment-31337.json"
  if [ ! -f "$DEPLOYMENT_FILE" ]; then
    echo "Error: Deployment file not found at $DEPLOYMENT_FILE"
    echo "Please run the initial deployment first using ./deploy.sh anvil"
    exit 1
  fi

  # Deploy proof verifiers to local Anvil
  forge script $DEPLOY_SCRIPT --rpc-url anvil --broadcast \
    --retries 3 \
    --slow \
    --delay 2 \
    --timeout 300

  # If we started anvil in this script, ask if we should stop it
  if [ ! -z "$ANVIL_PID" ]; then
    read -p "Do you want to stop the Anvil node? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      kill $ANVIL_PID
      echo "Anvil node stopped"
    fi
  fi

elif [ "$NETWORK" = "sepolia" ]; then
  # Check if environment variables are set
  if [ -z "$SEPOLIA_RPC_URL" ] || [ -z "$PRIVATE_KEY" ]; then
    echo "Error: Required environment variables not set"
    echo "Please set SEPOLIA_RPC_URL and PRIVATE_KEY in your .env file or environment"
    echo "You can copy .env.example to .env and fill in your values"
    exit 1
  fi

  # Check if deployment file exists for Sepolia
  DEPLOYMENT_FILE="./deployments/deployment-11155111.json"
  if [ ! -f "$DEPLOYMENT_FILE" ]; then
    echo "Error: Deployment file not found at $DEPLOYMENT_FILE"
    echo "Please run the initial deployment first using ./deploy.sh sepolia"
    exit 1
  fi

  # For Sepolia, check if ETHERSCAN_API_KEY is set
  if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "Warning: ETHERSCAN_API_KEY not set. Contract verification will be skipped."
    # Deploy proof verifiers to Sepolia without verification, with gas settings and sequential broadcasting
    echo "Deploying proof verifiers with gas settings: Gas Price=$GAS_PRICE, Priority Fee=$PRIORITY_FEE, Retries=$TX_RETRIES"
    forge script $DEPLOY_SCRIPT \
      --rpc-url $SEPOLIA_RPC_URL \
      --broadcast \
      --retries 10 \
      --slow \
      --delay 2 \
      --timeout 300
  else
    # Deploy proof verifiers to Sepolia with verification, with gas settings and sequential broadcasting
    echo "Deploying proof verifiers with gas settings: Gas Price=$GAS_PRICE, Priority Fee=$PRIORITY_FEE, Retries=$TX_RETRIES"
    forge script $DEPLOY_SCRIPT \
      --rpc-url $SEPOLIA_RPC_URL \
      --broadcast \
      --verify \
      --retries 10 \
      --slow \
      --delay 2 \
      --timeout 300
  fi
else
  echo "Unsupported network: $NETWORK"
  echo "Supported networks: anvil, sepolia"
  echo "Usage: ./deploy-proof-verifiers.sh [network]"
  echo "  network: anvil or sepolia (default: anvil)"
  exit 1
fi

echo "Finished deploying proof verifiers!"
echo "Check the deployments folder for the generated proof verifiers JSON file."
