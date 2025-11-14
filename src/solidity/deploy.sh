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
DEPLOY_SCRIPT="script/Deploy.s.sol"

echo "Deploying to $NETWORK..."

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

  # Deploy to local Anvil
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
  # For Sepolia, check if ETHERSCAN_API_KEY is set
  if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "Warning: ETHERSCAN_API_KEY not set. Contract verification will be skipped."
    # Deploy to Sepolia without verification, with gas settings and sequential broadcasting
    echo "Deploying with gas settings: Gas Price=$GAS_PRICE, Priority Fee=$PRIORITY_FEE, Retries=$TX_RETRIES"
    forge script $DEPLOY_SCRIPT \
      --rpc-url $SEPOLIA_RPC_URL \
      --broadcast \
      --retries 10 \
      --slow \
      --delay 2 \
      --timeout 300
  else
    # Deploy to Sepolia with verification, with gas settings and sequential broadcasting
    echo "Deploying with gas settings: Gas Price=$GAS_PRICE, Priority Fee=$PRIORITY_FEE, Retries=$TX_RETRIES"
    forge script $DEPLOY_SCRIPT \
      --rpc-url $SEPOLIA_RPC_URL \
      --broadcast \
      --verify \
      --retries 10 \
      --slow \
      --delay 2 \
      --timeout 300
  fi
elif [ "$NETWORK" = "ethereum" ]; then
  # Check if environment variables are set
  if [ -z "$MAINNET_RPC_URL" ] || [ -z "$PRIVATE_KEY" ]; then
    echo "Error: Required environment variables not set"
    echo "Please set MAINNET_RPC_URL and PRIVATE_KEY in your .env file or environment"
    echo "You can copy .env.example to .env and fill in your values"
    exit 1
  fi
  # For Ethereum, check if ETHERSCAN_API_KEY is set
  if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "Warning: ETHERSCAN_API_KEY not set. Contract verification will be skipped."
    # Deploy to Ethereum without verification, with gas settings and sequential broadcasting
    echo "Deploying with gas settings: Gas Price=$GAS_PRICE, Priority Fee=$PRIORITY_FEE, Retries=$TX_RETRIES"
    forge script $DEPLOY_SCRIPT \
      --rpc-url $MAINNET_RPC_URL \
      --broadcast \
      --retries 10 \
      --slow \
      --delay 2 \
      --timeout 300
  else
    # Deploy to Ethereum with verification, with gas settings and sequential broadcasting
    echo "Deploying with gas settings: Gas Price=$GAS_PRICE, Priority Fee=$PRIORITY_FEE, Retries=$TX_RETRIES"
    forge script $DEPLOY_SCRIPT \
      --rpc-url $MAINNET_RPC_URL \
      --broadcast \
      --verify \
      --retries 10 \
      --slow \
      --delay 2 \
      --timeout 300
  fi
elif [ "$NETWORK" = "base" ]; then
  # Check if environment variables are set
  if [ -z "$BASE_RPC_URL" ] || [ -z "$PRIVATE_KEY" ]; then
    echo "Error: Required environment variables not set"
    echo "Please set BASE_RPC_URL and PRIVATE_KEY in your .env file or environment"
    echo "You can copy .env.example to .env and fill in your values"
    exit 1
  fi
  # For Base, check if ETHERSCAN_API_KEY is set
  if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "Warning: ETHERSCAN_API_KEY not set. Contract verification will be skipped."
    # Deploy to Base without verification, with gas settings and sequential broadcasting
    echo "Deploying with gas settings: Gas Price=$GAS_PRICE, Priority Fee=$PRIORITY_FEE, Retries=$TX_RETRIES"
    forge script $DEPLOY_SCRIPT \
      --rpc-url $BASE_RPC_URL \
      --broadcast \
      --retries 10 \
      --slow \
      --delay 2 \
      --timeout 300
  else
    # Deploy to Base with verification, with gas settings and sequential broadcasting
    echo "Deploying with gas settings: Gas Price=$GAS_PRICE, Priority Fee=$PRIORITY_FEE, Retries=$TX_RETRIES"
    forge script $DEPLOY_SCRIPT \
      --rpc-url $BASE_RPC_URL \
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
  echo "Usage: ./deploy.sh [network]"
  echo "  network: anvil or sepolia (default: anvil)"
  exit 1
fi
