#!/bin/bash

# Default to anvil if no network is specified
NETWORK=${1:-anvil}

echo "Deploying to $NETWORK..."

if [ "$NETWORK" = "anvil" ]; then
  # Start anvil in the background if it's not already running
  export ETHERSCAN_API_KEY=""
  if ! nc -z localhost 8545 &>/dev/null; then
    echo "Starting Anvil node..."
    anvil &
    ANVIL_PID=$!
    # Give anvil a moment to start
    sleep 2
    echo "Anvil started with PID: $ANVIL_PID"
    
    # Use a default private key for Anvil
    export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  else
    echo "Anvil is already running"
    # Use a default private key for Anvil
    export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  fi
  
  # Deploy to local Anvil
  forge script script/Deploy.s.sol --rpc-url anvil --broadcast
  
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
    echo "Please set SEPOLIA_RPC_URL and PRIVATE_KEY"
    exit 1
  fi
  
  # For Sepolia, check if ETHERSCAN_API_KEY is set
  if [ -z "$ETHERSCAN_API_KEY" ]; then
    echo "Warning: ETHERSCAN_API_KEY not set. Contract verification will be skipped."
    # Deploy to Sepolia without verification
    forge script script/Deploy.s.sol --rpc-url sepolia --broadcast
  else
    # Deploy to Sepolia with verification
    forge script script/Deploy.s.sol --rpc-url sepolia --broadcast --verify
  fi
else
  echo "Unsupported network: $NETWORK"
  echo "Supported networks: anvil, sepolia"
  exit 1
fi 