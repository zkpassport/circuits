# Foundry Deployment Project

This project holds ZKPassport's Solidity verifiers, some tests and the deployment scripts to deploy
them on any EVM chain.

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- An Ethereum wallet with some Sepolia ETH (for Sepolia deployments)
- Infura or Alchemy account for RPC URL (for Sepolia deployments)
- Etherscan API key (optional, only for verification on Sepolia)

### Installation

1. Clone this repository

2. Install dependencies:

```bash
cd src/solidity
forge install
```

3. Create a `.env` file:

```bash
cp .env.example .env
```

4. Fill in your environment variables in the `.env` file:

```
PRIVATE_KEY=your_private_key_here
SEPOLIA_RPC_URL=https://sepolia.infura.io/v3/your_infura_key_here
ETHERSCAN_API_KEY=your_etherscan_api_key_here  # Only needed for Sepolia verification
```

Note: For local Anvil deployments, you don't need to set these environment variables.

## Usage

### Compile

```bash
forge build
```

### Test

```bash
forge test
```

### Deployment

You can deploy to both a local Anvil instance and Sepolia testnet using the provided script.

#### Deploy to Local Anvil

The script will automatically start an Anvil instance if one is not already running and will skip
contract verification:

```bash
cd src/solidity
./deploy.sh
# or explicitly
./deploy.sh anvil
```

#### Deploy to Sepolia

Make sure you have set the required environment variables in your `.env` file:

```bash
cd src/solidity
./deploy.sh sepolia
```

If `ETHERSCAN_API_KEY` is set, the script will attempt to verify the contracts on Etherscan. If not
set, verification will be skipped but deployment will still proceed.

### Manual Deployment

If you prefer to deploy manually without using the script:

#### Local Anvil

Start an Anvil instance:

```bash
anvil
```

In a separate terminal:

```bash
forge script script/Deploy.s.sol --rpc-url anvil --broadcast
```

#### Sepolia

With verification:

```bash
forge script script/Deploy.s.sol --rpc-url sepolia --broadcast --verify
```

Without verification:

```bash
forge script script/Deploy.s.sol --rpc-url sepolia --broadcast
```

## Additional Resources

- [Foundry Book](https://book.getfoundry.sh/)
- [Sepolia Faucet](https://sepoliafaucet.com/)
- [Etherscan Sepolia](https://sepolia.etherscan.io/)
