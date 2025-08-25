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
ROOT_REGISTRY_ADDRESS=0xB6bF4a45D5Ed1363C45BD0e4cbaDCcd48F8D3FaB
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

## Deployment

### Environment Setup

This project uses environment variables for deployment configuration. There are two ways to set them
up:

1. **Using a `.env` file (recommended):**

   - Copy `.env.example` to `.env`
   - Fill in your values in the `.env` file
   - The deployment script will automatically load these values

2. **Using environment variables directly:**
   - Export the required variables in your terminal:
     ```bash
     export PRIVATE_KEY=your_private_key_here
     export SEPOLIA_RPC_URL=your_sepolia_rpc_url
     export ETHERSCAN_API_KEY=your_etherscan_api_key  # Optional for verification
     ```

### Running Deployments

To deploy to different networks:

```bash
# Deploy to local Anvil node (default)
./deploy.sh

# Deploy to Sepolia testnet
./deploy.sh sepolia
```

The script will automatically:

- Load environment variables from `.env` if present
- Check if required variables are set
- Display helpful error messages if something is missing
- Use the appropriate RPC URL for the selected network

## Additional Resources

- [Foundry Book](https://book.getfoundry.sh/)
- [Sepolia Faucet](https://sepoliafaucet.com/)
- [Etherscan Sepolia](https://sepolia.etherscan.io/)
