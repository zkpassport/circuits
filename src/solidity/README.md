# Foundry Sepolia Deployment Project

This project demonstrates a basic Foundry project with deployment scripts for Ethereum Sepolia.

## Getting Started

### Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- An Ethereum wallet with some Sepolia ETH
- Infura or Alchemy account for RPC URL
- Etherscan API key (optional, for verification)

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
ETHERSCAN_API_KEY=your_etherscan_api_key_here
```

## Usage

### Compile

```bash
forge build
```

### Test

```bash
forge test
```

### Deploy to Sepolia

Deploy the Verifier contract:

```bash
forge script script/Deploy.s.sol:Deploy --rpc-url sepolia --broadcast --verify
```

## Additional Resources

- [Foundry Book](https://book.getfoundry.sh/)
- [Sepolia Faucet](https://sepoliafaucet.com/)
- [Etherscan Sepolia](https://sepolia.etherscan.io/)
