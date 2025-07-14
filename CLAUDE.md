# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is the zkpassport-circuits repository containing Noir zero-knowledge circuits for verifying electronic passport data. The project generates 700+ circuit variants to support different signature algorithms, hash functions, and certificate sizes used by passports worldwide.

## Key Commands

### Development
- `npm run lint` - Run TypeScript type checking
- `npm test` - Run Jest test suite
- `npm run generate` - Generate circuit templates from TypeScript
- `npm run compile` - Generate and compile Noir circuits (requires Nargo)
- `npm run package-circuits` - Package compiled circuits for deployment

### Testing Individual Tests
- `npm test -- <test-file-path>` - Run specific test file
- `npm test -- --testNamePattern="<test-name>"` - Run tests matching pattern

### Smart Contracts (from src/solidity/)
- `forge build` - Compile Solidity contracts
- `forge test` - Run contract tests
- `./deploy.sh` - Deploy to local Anvil
- `./deploy.sh sepolia` - Deploy to Sepolia testnet

### Circuit Analysis
- `scripts/info.sh <circuit-name>` - Get gate count for specific circuit
- `scripts/flamegraph.sh <circuit-name>` - Generate performance flamegraph
- `scripts/prove-honk.sh <circuit-name>` - Generate proof using Honk prover

## Architecture

### Circuit Generation System
The project uses a template-based system to generate hundreds of circuit variants:
1. **TypeScript templates** in `src/ts/scripts/circuit-builder.ts` define circuit patterns
2. **Generation phase** creates Noir code for each variant based on parameters
3. **Compilation phase** uses Nargo to compile Noir to bytecode and proving artifacts

### Circuit Naming Convention
Circuits follow pattern: `{signature_algorithm}_{hash_algorithm}_{curve/key_size}_{tbs_size}`
- Example: `ecdsa_sha256_secp256r1_1500` (ECDSA with SHA256 on secp256r1 curve, 1500-byte TBS)
- Example: `rsa_pss_sha256_2048_1200` (RSA-PSS with SHA256, 2048-bit key, 1200-byte TBS)

### Key Technologies
- **Noir**: Zero-knowledge proof language (Aztec)
- **Barretenberg**: Proving backend using Ultra Honk
- **TypeScript**: Circuit generation and testing infrastructure
- **Rust**: Certificate parsing (masterlist-interpreter) and parameter generation
- **Solidity**: On-chain proof verification contracts

### Testing Approach
- Integration tests in `src/ts/tests/` verify circuits with real and synthetic passport data
- Test data stored in `src/ts/tests/data/` includes sample certificates and passport data
- CSCA certificates from various countries in `src/ts/lib/cscas/` for validation

### Important Files
- `Nargo.toml` - Lists all circuit variants as workspace members
- `src/ts/scripts/circuit-builder.ts` - Main circuit generation logic
- `src/ts/lib/passport-generators/` - Tools for creating test passport data
- `src/noir/bin/` - Generated Noir circuit implementations
- `src/noir/lib/` - Shared Noir libraries (crypto primitives, utilities)

## Notes

- Circuit compilation is resource-intensive; CI only compiles a subset
- When modifying circuit templates, regenerate with `npm run generate` before compiling
- Proof generation requires significant memory (8GB+ recommended)
- Support for RSA, ECDSA, and DSA signature algorithms with various parameters
- Hash algorithm support: SHA1, SHA256, SHA384, SHA512

## Cryptographic Primitives

The 700+ circuit variants use the following cryptographic primitives:

### Digital Signature Algorithms

**RSA Signatures**
- Variants: RSA-PSS and RSA-PKCS#1 v1.5
- Key sizes: 1024, 2048, 3072, 4096 bits
- Hash algorithms: SHA-1, SHA-256, SHA-384, SHA-512
- Note: SHA-512 not supported with 1024-bit keys

**ECDSA (Elliptic Curve Digital Signature Algorithm)**
- NIST Curves:
  - P-256 (secp256r1) - 256-bit
  - P-384 (secp384r1) - 384-bit
  - P-521 (secp521r1) - 521-bit
- Brainpool Curves:
  - brainpoolP256r1, brainpoolP256t1 - 256-bit
  - brainpoolP384r1, brainpoolP384t1 - 384-bit
  - brainpoolP512r1, brainpoolP512t1 - 512-bit

### Hash Functions
- SHA-1 (20 bytes output)
- SHA-256 (32 bytes output)
- SHA-384 (48 bytes output)
- SHA-512 (64 bytes output)

### Zero-Knowledge Primitives
- **Poseidon2 Hash**: Used for commitments and nullifiers
- **Honk ZK Proof System**: Barretenberg/Aztec proving backend
- **Recursive Proofs**: 4-12 subproofs aggregation
- **Merkle Trees**: Binary trees with Poseidon2
  - Certificate Registry: 14 levels
  - Circuit Registry: 12 levels

### Privacy Features
- **Nullifier Schemes**:
  - Private: H(dg1, sod_signature)
  - Scoped: H(private_nullifier, service_scope, service_subscope)
- **Selective Disclosure**: Field-level privacy control
- **Binding Commitments**: Parameter binding for scope isolation

### Certificate Handling
- TBS sizes: 700, 1000, 1200, 1500, 1600 bytes
- X.509 certificate parsing and validation
- Public key extraction from certificates
- Support for certificate chains (CSCA → DSC → Passport)