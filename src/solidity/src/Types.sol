// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

struct ProofVerifier {
  bytes32 vkeyHash;
  address verifier;
}

enum ProofType {
  DISCLOSE,
  AGE,
  BIRTHDATE,
  EXPIRY_DATE,
  NATIONALITY_INCLUSION,
  NATIONALITY_EXCLUSION,
  ISSUING_COUNTRY_INCLUSION,
  ISSUING_COUNTRY_EXCLUSION,
  BIND,
  SANCTIONS,
  FACEMATCH
}

enum BoundDataIdentifier {
  NONE,
  USER_ADDRESS,
  CHAIN_ID,
  CUSTOM_DATA
}

enum FaceMatchMode {
  NONE,
  REGULAR,
  STRICT
}

enum Environment {
  DEVELOPMENT,
  PRODUCTION
}

enum NullifierType {
  NON_SALTED_NULLIFIER,
  SALTED_NULLIFIER,
  NON_SALTED_MOCK_NULLIFIER,
  SALTED_MOCK_NULLIFIER
}

enum OS {
  ANY,
  IOS,
  ANDROID
}

// ProofVerificationParams
// │
// ├── bytes32 version                        // Version identifier of the verifier
// │
// ├── ProofVerificationData proofVerificationData
// │   ├── bytes32 vkeyHash                   // Verification key hash
// │   ├── bytes proof                        // The actual ZK proof
// │   └── bytes32[] publicInputs             // Array of public inputs (7+ elements)
// │       │                                  // Use PublicInputsCast.asStruct() for structured access:
// │       ├── [0] certificate_registry_root  // Field - struct.certificateRegistryRoot
// │       ├── [1] circuit_registry_root      // Field - struct.circuitRegistryRoot
// │       ├── [2] current_date               // u64 - PublicInputsCast.getCurrentDate(struct)
// │       ├── [3] service_scope              // Field - struct.serviceScope
// │       ├── [4] service_subscope           // Field - struct.serviceSubscope
// │       ├── [5:5+N] param_commitments      // Field[N] - PublicInputsCast.getParamCommitment(array, index)
// │       ├── [5+N] nullifier_type           // u8 - PublicInputsCast.getNullifierType(array, paramCount)
// │       └── [6+N] scoped_nullifier         // Field - PublicInputsCast.getScopedNullifier(array, paramCount)
// │
// ├── bytes committedInputs              // Preimages of param_commitments
// │
// └── ServiceConfig serviceConfig
//     ├── uint256 validityPeriodInSeconds    // How long the proof is valid
//     ├── string domain                      // Service domain
//     ├── string scope                       // Service scope
//     └── bool devMode                       // Development mode flag
struct ProofVerificationParams {
  bytes32 version;
  ProofVerificationData proofVerificationData;
  bytes committedInputs;
  ServiceConfig serviceConfig;
}

struct ProofVerificationData {
  bytes32 vkeyHash;
  bytes proof;
  bytes32[] publicInputs;
}

struct ServiceConfig {
  uint256 validityPeriodInSeconds;
  string domain;
  string scope;
  bool devMode;
}

struct DisclosedData {
  string name;
  string issuingCountry;
  string nationality;
  string gender;
  string birthDate;
  string expiryDate;
  string documentNumber;
  string documentType;
}

struct BoundData {
  address senderAddress;
  uint256 chainId;
  string customData;
}
