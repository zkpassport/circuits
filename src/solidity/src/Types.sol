// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

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

struct ProofVerificationData {
  bytes32 vkeyHash;
  bytes proof;
  bytes32[] publicInputs;
}

struct Commitments {
  bytes committedInputs;
  uint256[] committedInputCounts;
}

struct ServiceConfig {
  uint256 validityPeriodInSeconds;
  string domain;
  string scope;
  bool devMode;
}

// Group parameters for the proof verification
//
// publicInputs:
// - 0: certificate_registry_root: pub Field,
// - 1: circuit_registry_root: pub Field,
// - 2: current_date: pub u64,
// - 3: service_scope: pub Field,
// - 4: service_subscope: pub Field,
// - 5:5+N: param_commitments: pub [Field; N],
// - 5+N: nullifier_type: pub u8,
// - 6+N: scoped_nullifier: pub Field,
//
// committedInputs: the preimages of the `param_commitments` of the disclosure proofs.
// committedInputCounts: offsets to locate the committedInputs of each of the param_commitments of the public_inputs.
struct ProofVerificationParams {
  ProofVerificationData proofVerificationData;
  Commitments commitments;
  ServiceConfig serviceConfig;
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