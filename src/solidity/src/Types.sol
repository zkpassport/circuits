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
  SANCTIONS
}

enum BoundDataIdentifier {
  NONE,
  USER_ADDRESS,
  CHAIN_ID,
  CUSTOM_DATA
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
// - 5+N: scoped_nullifier: pub Field,
//
// committedInputs: the preimages of the `param_commitments` of the disclosure proofs.
// committedInputCounts: offsets to locate the committedInputs of each of the param_commitments of the public_inputs.
struct ProofVerificationParams {
  bytes32 vkeyHash;
  bytes proof;
  bytes32[] publicInputs;
  bytes committedInputs;
  uint256[] committedInputCounts;
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