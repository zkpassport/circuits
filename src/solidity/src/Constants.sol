// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

// Is this not updateable?
bytes32 constant SANCTIONS_TREES_ROOT = 0x27cea23b989f5246d6577568d11cff22537f10fb47729dc004d1bf464ce37bd3;

// Not checked.
// Suggested comment to put here:
// The lengths of the preimages of the `param_commitments` of the various disclosure circuits.
library CommittedInputLen {
  uint256 constant COMPARE_AGE = 11;
  uint256 constant COMPARE_BIRTHDATE = 25;
  uint256 constant COMPARE_EXPIRY = 25;
  uint256 constant DISCLOSE_BYTES = 181;
  uint256 constant INCL_ISSUING_COUNTRY = 601;
  uint256 constant EXCL_ISSUING_COUNTRY = 601;
  uint256 constant INCL_NATIONALITY = 601;
  uint256 constant EXCL_NATIONALITY = 601;
  uint256 constant BIND = 501;
  uint256 constant SANCTIONS = 33;
}

// For the items above which have the same number, consider adding a test which
// simply asserts that they're all equal, so that if a maintainer of this repo
// ever does change one of these values, the test will fail and it'll prompt the
// dev to think about consequences of this.
// E.g. assert(COMPARE_BIRTHDATE == COMPARE_EXPIRY, "It looks like you've changed one of these constants. 
// There are baked-in assumptions that these values must always be equal. This assumption is relied upon by 
// 'getDateProofInputs'. You might break the protocol unless you think very carefully about the change you're making" );
// 
// Similar for the `601` items.
