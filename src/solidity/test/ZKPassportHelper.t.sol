// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {ZKPassportHelper} from "../src/ZKPassportHelper.sol";
import {NullifierType} from "../src/Types.sol";
import {IRootRegistry} from "../src/IRootRegistry.sol";
import {MockRootRegistry} from "./MockRootRegistry.sol";

// Testing mainly the ordering of trailing public inputs 
// (last 3 elements, in order):
//   [length-3] nullifier_type
//   [length-2] scoped_nullifier
//   [length-1] oprf_pk_hash
contract ZKPassportHelperTest is Test {
  ZKPassportHelper helper;

  bytes32 constant SCOPED_NULLIFIER = bytes32(uint256(0xdead));
  bytes32 constant OPRF_PK_HASH = bytes32(uint256(0xbeef));

  function setUp() public {
    IRootRegistry rootRegistry = new MockRootRegistry();
    helper = new ZKPassportHelper(rootRegistry);
  }

  // Builds a minimal publicInputs array with 2 param commitments + the 3 trailing fields.
  function _buildPublicInputs(uint256 nullifierTypeValue) internal pure returns (bytes32[] memory) {
    bytes32[] memory publicInputs = new bytes32[](5);
    publicInputs[0] = bytes32(uint256(0xa1)); // param commitment
    publicInputs[1] = bytes32(uint256(0xa2)); // param commitment
    publicInputs[2] = bytes32(nullifierTypeValue);
    publicInputs[3] = SCOPED_NULLIFIER;
    publicInputs[4] = OPRF_PK_HASH;
    return publicInputs;
  }

  function test_GetNullifierType_AllVariants() public view {
    assertEq(
      uint256(helper.getNullifierType(_buildPublicInputs(0))),
      uint256(NullifierType.NON_SALTED_NULLIFIER)
    );
    assertEq(
      uint256(helper.getNullifierType(_buildPublicInputs(1))),
      uint256(NullifierType.SALTED_NULLIFIER)
    );
    assertEq(
      uint256(helper.getNullifierType(_buildPublicInputs(2))),
      uint256(NullifierType.NON_SALTED_MOCK_NULLIFIER)
    );
    assertEq(
      uint256(helper.getNullifierType(_buildPublicInputs(3))),
      uint256(NullifierType.SALTED_MOCK_NULLIFIER)
    );
  }

  function test_IsSaltedNullifier() public view {
    assertEq(helper.isSaltedNullifier(_buildPublicInputs(0)), false); // NON_SALTED
    assertEq(helper.isSaltedNullifier(_buildPublicInputs(1)), true);  // SALTED
    assertEq(helper.isSaltedNullifier(_buildPublicInputs(2)), false); // NON_SALTED_MOCK
    assertEq(helper.isSaltedNullifier(_buildPublicInputs(3)), true);  // SALTED_MOCK
  }

  function test_GetOprfPubKeyHash() public view {
    bytes32 result = helper.getOprfPubKeyHash(_buildPublicInputs(1));
    assertEq(result, OPRF_PK_HASH);
    assertTrue(result != SCOPED_NULLIFIER);
  }

  function test_VerifyOprfPubKeyHash_Matches() public view {
    assertEq(helper.verifyOprfPubKeyHash(_buildPublicInputs(1), OPRF_PK_HASH), true);
  }

  function test_VerifyOprfPubKeyHash_Mismatches() public view {
    bytes32 wrongHash = bytes32(uint256(0xcafe));
    assertEq(helper.verifyOprfPubKeyHash(_buildPublicInputs(1), wrongHash), false);
  }

  function test_VerifyOprfPubKeyHash_ZeroForNonSalted() public view {
    // Build inputs with oprf_pk_hash = 0 (as non-salted proofs should produce).
    bytes32[] memory publicInputs = new bytes32[](5);
    publicInputs[0] = bytes32(uint256(0xa1));
    publicInputs[1] = bytes32(uint256(0xa2));
    publicInputs[2] = bytes32(uint256(0)); // NON_SALTED
    publicInputs[3] = SCOPED_NULLIFIER;
    publicInputs[4] = bytes32(0);
    assertEq(helper.verifyOprfPubKeyHash(publicInputs, bytes32(0)), true);
  }
}
