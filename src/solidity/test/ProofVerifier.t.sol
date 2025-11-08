// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {IProofVerifier} from "../src/IProofVerifier.sol";
import {HonkVerifier} from "../src/ultra-honk-verifiers/OuterCount5.sol";
import {ZKPassportTest} from "./Utils.t.sol";

contract SubVerifierTest is ZKPassportTest {
  IProofVerifier public verifier;

  function setUp() public {
    verifier = IProofVerifier(address(new HonkVerifier()));
  }

  function test_VerifyValidProof() public {
    FixtureData memory data = loadFixture(fixtures.valid);

    // Verify the proof
    vm.startSnapshotGas("UltraHonkVerifier verify");
    bool result = verifier.verify(data.proof, data.publicInputs);
    uint256 gasUsed = vm.stopSnapshotGas();
    console.log("Gas used in UltraHonkVerifier verify");
    console.log(gasUsed);
    assertEq(result, true);
  }

  /**
   * @dev Test with a properly sized but mathematically invalid proof
   * We expect verification to revert with SumcheckFailed
   */
  function test_VerifyWithDummyProof() public {
    // Create a dummy proof with the exact required size (317 * 32 = 14624 bytes)
    bytes memory proof = new bytes(10144);

    // Generate some random values for the proof
    for (uint256 i = 0; i < 10144; i++) {
      proof[i] = bytes1(uint8(i % 256));
    }

    // Create a dummy public inputs array with the required size (9)
    bytes32[] memory publicInputs = new bytes32[](9);

    // Fill with some values
    for (uint256 i = 0; i < 9; i++) {
      publicInputs[i] = bytes32(uint256(i));
    }

    // Expect the SumcheckFailed error
    vm.expectRevert();
    verifier.verify(proof, publicInputs);
  }

  /**
   * @dev Test with an incorrectly sized proof
   * We expect it to revert with ProofLengthWrong
   */
  function test_VerifyInvalidProofLength() public {
    vm.expectRevert();
    verifier.verify(bytes(""), new bytes32[](0));
  }
}
