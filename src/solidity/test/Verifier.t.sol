// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {IVerifier, HonkVerifier} from "../src/OuterCount5.sol";
import {TestUtils} from "./Utils.t.sol";

contract VerifierTest is TestUtils {
  IVerifier public verifier;

  // Path to the proof file - using files directly in project root
  string constant PROOF_PATH = "./test/fixtures/valid_proof.hex";
  string constant PUBLIC_INPUTS_PATH = "./test/fixtures/valid_public_inputs.json";

  function setUp() public {
    verifier = new HonkVerifier();
  }

  function test_VerifyValidProof() public {
    // Load proof and public inputs from files
    bytes memory proof = loadBytesFromFile(PROOF_PATH);
    bytes32[] memory publicInputs = loadBytes32FromFile(PUBLIC_INPUTS_PATH);

    // Verify the proof
    vm.startSnapshotGas("UltraHonkVerifier verify");
    bool result = verifier.verify(proof, publicInputs);
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
    // Create a dummy proof with the exact required size (440 * 32 = 14080 bytes)
    bytes memory proof = new bytes(14080);

    // Generate some random values for the proof
    for (uint i = 0; i < 14080; i++) {
      proof[i] = bytes1(uint8(i % 256));
    }

    // Create a dummy public inputs array with the required size (31)
    bytes32[] memory publicInputs = new bytes32[](31);

    // Fill with some values
    for (uint i = 0; i < 31; i++) {
      publicInputs[i] = bytes32(uint256(i));
    }

    // Expect the SumcheckFailed error
    vm.expectRevert("SumcheckFailed()");
    verifier.verify(proof, publicInputs);
  }

  /**
   * @dev Test with an incorrectly sized proof
   * We expect it to revert with ProofLengthWrong
   */
  function test_VerifyInvalidProofLength() public {
    vm.expectRevert("ProofLengthWrong()");
    verifier.verify(bytes(""), new bytes32[](0));
  }
}
