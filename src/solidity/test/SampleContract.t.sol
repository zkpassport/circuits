// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportVerifier, ProofType, ProofVerificationParams} from "../src/ZKPassportVerifier.sol";
import {HonkVerifier as OuterVerifier12} from "../src/ultra-honk-verifiers/OuterCount12.sol";
import {SampleContract} from "../src/SampleContract.sol";
import {TestUtils} from "./Utils.t.sol";
import {CommittedInputLen} from "../src/Constants.sol";

contract SampleContractTest is TestUtils {
  OuterVerifier12 public verifier;
  ZKPassportVerifier public zkPassportVerifier;
  SampleContract public sampleContract;
  // Path to the proof file - using files directly in project root
  string constant PROOF_PATH = "./test/fixtures/all_subproofs_proof.hex";
  string constant PUBLIC_INPUTS_PATH = "./test/fixtures/all_subproofs_public_inputs.json";
  string constant COMMITTED_INPUTS_PATH = "./test/fixtures/all_subproofs_committed_inputs.hex";
  bytes32 constant VKEY_HASH = 0x048f929a5be0814a81e5c4e62305e5cd4d203fb5e56c9ae5f5990aeee8fcabb4;
  uint256 constant CURRENT_DATE = 1756239313;

  function setUp() public {
    // Deploy the ZKPassportVerifier
    zkPassportVerifier = new ZKPassportVerifier(vm.envAddress("ROOT_REGISTRY_ADDRESS"));
    // Deploy the UltraHonkVerifier
    verifier = new OuterVerifier12();

    // Add the verifier to the ZKPassportVerifier
    bytes32[] memory vkeyHashes = new bytes32[](1);
    vkeyHashes[0] = VKEY_HASH;
    address[] memory verifiers = new address[](1);
    verifiers[0] = address(verifier);
    zkPassportVerifier.addVerifiers(vkeyHashes, verifiers);

    sampleContract = new SampleContract();
    sampleContract.setZKPassportVerifier(address(zkPassportVerifier));
  }

  function test_Register() public {
    // Load proof and public inputs from files
    bytes memory proof = loadBytesFromFile(PROOF_PATH);
    bytes32[] memory publicInputs = loadBytes32FromFile(PUBLIC_INPUTS_PATH);
    bytes memory committedInputs = loadBytesFromFile(COMMITTED_INPUTS_PATH);

    // Contains in order the number of bytes of committed inputs for each disclosure proofs
    // that was verified by the final recursive proof
    uint256[] memory committedInputCounts = new uint256[](9);
    committedInputCounts[0] = CommittedInputLen.DISCLOSE_BYTES;
    committedInputCounts[1] = CommittedInputLen.INCL_NATIONALITY;
    committedInputCounts[2] = CommittedInputLen.EXCL_NATIONALITY;
    committedInputCounts[3] = CommittedInputLen.INCL_ISSUING_COUNTRY;
    committedInputCounts[4] = CommittedInputLen.EXCL_ISSUING_COUNTRY;
    committedInputCounts[5] = CommittedInputLen.COMPARE_AGE;
    committedInputCounts[6] = CommittedInputLen.COMPARE_EXPIRY;
    committedInputCounts[7] = CommittedInputLen.COMPARE_BIRTHDATE;
    committedInputCounts[8] = CommittedInputLen.SANCTIONS;

    // The sender cannot call this function cause they are not verified
    vm.expectRevert("User is not verified");
    sampleContract.doStuff();

    vm.warp(CURRENT_DATE);
    ProofVerificationParams memory params = ProofVerificationParams({
      vkeyHash: VKEY_HASH,
      proof: proof,
      publicInputs: publicInputs,
      committedInputs: committedInputs,
      committedInputCounts: committedInputCounts,
      validityPeriodInSeconds: 7 days,
      domain: "zkpassport.id",
      scope: "bigproof",
      // Set to true to accept mock proofs from the ZKR
      devMode: false
    });
    bytes32 uniqueIdentifier = sampleContract.register(params, false);

    // The sender can now call this function since they registered just before
    sampleContract.doStuff();
    assertEq(
      uniqueIdentifier,
      bytes32(uint256(0x0a70167613fa7c456b46f57e91d4fc40c1a7895f55bb7d36ef0ac17ff05045e6))
    );
    assertEq(sampleContract.userNationality(uniqueIdentifier), "AUS");
    assertEq(sampleContract.isVerified(uniqueIdentifier), true);
  }
}
