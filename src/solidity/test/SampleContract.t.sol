// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportVerifier, ProofType} from "../src/ZKPassportVerifier.sol";
import {HonkVerifier as OuterVerifier11} from "../src/OuterCount11.sol";
import {SampleContract} from "../src/SampleContract.sol";
import {TestUtils} from "./Utils.t.sol";

contract SampleContractTest is TestUtils {
  OuterVerifier11 public verifier;
  ZKPassportVerifier public zkPassportVerifier;
  SampleContract public sampleContract;
  // Path to the proof file - using files directly in project root
  string constant PROOF_PATH = "./test/fixtures/all_subproofs_proof.hex";
  string constant PUBLIC_INPUTS_PATH = "./test/fixtures/all_subproofs_public_inputs.json";
  string constant COMMITTED_INPUTS_PATH = "./test/fixtures/all_subproofs_committed_inputs.hex";
  bytes32 constant VKEY_HASH =
    bytes32(uint256(0x069f039e7d9a3a64d963797f9a7232380dab2c2cd294c1d7864105b7caa6ea00));
  bytes32 constant CERTIFICATE_REGISTRY_ROOT =
    bytes32(uint256(0x051f7d5144ece7ab472f3b057ddf0bd9d434b22e4e6f5982142d3475e5271373));

  function setUp() public {
    // Deploy the ZKPassportVerifier
    zkPassportVerifier = new ZKPassportVerifier();
    // Deploy the UltraHonkVerifier
    verifier = new OuterVerifier11();

    // Add the verifier to the ZKPassportVerifier
    bytes32[] memory vkeyHashes = new bytes32[](1);
    vkeyHashes[0] = VKEY_HASH;
    address[] memory verifiers = new address[](1);
    verifiers[0] = address(verifier);
    zkPassportVerifier.addVerifiers(vkeyHashes, verifiers);
    zkPassportVerifier.addCertificateRegistryRoot(CERTIFICATE_REGISTRY_ROOT);

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
    uint256[] memory committedInputCounts = new uint256[](8);
    committedInputCounts[0] = 181;
    committedInputCounts[1] = 601;
    committedInputCounts[2] = 601;
    committedInputCounts[3] = 601;
    committedInputCounts[4] = 601;
    committedInputCounts[5] = 11;
    committedInputCounts[6] = 25;
    committedInputCounts[7] = 25;

    // The sender cannot call this function cause they are not verified
    vm.expectRevert("User is not verified");
    sampleContract.doStuff();

    // Set the timestamp to 2025-04-17 09:22:52 UTC
    vm.warp(1744881772);
    bytes32 uniqueIdentifier = sampleContract.register(
      VKEY_HASH,
      proof,
      publicInputs,
      committedInputs,
      committedInputCounts,
      false
    );

    // The sender can now call this function since they registered just before
    sampleContract.doStuff();
    assertEq(
      uniqueIdentifier,
      bytes32(uint256(0x166e45d330ee09cdfd9584800d692caf5c89bafa9c756ddb07efe5a937311f36))
    );
    assertEq(sampleContract.userNationality(uniqueIdentifier), "AUS");
    assertEq(sampleContract.isVerified(uniqueIdentifier), true);
  }
}
