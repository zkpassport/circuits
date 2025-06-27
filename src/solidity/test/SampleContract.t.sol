// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportVerifier, ProofType, ProofVerificationParams} from "../src/ZKPassportVerifier.sol";
import {HonkVerifier as OuterVerifier12} from "../src/OuterCount12.sol";
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
  bytes32 constant VKEY_HASH = 0x1fdff1847be0a0ac3af37e59d0f83b2a400c15be4049954dc82aba099b0c9924;
  bytes32 constant CERTIFICATE_REGISTRY_ROOT = 0x15a8f615191352fff1aa650203a541f2f7e38f9b409f1599944ec75e972f32e6;
  bytes32 constant CIRCUIT_REGISTRY_ROOT = 0x1cec98bdbc92ca83904e96bd19237a770c6b32d8c96909c25731b15851580d52;

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
    zkPassportVerifier.addCertificateRegistryRoot(CERTIFICATE_REGISTRY_ROOT);
    zkPassportVerifier.addCircuitRegistryRoot(CIRCUIT_REGISTRY_ROOT);

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


    // Set the timestamp to 2025-06-27 10:00:00 UTC
    vm.warp(1751015400);
    ProofVerificationParams memory params = ProofVerificationParams({
      vkeyHash: VKEY_HASH,
      proof: proof,
      publicInputs: publicInputs,
      committedInputs: committedInputs,
      committedInputCounts: committedInputCounts,
      validityPeriodInDays: 7,
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
      bytes32(uint256(0x08e728ced3c0ae721742755e62018c14be91a47da5dbfe392fb098cee6d31025))
    );
    assertEq(sampleContract.userNationality(uniqueIdentifier), "AUS");
    assertEq(sampleContract.isVerified(uniqueIdentifier), true);
  }
}
