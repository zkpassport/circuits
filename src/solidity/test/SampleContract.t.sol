// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportRootVerifier} from "../src/ZKPassportRootVerifier.sol";
import {ZKPassportVerifier, ProofType, ProofVerificationParams} from "../src/ZKPassportVerifier.sol";
import {ProofVerificationData, Commitments, ServiceConfig} from "../src/Types.sol";
import {HonkVerifier as OuterVerifier13} from "../src/ultra-honk-verifiers/OuterCount13.sol";
import {SampleContract} from "../src/SampleContract.sol";
import {TestUtils} from "./Utils.t.sol";
import {CommittedInputLen} from "../src/Constants.sol";

contract SampleContractTest is TestUtils {
  SampleContract public sampleContract;
  // Path to the proof file - using files directly in project root
  string constant PROOF_PATH = "./test/fixtures/all_subproofs_proof.hex";
  string constant PUBLIC_INPUTS_PATH = "./test/fixtures/all_subproofs_public_inputs.json";
  string constant COMMITTED_INPUTS_PATH = "./test/fixtures/all_subproofs_committed_inputs.hex";
  bytes32 constant VKEY_HASH = 0x048f929a5be0814a81e5c4e62305e5cd4d203fb5e56c9ae5f5990aeee8fcabb4;
  // TODO: Add automatic update of this timestamp for testing
  uint256 constant CURRENT_DATE = 1761776121;
  // The version of the ZKPassportVerifier
  uint256 constant VERIFIER_VERSION = 1;

  function setUp() public {
    // Deploy the ZKPassportVerifier
    ZKPassportVerifier zkPassportVerifier = new ZKPassportVerifier(vm.envAddress("ROOT_REGISTRY_ADDRESS"));
    // Deploy the UltraHonkVerifier
    OuterVerifier13 subverifier = new OuterVerifier13();
    // Add the sub-verifier to the ZKPassportVerifier
    bytes32[] memory vkeyHashes = new bytes32[](1);
    vkeyHashes[0] = VKEY_HASH;
    address[] memory subverifiers = new address[](1);
    subverifiers[0] = address(subverifier);
    zkPassportVerifier.addSubVerifiers(vkeyHashes, subverifiers);
    // Deploy the ZKPassportRootVerifier
    ZKPassportRootVerifier rootVerifier = new ZKPassportRootVerifier(vm.envAddress("ROOT_VERIFIER_ADMIN_ADDRESS"), vm.envAddress("ROOT_VERIFIER_GUARDIAN_ADDRESS"), VERIFIER_VERSION, address(zkPassportVerifier));
    // Deploy the SampleContract
    sampleContract = new SampleContract();
    sampleContract.setZKPassportVerifier(address(rootVerifier));
  }

  function test_Register() public {
    // Load proof and public inputs from files
    bytes memory proof = loadBytesFromFile(PROOF_PATH);
    bytes32[] memory publicInputs = loadBytes32FromFile(PUBLIC_INPUTS_PATH);
    bytes memory committedInputs = loadBytesFromFile(COMMITTED_INPUTS_PATH);

    // The sender cannot call this function cause they are not verified
    vm.expectRevert("User is not verified");
    sampleContract.doStuff();

    vm.warp(CURRENT_DATE);
    ProofVerificationParams memory params = ProofVerificationParams({
      proofVerificationData: ProofVerificationData({
        vkeyHash: VKEY_HASH,
        proof: proof,
        publicInputs: publicInputs
      }),
      commitments: Commitments({
        committedInputs: committedInputs
      }),
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days,
        domain: "zkpassport.id",
        scope: "bigproof",
        devMode: false
      })
    });
    bytes32 uniqueIdentifier = sampleContract.register(params, false);

    // The sender can now call this function since they registered just before
    sampleContract.doStuff();
    assertEq(
      uniqueIdentifier,
      bytes32(uint256(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461))
    );
    assertEq(sampleContract.userNationality(uniqueIdentifier), "AUS");
    assertEq(sampleContract.isVerified(uniqueIdentifier), true);
  }
}
