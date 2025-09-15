// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportVerifier, ProofType, ProofVerificationParams} from "../src/ZKPassportVerifier.sol";
import {HonkVerifier as OuterVerifier5} from "../src/OuterCount5.sol";
import {HonkVerifier as OuterVerifier12} from "../src/OuterCount12.sol";
import {TestUtils} from "./Utils.t.sol";
import {CommittedInputLen} from "../src/Constants.sol";
import {DisclosedData} from "../src/Types.sol";

contract ZKPassportVerifierTest is TestUtils {
  OuterVerifier5 public verifier5;
  OuterVerifier12 public verifier12;
  ZKPassportVerifier public zkPassportVerifier;

  // Path to the proof file - using files directly in project root
  string constant PROOF_PATH = "./test/fixtures/valid_proof.hex";
  string constant PUBLIC_INPUTS_PATH = "./test/fixtures/valid_public_inputs.json";
  string constant COMMITTED_INPUTS_PATH = "./test/fixtures/valid_committed_inputs.hex";
  string constant ALL_SUBPROOFS_PROOF_PATH = "./test/fixtures/all_subproofs_proof.hex";
  string constant ALL_SUBPROOFS_PUBLIC_INPUTS_PATH =
    "./test/fixtures/all_subproofs_public_inputs.json";
  string constant ALL_SUBPROOFS_COMMITTED_INPUTS_PATH =
    "./test/fixtures/all_subproofs_committed_inputs.hex";

  bytes32 constant VKEY_HASH =
    bytes32(uint256(0x04b98c6f867d6a7f86d514b72c3be8f41b7aa6f49fdc17514c9f9f0a2ac3ef9a));
  bytes32 constant OUTER_PROOF_12_VKEY_HASH =
    bytes32(uint256(0x048f929a5be0814a81e5c4e62305e5cd4d203fb5e56c9ae5f5990aeee8fcabb4));
  uint256 constant CURRENT_DATE = 1756239313;
  uint256 constant PROOF_GENERATION_DATE = 1756235561;

  function setUp() public {
    // Deploy the ZKPassportVerifier
    zkPassportVerifier = new ZKPassportVerifier(vm.envAddress("ROOT_REGISTRY_ADDRESS"));
    // Deploy the UltraHonkVerifier
    verifier5 = new OuterVerifier5();
    verifier12 = new OuterVerifier12();

    // Add the verifier to the ZKPassportVerifier
    bytes32[] memory vkeyHashes = new bytes32[](2);
    vkeyHashes[0] = VKEY_HASH;
    vkeyHashes[1] = OUTER_PROOF_12_VKEY_HASH;
    address[] memory verifiers = new address[](2);
    verifiers[0] = address(verifier5);
    verifiers[1] = address(verifier12);
    zkPassportVerifier.addVerifiers(vkeyHashes, verifiers);
  }

  function test_VerifyValidProof() public {
    // Load proof and public inputs from files
    bytes memory proof = loadBytesFromFile(PROOF_PATH);
    bytes32[] memory publicInputs = loadBytes32FromFile(PUBLIC_INPUTS_PATH);
    bytes memory committedInputs = loadBytesFromFile(COMMITTED_INPUTS_PATH);
    // Contains in order the number of bytes of committed inputs for each disclosure proofs
    // that was verified by the final recursive proof
    uint256[] memory committedInputCounts = new uint256[](2);
    committedInputCounts[0] = CommittedInputLen.DISCLOSE_BYTES;
    committedInputCounts[1] = CommittedInputLen.BIND;

    // Verify the proof
    vm.startSnapshotGas("ZKPassportVerifier verifyProof");
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
      devMode: false
    });
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    uint256 gasUsed = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier verifyProof");
    console.log(gasUsed);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x0a70167613fa7c456b46f57e91d4fc40c1a7895f55bb7d36ef0ac17ff05045e6)
    );

    vm.startSnapshotGas("ZKPassportVerifier getDisclosedData");
    DisclosedData memory disclosedData = zkPassportVerifier.getDisclosedData(committedInputs, committedInputCounts, false);
    uint256 gasUsedGetDisclosedData = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getDisclosedData");
    console.log(gasUsedGetDisclosedData);
    assertEq(disclosedData.name, "SILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<");
    assertEq(disclosedData.nationality, "AUS");
    assertEq(disclosedData.gender, "M");
    assertEq(disclosedData.birthDate, "881112");
    assertEq(disclosedData.documentNumber, "PA1234567");
    assertEq(disclosedData.documentType, "P<");
  }

  function test_VerifyValidProof_2() public {
    // Load proof and public inputs from files
    bytes memory proof = loadBytesFromFile(PROOF_PATH);
    bytes32[] memory publicInputs = loadBytes32FromFile(PUBLIC_INPUTS_PATH);
    bytes memory committedInputs = loadBytesFromFile(COMMITTED_INPUTS_PATH);
    // Contains in order the number of bytes of committed inputs for each disclosure proofs
    // that was verified by the final recursive proof
    uint256[] memory committedInputCounts = new uint256[](2);
    committedInputCounts[0] = 181;
    committedInputCounts[1] = 501;

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
      devMode: false
    });
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x0a70167613fa7c456b46f57e91d4fc40c1a7895f55bb7d36ef0ac17ff05045e6)
    );

    vm.startSnapshotGas("ZKPassportVerifier getBoundData");
    (address senderAddress, uint256 chainId, string memory customData) = zkPassportVerifier
      .getBoundData(committedInputs, committedInputCounts);
    uint256 gasUsedGetBoundData = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getBoundData");
    console.log(gasUsedGetBoundData);
    assertEq(senderAddress, 0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8);
    assertEq(chainId, 31337);
    assertEq(customData, "email:test@test.com,customer_id:1234567890");
  }

  function test_VerifyAllSubproofsProof() public {
    // Load proof and public inputs from files
    bytes memory proof = loadBytesFromFile(ALL_SUBPROOFS_PROOF_PATH);
    bytes32[] memory publicInputs = loadBytes32FromFile(ALL_SUBPROOFS_PUBLIC_INPUTS_PATH);
    bytes memory committedInputs = loadBytesFromFile(ALL_SUBPROOFS_COMMITTED_INPUTS_PATH);

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

    // Verify the proof
    vm.startSnapshotGas("ZKPassportVerifier verifyProof");
    vm.warp(CURRENT_DATE);
    ProofVerificationParams memory params = ProofVerificationParams({
      vkeyHash: OUTER_PROOF_12_VKEY_HASH,
      proof: proof,
      publicInputs: publicInputs,
      committedInputs: committedInputs,
      committedInputCounts: committedInputCounts,
      validityPeriodInSeconds: 7 days,
      domain: "zkpassport.id",
      scope: "bigproof",
      devMode: false
    });
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    uint256 gasUsed = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier verifyProof");
    console.log(gasUsed);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x0a70167613fa7c456b46f57e91d4fc40c1a7895f55bb7d36ef0ac17ff05045e6)
    );

    vm.startSnapshotGas("ZKPassportVerifier isAgeAboveOrEqual");
    bool isAgeAboveOrEqual = zkPassportVerifier.isAgeAboveOrEqual(
      committedInputs,
      committedInputCounts,
      18,
      1 days
    );
    uint256 gasUsedGetAgeProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier isAgeAboveOrEqual");
    console.log(gasUsedGetAgeProofInputs);
    assertEq(isAgeAboveOrEqual, true);

    vm.startSnapshotGas("ZKPassportVerifier isNationalityIn");
    string[] memory countryList = new string[](4);
    countryList[0] = "AUS";
    countryList[1] = "FRA";
    countryList[2] = "USA";
    countryList[3] = "GBR";
    bool isNationalityIn = zkPassportVerifier.isNationalityIn(
      committedInputs,
      committedInputCounts,
      countryList
    );
    uint256 gasUsedGetCountryProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier isNationalityIn");
    console.log(gasUsedGetCountryProofInputs);
    assertEq(isNationalityIn, true);


    vm.startSnapshotGas("ZKPassportVerifier isIssuingCountryOut");
    string[] memory exclusionCountryList = new string[](3);
    exclusionCountryList[0] = "ESP";
    exclusionCountryList[1] = "ITA";
    exclusionCountryList[2] = "PRT";
    bool isIssuingCountryOut = zkPassportVerifier.isIssuingCountryOut(
      committedInputs,
      committedInputCounts,
      exclusionCountryList
    );
    uint256 gasUsedGetExclusionCountryProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier isIssuingCountryOut");
    console.log(gasUsedGetExclusionCountryProofInputs);
    assertEq(isIssuingCountryOut, true);
  }

  function test_VerifyAllSubproofsProof_2() public {
    // Load proof and public inputs from files
    bytes memory committedInputs = loadBytesFromFile(ALL_SUBPROOFS_COMMITTED_INPUTS_PATH);

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

    vm.warp(CURRENT_DATE);
    ProofVerificationParams memory params = ProofVerificationParams({
      vkeyHash: OUTER_PROOF_12_VKEY_HASH,
      proof: loadBytesFromFile(ALL_SUBPROOFS_PROOF_PATH),
      publicInputs: loadBytes32FromFile(ALL_SUBPROOFS_PUBLIC_INPUTS_PATH),
      committedInputs: committedInputs,
      committedInputCounts: committedInputCounts,
      validityPeriodInSeconds: 7 days,
      domain: "zkpassport.id",
      scope: "bigproof",
      devMode: false
    });
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    assertEq(result, true);

    vm.startSnapshotGas("ZKPassportVerifier isBirthdateBelowOrEqual");
    bool isBirthdateBelowOrEqual = zkPassportVerifier.isBirthdateBelowOrEqual(
        committedInputs,
        committedInputCounts,
        PROOF_GENERATION_DATE,
        1 days
      );
    uint256 gasUsedIsBirthdateBelowOrEqual = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier isBirthdateBelowOrEqual");
    console.log(gasUsedIsBirthdateBelowOrEqual);
    assertEq(isBirthdateBelowOrEqual, true);

    {
      vm.startSnapshotGas("ZKPassportVerifier isExpiryDateAboveOrEqual");
      bool isExpiryDateAboveOrEqual = zkPassportVerifier.isExpiryDateAboveOrEqual(
          committedInputs,
          committedInputCounts,
          PROOF_GENERATION_DATE,
          1 days
        );
      uint256 gasUsedIsExpiryDateAboveOrEqual = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier isExpiryDateAboveOrEqual");
      console.log(gasUsedIsExpiryDateAboveOrEqual);
      assertEq(isExpiryDateAboveOrEqual, true);
    }
    {
      vm.startSnapshotGas("ZKPassportVerifier isIssuingCountryIn");
      string[] memory countryList = new string[](4);
      countryList[0] = "AUS";
      countryList[1] = "FRA";
      countryList[2] = "USA";
      countryList[3] = "GBR";
      bool isIssuingCountryIn = zkPassportVerifier.isIssuingCountryIn(
        committedInputs,
        committedInputCounts,
        countryList
      );
      uint256 gasUsedIsIssuingCountryIn = vm.stopSnapshotGas();
      console.log(
        "Gas used in ZKPassportVerifier isIssuingCountryIn"
      );
      console.log(gasUsedIsIssuingCountryIn);
      assertEq(isIssuingCountryIn, true);
    }

    {
      vm.startSnapshotGas("ZKPassportVerifier enforceSanctionsRoot");
      zkPassportVerifier.enforceSanctionsRoot(committedInputs, committedInputCounts);
      uint256 gasUsedEnforceSanctionsRoot = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier enforceSanctionsRoot");
      console.log(gasUsedEnforceSanctionsRoot);
    }
  }
}
