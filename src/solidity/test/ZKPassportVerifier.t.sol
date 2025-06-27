// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportVerifier, ProofType, ProofVerificationParams} from "../src/ZKPassportVerifier.sol";
import {HonkVerifier as OuterVerifier5} from "../src/OuterCount5.sol";
import {HonkVerifier as OuterVerifier12} from "../src/OuterCount12.sol";
import {TestUtils} from "./Utils.t.sol";
import {CommittedInputLen, SANCTIONS_TREES_ROOT} from "../src/Constants.sol";

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
  bytes32 constant VKEY_HASH = 0x2ab349ef31f5d516da820a3f55f93c53f9c899b0b991c93fc341199cc1e3b36c;
  bytes32 constant OUTER_PROOF_12_VKEY_HASH = 0x1fdff1847be0a0ac3af37e59d0f83b2a400c15be4049954dc82aba099b0c9924;
  bytes32 constant CERTIFICATE_REGISTRY_ROOT = 0x121bdda58fa5af5248e23d46343aea21eaeba397f3c2d8d03994d176dfe1f3a0;
  bytes32 constant CERTIFICATE_REGISTRY_ROOT_2 = 0x15a8f615191352fff1aa650203a541f2f7e38f9b409f1599944ec75e972f32e6;

  bytes32 constant CIRCUIT_REGISTRY_ROOT = 0x1cec98bdbc92ca83904e96bd19237a770c6b32d8c96909c25731b15851580d52;
  bytes32 constant CIRCUIT_REGISTRY_ROOT_2 = 0x29d2ab14cc2f7c2deee53a98af204140c7de8550864c97b58edd05e5cfb5e145;

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
    zkPassportVerifier.addCertificateRegistryRoot(CERTIFICATE_REGISTRY_ROOT);
    zkPassportVerifier.addCertificateRegistryRoot(CERTIFICATE_REGISTRY_ROOT_2);
    zkPassportVerifier.addCircuitRegistryRoot(CIRCUIT_REGISTRY_ROOT);
    zkPassportVerifier.addCircuitRegistryRoot(CIRCUIT_REGISTRY_ROOT_2);
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
    // Set the timestamp to 2025-06-11 10:10:53 UTC
    vm.warp(1749636653);
    ProofVerificationParams memory params = ProofVerificationParams({
      vkeyHash: VKEY_HASH,
      proof: proof,
      publicInputs: publicInputs,
      committedInputs: committedInputs,
      committedInputCounts: committedInputCounts,
      validityPeriodInDays: 7,
      scope: "zkpassport.id",
      subscope: "bigproof",
      devMode: false
    });
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    uint256 gasUsed = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier verifyProof");
    console.log(gasUsed);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x08e728ced3c0ae721742755e62018c14be91a47da5dbfe392fb098cee6d31025)
    );

    vm.startSnapshotGas("ZKPassportVerifier getDiscloseProofInputs");
    (bytes memory discloseMask, bytes memory discloseBytes) = zkPassportVerifier
      .getDiscloseProofInputs(committedInputs, committedInputCounts);
    uint256 gasUsedDiscloseProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getDiscloseProofInputs");
    console.log(gasUsedDiscloseProofInputs);
    console.log("Disclose mask");
    console.logBytes(discloseMask);
    console.log("Disclose bytes");
    console.logBytes(discloseBytes);

    vm.startSnapshotGas("ZKPassportVerifier getDisclosedData");
    (
      string memory name,
      ,
      string memory nationality,
      string memory gender,
      string memory birthDate,
      ,
      string memory documentNumber,
      string memory documentType
    ) = zkPassportVerifier.getDisclosedData(discloseBytes, false);
    uint256 gasUsedGetDisclosedData = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getDisclosedData");
    console.log(gasUsedGetDisclosedData);
    assertEq(name, "SILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<");
    assertEq(nationality, "AUS");
    assertEq(gender, "M");
    assertEq(birthDate, "881112");
    assertEq(documentNumber, "PA1234567");
    assertEq(documentType, "P<");
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

    // Set the timestamp to 2025-06-11 10:10:53 UTC
    vm.warp(1749636653);
    ProofVerificationParams memory params = ProofVerificationParams({
      vkeyHash: VKEY_HASH,
      proof: proof,
      publicInputs: publicInputs,
      committedInputs: committedInputs,
      committedInputCounts: committedInputCounts,
      validityPeriodInDays: 7,
      scope: "zkpassport.id",
      subscope: "bigproof",
      devMode: false
    });
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x08e728ced3c0ae721742755e62018c14be91a47da5dbfe392fb098cee6d31025)
    );

    vm.startSnapshotGas("ZKPassportVerifier getBindProofInputs");
    bytes memory data = zkPassportVerifier.getBindProofInputs(
      committedInputs,
      committedInputCounts
    );
    uint256 gasUsedGetBindProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getBindProofInputs");
    console.log(gasUsedGetBindProofInputs);

    vm.startSnapshotGas("ZKPassportVerifier getBoundData");
    (address senderAddress, string memory customData) = zkPassportVerifier.getBoundData(data);
    uint256 gasUsedGetBoundData = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getBoundData");
    console.log(gasUsedGetBoundData);
    assertEq(senderAddress, 0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8);
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
    // Set the timestamp to 2025-06-27 10:00:00 UTC
    vm.warp(1751015400);
    ProofVerificationParams memory params = ProofVerificationParams({
      vkeyHash: OUTER_PROOF_12_VKEY_HASH,
      proof: proof,
      publicInputs: publicInputs,
      committedInputs: committedInputs,
      committedInputCounts: committedInputCounts,
      validityPeriodInDays: 7,
      scope: "zkpassport.id",
      subscope: "bigproof",
      devMode: false
    });
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    uint256 gasUsed = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier verifyProof");
    console.log(gasUsed);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x08e728ced3c0ae721742755e62018c14be91a47da5dbfe392fb098cee6d31025)
    );

    vm.startSnapshotGas("ZKPassportVerifier getAgeProofInputs");
    (uint256 currentDate, uint8 minAge, uint8 maxAge) = zkPassportVerifier.getAgeProofInputs(
      committedInputs,
      committedInputCounts
    );
    uint256 gasUsedGetAgeProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getAgeProofInputs");
    console.log(gasUsedGetAgeProofInputs);
    assertEq(currentDate, 1750982400);
    assertEq(minAge, 18);
    assertEq(maxAge, 0);

    vm.startSnapshotGas("ZKPassportVerifier getCountryProofInputs - nationality inclusion");
    string[] memory countryList = zkPassportVerifier.getCountryProofInputs(
      committedInputs,
      committedInputCounts,
      ProofType.NATIONALITY_INCLUSION
    );
    uint256 gasUsedGetCountryProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getCountryProofInputs - nationality inclusion");
    console.log(gasUsedGetCountryProofInputs);
    assertEq(countryList[0], "AUS");
    assertEq(countryList[1], "FRA");
    assertEq(countryList[2], "USA");
    assertEq(countryList[3], "GBR");

    vm.startSnapshotGas("ZKPassportVerifier getCountryProofInputs - issuing country exclusion");
    string[] memory exclusionCountryList = zkPassportVerifier.getCountryProofInputs(
      committedInputs,
      committedInputCounts,
      ProofType.ISSUING_COUNTRY_EXCLUSION
    );
    uint256 gasUsedGetExclusionCountryProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getCountryProofInputs - issuing country exclusion");
    console.log(gasUsedGetExclusionCountryProofInputs);
    assertEq(exclusionCountryList[0], "ESP");
    assertEq(exclusionCountryList[1], "ITA");
    assertEq(exclusionCountryList[2], "PRT");
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

    // Set the timestamp to 2025-06-27 10:00:00 UTC
    vm.warp(1751015400);
    ProofVerificationParams memory params = ProofVerificationParams({
      vkeyHash: OUTER_PROOF_12_VKEY_HASH,
      proof: loadBytesFromFile(ALL_SUBPROOFS_PROOF_PATH),
      publicInputs: loadBytes32FromFile(ALL_SUBPROOFS_PUBLIC_INPUTS_PATH),
      committedInputs: committedInputs,
      committedInputCounts: committedInputCounts,
      validityPeriodInDays: 7,
      scope: "zkpassport.id",
      subscope: "bigproof",
      devMode: false
    });
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    assertEq(result, true);

    uint256 gasUsed;
    {
      vm.startSnapshotGas("ZKPassportVerifier getDateProofInputs - birthdate");
      (
        uint256 currentDateBirthDate,
        uint256 minDateBirthDate,
        uint256 maxDateBirthDate
      ) = zkPassportVerifier.getDateProofInputs(
          committedInputs,
          committedInputCounts,
          ProofType.BIRTHDATE
        );
      gasUsed = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier getDateProofInputs - birthdate");
      console.log(gasUsed);
      assertEq(currentDateBirthDate, 1750982400);
      assertEq(minDateBirthDate, 0);
      assertEq(maxDateBirthDate, 1750982400);
    }

    {
      vm.startSnapshotGas("ZKPassportVerifier getDateProofInputs - expiry date");
      (
        uint256 currentDateExpiryDate,
        uint256 minDateExpiryDate,
        uint256 maxDateExpiryDate
      ) = zkPassportVerifier.getDateProofInputs(
          committedInputs,
          committedInputCounts,
          ProofType.EXPIRY_DATE
        );
      gasUsed = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier getDateProofInputs - expiry date");
      console.log(gasUsed);
      assertEq(currentDateExpiryDate, 1750982400);
      assertEq(minDateExpiryDate, 1750982400);
      assertEq(maxDateExpiryDate, 0);
    }
    {
      vm.startSnapshotGas("ZKPassportVerifier getCountryProofInputs - issuing country inclusion");
      string[] memory countryList = zkPassportVerifier.getCountryProofInputs(
        committedInputs,
        committedInputCounts,
        ProofType.ISSUING_COUNTRY_INCLUSION
      );
      gasUsed = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier getCountryProofInputs - issuing country inclusion");
      console.log(gasUsed);
      assertEq(countryList[0], "AUS");
      assertEq(countryList[1], "FRA");
      assertEq(countryList[2], "USA");
      assertEq(countryList[3], "GBR");
    }
    
    {
      vm.startSnapshotGas("ZKPassportVerifier getCountryProofInputs - issuing country exclusion");
      string[] memory exclusionCountryList = zkPassportVerifier.getCountryProofInputs(
        committedInputs,
        committedInputCounts,
        ProofType.ISSUING_COUNTRY_EXCLUSION
      );
      gasUsed = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier getCountryProofInputs - issuing country exclusion");
      console.log(gasUsed);
      assertEq(exclusionCountryList[0], "ESP");
      assertEq(exclusionCountryList[1], "ITA");
      assertEq(exclusionCountryList[2], "PRT");
    }

    {
      vm.startSnapshotGas("ZKPassportVerifier getSanctions proof inputs");
      bytes32 sanctionsTreeCommitment = zkPassportVerifier.getSanctionsProofInputs(
        committedInputs,
        committedInputCounts
      );
      assertEq(sanctionsTreeCommitment, SANCTIONS_TREES_ROOT);
      gasUsed = vm.stopSnapshotGas();

      vm.startSnapshotGas("ZKPassportVerifier enforceSanctionsRoot");
      zkPassportVerifier.enforceSanctionsRoot(
        committedInputs,
        committedInputCounts
      );
      gasUsed = vm.stopSnapshotGas();
    }
  }

}
