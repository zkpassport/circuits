// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportVerifier, ProofType, ProofVerificationParams} from "../src/ZKPassportVerifier.sol";
import {HonkVerifier as OuterVerifier5} from "../src/ultra-honk-verifiers/OuterCount5.sol";
import {HonkVerifier as OuterVerifier13} from "../src/ultra-honk-verifiers/OuterCount13.sol";
import {TestUtils} from "./Utils.t.sol";
import {CommittedInputLen} from "../src/Constants.sol";
import {DisclosedData, BoundData, FaceMatchMode, ProofVerificationData, Commitments, ServiceConfig, OS} from "../src/Types.sol";

contract ZKPassportVerifierTest is TestUtils {
  OuterVerifier5 public verifier5;
  OuterVerifier13 public verifier13;
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
  bytes32 constant OUTER_PROOF_13_VKEY_HASH =
    bytes32(uint256(0x048f929a5be0814a81e5c4e62305e5cd4d203fb5e56c9ae5f5990aeee8fcabb4));
  uint256 constant CURRENT_DATE = 1761644953;
  uint256 constant PROOF_GENERATION_DATE = 1761644553;

  function setUp() public {
    // Deploy the ZKPassportVerifier
    zkPassportVerifier = new ZKPassportVerifier(vm.envAddress("ROOT_REGISTRY_ADDRESS"));
    // Deploy the UltraHonkVerifier
    verifier5 = new OuterVerifier5();
    verifier13 = new OuterVerifier13();

    // Add the verifier to the ZKPassportVerifier
    bytes32[] memory vkeyHashes = new bytes32[](2);
    vkeyHashes[0] = VKEY_HASH;
    vkeyHashes[1] = OUTER_PROOF_13_VKEY_HASH;
    address[] memory verifiers = new address[](2);
    verifiers[0] = address(verifier5);
    verifiers[1] = address(verifier13);
    zkPassportVerifier.addVerifiers(vkeyHashes, verifiers);
  }

  function test_VerifyValidProof() public {
    // Load proof and public inputs from files
    bytes memory proof = loadBytesFromFile(PROOF_PATH);
    bytes32[] memory publicInputs = loadBytes32FromFile(PUBLIC_INPUTS_PATH);
    bytes memory committedInputs = loadBytesFromFile(COMMITTED_INPUTS_PATH);

    // Verify the proof
    vm.startSnapshotGas("ZKPassportVerifier verifyProof");
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
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    uint256 gasUsed = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier verifyProof");
    console.log(gasUsed);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461)
    );

    vm.startSnapshotGas("ZKPassportVerifier getDisclosedData");
    DisclosedData memory disclosedData = zkPassportVerifier.getDisclosedData(params.commitments, false);
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
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461)
    );

    vm.startSnapshotGas("ZKPassportVerifier getBoundData");
    BoundData memory boundData = zkPassportVerifier
      .getBoundData(params.commitments);
    uint256 gasUsedGetBoundData = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier getBoundData");
    console.log(gasUsedGetBoundData);
    assertEq(boundData.senderAddress, 0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8);
    assertEq(boundData.chainId, 31337);
    assertEq(boundData.customData, "email:test@test.com,customer_id:1234567890");
  }

  function test_VerifyAllSubproofsProof() public {
    // Load proof and public inputs from files
    bytes memory proof = loadBytesFromFile(ALL_SUBPROOFS_PROOF_PATH);
    bytes32[] memory publicInputs = loadBytes32FromFile(ALL_SUBPROOFS_PUBLIC_INPUTS_PATH);
    bytes memory committedInputs = loadBytesFromFile(ALL_SUBPROOFS_COMMITTED_INPUTS_PATH);

    // Verify the proof
    vm.startSnapshotGas("ZKPassportVerifier verifyProof");
    vm.warp(CURRENT_DATE);
    ProofVerificationParams memory params = ProofVerificationParams({
      proofVerificationData: ProofVerificationData({
        vkeyHash: OUTER_PROOF_13_VKEY_HASH,
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
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    uint256 gasUsed = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier verifyProof");
    console.log(gasUsed);
    assertEq(result, true);
    assertEq(
      scopedNullifier,
      bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461)
    );

    vm.startSnapshotGas("ZKPassportVerifier isAgeAboveOrEqual");
    assertEq(zkPassportVerifier.isAgeAboveOrEqual(
      18,
      params.commitments,
      params.serviceConfig
    ), true);
    uint256 gasUsedGetAgeProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier isAgeAboveOrEqual");
    console.log(gasUsedGetAgeProofInputs);

    vm.startSnapshotGas("ZKPassportVerifier isNationalityIn");
    string[] memory countryList = new string[](4);
    countryList[0] = "AUS";
    countryList[1] = "FRA";
    countryList[2] = "USA";
    countryList[3] = "GBR";
    bool isNationalityIn = zkPassportVerifier.isNationalityIn(
      countryList,
      params.commitments
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
      exclusionCountryList,
      params.commitments
    );
    uint256 gasUsedGetExclusionCountryProofInputs = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier isIssuingCountryOut");
    console.log(gasUsedGetExclusionCountryProofInputs);
    assertEq(isIssuingCountryOut, true);
  }

  function test_VerifyAllSubproofsProof_2() public {
    // Load proof and public inputs from files
    bytes memory committedInputs = loadBytesFromFile(ALL_SUBPROOFS_COMMITTED_INPUTS_PATH);

    vm.warp(CURRENT_DATE);
    ProofVerificationParams memory params = ProofVerificationParams({
      proofVerificationData: ProofVerificationData({
        vkeyHash: OUTER_PROOF_13_VKEY_HASH,
        proof: loadBytesFromFile(ALL_SUBPROOFS_PROOF_PATH),
        publicInputs: loadBytes32FromFile(ALL_SUBPROOFS_PUBLIC_INPUTS_PATH)
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
    (bool result, bytes32 scopedNullifier) = zkPassportVerifier.verifyProof(params);
    assertEq(result, true);

    vm.startSnapshotGas("ZKPassportVerifier isBirthdateBeforeOrEqual");
    bool isBirthdateBeforeOrEqual = zkPassportVerifier.isBirthdateBeforeOrEqual(
        PROOF_GENERATION_DATE,
        params.commitments,
        params.serviceConfig
      );
    uint256 gasUsedIsBirthdateBeforeOrEqual = vm.stopSnapshotGas();
    console.log("Gas used in ZKPassportVerifier isBirthdateBeforeOrEqual");
    console.log(gasUsedIsBirthdateBeforeOrEqual);
    assertEq(isBirthdateBeforeOrEqual, true);

    {
      vm.startSnapshotGas("ZKPassportVerifier isExpiryDateAfterOrEqual");
      bool isExpiryDateAfterOrEqual = zkPassportVerifier.isExpiryDateAfterOrEqual(
          PROOF_GENERATION_DATE,
          params.commitments,
          params.serviceConfig
        );
      uint256 gasUsedIsExpiryDateAfterOrEqual = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier isExpiryDateAfterOrEqual");
      console.log(gasUsedIsExpiryDateAfterOrEqual);
      assertEq(isExpiryDateAfterOrEqual, true);
    }
    {
      vm.startSnapshotGas("ZKPassportVerifier isIssuingCountryIn");
      string[] memory countryList = new string[](4);
      countryList[0] = "AUS";
      countryList[1] = "FRA";
      countryList[2] = "USA";
      countryList[3] = "GBR";
      bool isIssuingCountryIn = zkPassportVerifier.isIssuingCountryIn(
        countryList,
        params.commitments
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
      zkPassportVerifier.enforceSanctionsRoot(true, params.commitments);
      uint256 gasUsedEnforceSanctionsRoot = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier enforceSanctionsRoot");
      console.log(gasUsedEnforceSanctionsRoot);
    }

    {
      vm.startSnapshotGas("ZKPassportVerifier isFaceMatchVerified");
      bool isFacematchVerified = zkPassportVerifier.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.IOS, params.commitments, params.serviceConfig);
      uint256 gasUsedIsFaceMatchVerified = vm.stopSnapshotGas();
      console.log("Gas used in ZKPassportVerifier isFaceMatchVerified");
      console.log(gasUsedIsFaceMatchVerified);
      assertEq(isFacematchVerified, true);
      // Should be false because the facematch mode is not strict but regular
      assertEq(zkPassportVerifier.isFaceMatchVerified(FaceMatchMode.STRICT, OS.IOS, params.commitments, params.serviceConfig), false);
      // Should be false because the OS is not iOS
      assertEq(zkPassportVerifier.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.ANDROID, params.commitments, params.serviceConfig), false);
      // Should be true because the OS is any
      assertEq(zkPassportVerifier.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.ANY, params.commitments, params.serviceConfig), true);
    }
  }
}
