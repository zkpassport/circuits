// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportTest} from "./Utils.t.sol";
import {ZKPassportRootVerifier} from "../src/ZKPassportRootVerifier.sol";
import {ZKPassportSubVerifier} from "../src/ZKPassportSubVerifier.sol";
import {ZKPassportHelper} from "../src/ZKPassportHelper.sol";
import {CommittedInputLen} from "../src/Constants.sol";
import {DisclosedData, BoundData, FaceMatchMode, ProofVerificationData, Commitments, ServiceConfig, OS, ProofType, ProofVerificationParams} from "../src/Types.sol";


contract ZKPassportRootVerifierTest is ZKPassportTest {
  ZKPassportRootVerifier public rootVerifier;
  ZKPassportSubVerifier public subVerifier;

  function setUp() public {
    (rootVerifier, subVerifier) = deployZKPassport();
  }

  function test_VerifyValidProof_1() public {
    FixtureData memory data = loadFixture(fixtures.valid);
    uint256 currentDate = uint256(data.publicInputs[2]);

    vm.warp(currentDate);
    ProofVerificationParams memory params = ProofVerificationParams({
      version: VERIFIER_VERSION,
      proofVerificationData: ProofVerificationData({
        vkeyHash: fixtures.valid.vkeyHash,
        proof: data.proof,
        publicInputs: data.publicInputs
      }),
      commitments: Commitments({
        committedInputs: data.committedInputs
      }),
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days,
        domain: "zkpassport.id",
        scope: "bigproof",
        devMode: false
      })
    });

    vm.startSnapshotGas("ZKPassportRootVerifier.verify");
    (bool result, bytes32 scopedNullifier, ZKPassportHelper helper) = rootVerifier.verify(params);
    logGas("ZKPassportRootVerifier.verify");

    assertEq(result, true, "Proof should verify successfully");
    assertEq(
      scopedNullifier,
      bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461),
      "Scoped nullifier should match"
    );

    vm.startSnapshotGas("ZKPassportHelper.getDisclosedData");
    DisclosedData memory disclosedData = helper.getDisclosedData(params.commitments, false);
    logGas("ZKPassportHelper.getDisclosedData");

    assertEq(disclosedData.name, "SILVERHAND<<JOHNNY<<<<<<<<<<<<<<<<<<<<<");
    assertEq(disclosedData.nationality, "AUS");
    assertEq(disclosedData.gender, "M");
    assertEq(disclosedData.birthDate, "881112");
    assertEq(disclosedData.documentNumber, "PA1234567");
    assertEq(disclosedData.documentType, "P<");
  }

  function test_VerifyValidProof_2() public {
    FixtureData memory data = loadFixture(fixtures.valid);
    uint256 currentDate = uint256(data.publicInputs[2]);

    vm.warp(currentDate);
    ProofVerificationParams memory params = ProofVerificationParams({
      version: VERIFIER_VERSION,
      proofVerificationData: ProofVerificationData({
        vkeyHash: fixtures.valid.vkeyHash,
        proof: data.proof,
        publicInputs: data.publicInputs
      }),
      commitments: Commitments({
        committedInputs: data.committedInputs
      }),
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days,
        domain: "zkpassport.id",
        scope: "bigproof",
        devMode: false
      })
    });
    (bool result, bytes32 scopedNullifier, ZKPassportHelper helper) = rootVerifier.verify(params);
    assertEq(result, true, "Proof should verify successfully");
    assertEq(
      scopedNullifier,
      bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461),
      "Scoped nullifier should match"
    );

    vm.startSnapshotGas("ZKPassportHelper.getBoundData");
    BoundData memory boundData = helper.getBoundData(params.commitments);
    logGas("ZKPassportHelper.getBoundData");

    assertEq(boundData.senderAddress, 0x04Fb06E8BF44eC60b6A99D2F98551172b2F2dED8, "Bound sender address should match");
    assertEq(boundData.chainId, 31337, "Bound chain ID should match");
    assertEq(boundData.customData, "email:test@test.com,customer_id:1234567890", "Bound custom data should match");
  }

  function test_VerifyAllSubproofsProof() public {
    FixtureData memory data = loadFixture(fixtures.allSubproofs);
    uint256 currentDate = uint256(data.publicInputs[2]);

    // Verify the proof
    vm.warp(currentDate);
    ProofVerificationParams memory params = ProofVerificationParams({
      version: VERIFIER_VERSION,
      proofVerificationData: ProofVerificationData({
        vkeyHash: fixtures.allSubproofs.vkeyHash,
        proof: data.proof,
        publicInputs: data.publicInputs
      }),
      commitments: Commitments({
        committedInputs: data.committedInputs
      }),
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days,
        domain: "zkpassport.id",
        scope: "bigproof",
        devMode: false
      })
    });

    vm.startSnapshotGas("ZKPassportRootVerifier.verify");
    (bool result, bytes32 scopedNullifier, ZKPassportHelper helper) = rootVerifier.verify(params);
    logGas("ZKPassportRootVerifier.verify");
    assertEq(result, true, "Proof should verify successfully");
    assertEq(
      scopedNullifier,
      bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461),
      "Scoped nullifier should match"
    );

    vm.startSnapshotGas("ZKPassportHelper.isAgeAboveOrEqual");
    assertEq(helper.isAgeAboveOrEqual(18, params.commitments), true, "isAgeAboveOrEqual should return true");
    logGas("ZKPassportHelper.isAgeAboveOrEqual");

    vm.startSnapshotGas("ZKPassportHelper.isNationalityIn");
    string[] memory countryList = new string[](4);
    countryList[0] = "AUS";
    countryList[1] = "FRA";
    countryList[2] = "USA";
    countryList[3] = "GBR";
    bool isNationalityIn = helper.isNationalityIn(
      countryList,
      params.commitments
    );
    logGas("ZKPassportHelper.isNationalityIn");
    assertEq(isNationalityIn, true, "isNationalityIn should return true");

    vm.startSnapshotGas("ZKPassportHelper.isIssuingCountryOut");
    string[] memory exclusionCountryList = new string[](3);
    exclusionCountryList[0] = "ESP";
    exclusionCountryList[1] = "ITA";
    exclusionCountryList[2] = "PRT";
    bool isIssuingCountryOut = helper.isIssuingCountryOut(
      exclusionCountryList,
      params.commitments
    );
    logGas("ZKPassportHelper.isIssuingCountryOut");
    assertEq(isIssuingCountryOut, true, "isIssuingCountryOut should return true");
  }

  function test_VerifyAllSubproofsProof_2() public {
    FixtureData memory data = loadFixture(fixtures.allSubproofs);
    uint256 currentDate = uint256(data.publicInputs[2]);

    vm.warp(currentDate);
    ProofVerificationParams memory params = ProofVerificationParams({
      version: VERIFIER_VERSION,
      proofVerificationData: ProofVerificationData({
        vkeyHash: fixtures.allSubproofs.vkeyHash,
        proof: data.proof,
        publicInputs: data.publicInputs
      }),
      commitments: Commitments({
        committedInputs: data.committedInputs
      }),
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days,
        domain: "zkpassport.id",
        scope: "bigproof",
        devMode: false
      })
    });
    (bool result, bytes32 scopedNullifier, ZKPassportHelper helper) = rootVerifier.verify(params);
    assertEq(result, true, "Proof should verify successfully");
    assertEq(scopedNullifier, bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461), "Scoped nullifier should match");

    vm.startSnapshotGas("ZKPassportHelper.isBirthdateBeforeOrEqual");
    bool isBirthdateBeforeOrEqual = helper.isBirthdateBeforeOrEqual(
        currentDate,
        params.commitments
      );
    logGas("ZKPassportHelper.isBirthdateBeforeOrEqual");
    assertEq(isBirthdateBeforeOrEqual, true, "isBirthdateBeforeOrEqual should return true");

    {
      vm.startSnapshotGas("ZKPassportHelper.isExpiryDateAfterOrEqual");
      bool isExpiryDateAfterOrEqual = helper.isExpiryDateAfterOrEqual(
          currentDate,
          params.commitments
        );
      logGas("ZKPassportHelper.isExpiryDateAfterOrEqual");
      assertEq(isExpiryDateAfterOrEqual, true, "isExpiryDateAfterOrEqual should return true");
    }
    {
      vm.startSnapshotGas("ZKPassportHelper.isIssuingCountryIn");
      string[] memory countryList = new string[](4);
      countryList[0] = "AUS";
      countryList[1] = "FRA";
      countryList[2] = "USA";
      countryList[3] = "GBR";
      bool isIssuingCountryIn = helper.isIssuingCountryIn(
        countryList,
        params.commitments
      );
      logGas("ZKPassportHelper.isIssuingCountryIn");
      assertEq(isIssuingCountryIn, true, "isIssuingCountryIn should return true");
    }

    {
      vm.startSnapshotGas("ZKPassportHelper.enforceSanctionsRoot");
      bool isSanctionsRootValid = helper.isSanctionsRootValid(true, params.commitments);
      assertEq(isSanctionsRootValid, true, "isSanctionsRootValid should return true");
      logGas("ZKPassportHelper.enforceSanctionsRoot");
    }

    {
      vm.startSnapshotGas("ZKPassportHelper.isFaceMatchVerified");
      bool isFacematchVerified = helper.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.IOS, params.commitments);
      logGas("ZKPassportHelper.isFaceMatchVerified");
      assertEq(isFacematchVerified, true, "isFaceMatchVerified should return true");
      // Should be false because the facematch mode is not strict but regular
      assertEq(helper.isFaceMatchVerified(FaceMatchMode.STRICT, OS.IOS, params.commitments), false, "isFaceMatchVerified should return false");
      // Should be false because the OS is not iOS
      assertEq(helper.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.ANDROID, params.commitments), false, "isFaceMatchVerified should return false");
      // Should be true because the OS is any
      assertEq(helper.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.ANY, params.commitments), true, "isFaceMatchVerified should return true");
    }
  }
}
