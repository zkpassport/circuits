// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {ZKPassportTest} from "./Utils.t.sol";
import {ZKPassportRootVerifier} from "../src/ZKPassportRootVerifier.sol";
import {IRootRegistry} from "../src/IRootRegistry.sol";
import {ZKPassportSubVerifier} from "../src/ZKPassportSubVerifier.sol";
import {ZKPassportHelper} from "../src/ZKPassportHelper.sol";
import {CommittedInputLen} from "../src/Constants.sol";
import {
  DisclosedData,
  BoundData,
  FaceMatchMode,
  ProofVerificationData,
  ServiceConfig,
  OS,
  ProofType,
  ProofVerificationParams
} from "../src/Types.sol";

contract ZKPassportRootVerifierTest is ZKPassportTest {
  ZKPassportRootVerifier public rootVerifier;
  ZKPassportSubVerifier public subVerifier;

  // Use labeled test accounts
  address public admin = makeAddr("admin");
  address public guardian = makeAddr("guardian");
  address public user = makeAddr("user");

  // Events from RootVerifier
  event ConfigUpdated(bytes32 indexed key, bytes32 oldValue, bytes32 newValue);

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
        vkeyHash: fixtures.valid.vkeyHash, proof: data.proof, publicInputs: data.publicInputs
      }),
      committedInputs: data.committedInputs,
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days, domain: "zkpassport.id", scope: "bigproof", devMode: false
      })
    });

    vm.startSnapshotGas("ZKPassportRootVerifier.verify");
    (bool result, bytes32 scopedNullifier, ZKPassportHelper helper) = rootVerifier.verify(params);
    logGas("ZKPassportRootVerifier.verify");
    uint256 proofTimestamp = helper.getProofTimestamp(params.proofVerificationData.publicInputs);
    assertEq(proofTimestamp, currentDate);

    assertEq(result, true, "Proof should verify successfully");
    assertEq(
      scopedNullifier,
      bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461),
      "Scoped nullifier should match"
    );

    vm.startSnapshotGas("ZKPassportHelper.getDisclosedData");
    DisclosedData memory disclosedData = helper.getDisclosedData(params.committedInputs, false);
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
        vkeyHash: fixtures.valid.vkeyHash, proof: data.proof, publicInputs: data.publicInputs
      }),
      committedInputs: data.committedInputs,
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days, domain: "zkpassport.id", scope: "bigproof", devMode: false
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
    BoundData memory boundData = helper.getBoundData(params.committedInputs);
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
        vkeyHash: fixtures.allSubproofs.vkeyHash, proof: data.proof, publicInputs: data.publicInputs
      }),
      committedInputs: data.committedInputs,
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days, domain: "zkpassport.id", scope: "bigproof", devMode: false
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
    assertEq(helper.isAgeAboveOrEqual(18, params.committedInputs), true, "isAgeAboveOrEqual should return true");
    logGas("ZKPassportHelper.isAgeAboveOrEqual");

    vm.startSnapshotGas("ZKPassportHelper.isNationalityIn");
    string[] memory countryList = new string[](4);
    countryList[0] = "AUS";
    countryList[1] = "FRA";
    countryList[2] = "USA";
    countryList[3] = "GBR";
    bool isNationalityIn = helper.isNationalityIn(countryList, params.committedInputs);
    logGas("ZKPassportHelper.isNationalityIn");
    assertEq(isNationalityIn, true, "isNationalityIn should return true");

    vm.startSnapshotGas("ZKPassportHelper.isIssuingCountryOut");
    string[] memory exclusionCountryList = new string[](3);
    exclusionCountryList[0] = "ESP";
    exclusionCountryList[1] = "ITA";
    exclusionCountryList[2] = "PRT";
    bool isIssuingCountryOut = helper.isIssuingCountryOut(exclusionCountryList, params.committedInputs);
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
        vkeyHash: fixtures.allSubproofs.vkeyHash, proof: data.proof, publicInputs: data.publicInputs
      }),
      committedInputs: data.committedInputs,
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days, domain: "zkpassport.id", scope: "bigproof", devMode: false
      })
    });
    (bool result, bytes32 scopedNullifier, ZKPassportHelper helper) = rootVerifier.verify(params);
    assertEq(result, true, "Proof should verify successfully");
    assertEq(
      scopedNullifier,
      bytes32(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461),
      "Scoped nullifier should match"
    );

    vm.startSnapshotGas("ZKPassportHelper.isBirthdateBeforeOrEqual");
    bool isBirthdateBeforeOrEqual = helper.isBirthdateBeforeOrEqual(currentDate, params.committedInputs);
    logGas("ZKPassportHelper.isBirthdateBeforeOrEqual");
    assertEq(isBirthdateBeforeOrEqual, true, "isBirthdateBeforeOrEqual should return true");

    {
      vm.startSnapshotGas("ZKPassportHelper.isExpiryDateAfterOrEqual");
      bool isExpiryDateAfterOrEqual = helper.isExpiryDateAfterOrEqual(currentDate, params.committedInputs);
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
      bool isIssuingCountryIn = helper.isIssuingCountryIn(countryList, params.committedInputs);
      logGas("ZKPassportHelper.isIssuingCountryIn");
      assertEq(isIssuingCountryIn, true, "isIssuingCountryIn should return true");
    }

    {
      vm.startSnapshotGas("ZKPassportHelper.enforceSanctionsRoot");
      bool isSanctionsRootValid = helper.isSanctionsRootValid(currentDate, true, params.committedInputs);
      assertEq(isSanctionsRootValid, true, "isSanctionsRootValid should return true");
      logGas("ZKPassportHelper.enforceSanctionsRoot");
    }

    {
      vm.startSnapshotGas("ZKPassportHelper.isFaceMatchVerified");
      bool isFacematchVerified = helper.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.IOS, params.committedInputs);
      logGas("ZKPassportHelper.isFaceMatchVerified");
      assertEq(isFacematchVerified, true, "isFaceMatchVerified should return true");
      // Should be false because the facematch mode is not strict but regular
      assertEq(
        helper.isFaceMatchVerified(FaceMatchMode.STRICT, OS.IOS, params.committedInputs),
        false,
        "isFaceMatchVerified should return false"
      );
      // Should be false because the OS is not iOS
      assertEq(
        helper.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.ANDROID, params.committedInputs),
        false,
        "isFaceMatchVerified should return false"
      );
      // Should be true because the OS is any
      assertEq(
        helper.isFaceMatchVerified(FaceMatchMode.REGULAR, OS.ANY, params.committedInputs),
        true,
        "isFaceMatchVerified should return true"
      );
    }
  }

  function testOnlyAdminOrGuardianCanPause() public {
    // Guardian can pause
    vm.prank(guardian);
    rootVerifier.pause();
    assertTrue(rootVerifier.paused());

    // Guardian cannot unpause
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.unpause();

    // Admin can unpause
    vm.prank(admin);
    rootVerifier.unpause();
    assertFalse(rootVerifier.paused());

    // Admin can also pause
    vm.prank(admin);
    rootVerifier.pause();
    assertTrue(rootVerifier.paused());

    // Admin can unpause again
    vm.prank(admin);
    rootVerifier.unpause();
    assertFalse(rootVerifier.paused());

    // User cannot pause
    vm.prank(user);
    vm.expectRevert("Not authorized: admin or guardian only");
    rootVerifier.pause();
  }

  function testVerifyWhenPaused() public {
    FixtureData memory data = loadFixture(fixtures.valid);
    uint256 currentDate = uint256(data.publicInputs[2]);
    vm.warp(currentDate);

    ProofVerificationParams memory params = ProofVerificationParams({
      version: VERIFIER_VERSION,
      proofVerificationData: ProofVerificationData({
        vkeyHash: fixtures.valid.vkeyHash, proof: data.proof, publicInputs: data.publicInputs
      }),
      committedInputs: data.committedInputs,
      serviceConfig: ServiceConfig({
        validityPeriodInSeconds: 7 days, domain: "zkpassport.id", scope: "bigproof", devMode: false
      })
    });

    // Pause the contract
    vm.prank(guardian);
    rootVerifier.pause();

    // Attempt to verify - should revert
    vm.expectRevert("Root verifier is paused");
    rootVerifier.verify(params);
  }

  function testAddSubVerifier() public {
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    bytes32 newVersion = bytes32(uint256(2));

    // Admin adds new subverifier
    vm.prank(admin);
    rootVerifier.addSubVerifier(newVersion, newSubVerifier);

    // Check that subverifier was added
    assertEq(rootVerifier.getSubVerifier(newVersion), address(newSubVerifier));
  }

  function testOnlyAdminCanAddSubVerifier() public {
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    bytes32 newVersion = bytes32(uint256(2));

    // User tries to add subverifier
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.addSubVerifier(newVersion, newSubVerifier);

    // Guardian tries to add subverifier
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.addSubVerifier(newVersion, newSubVerifier);
  }

  function testCannotAddSubVerifierToZeroVersion() public {
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);

    // Admin tries to add subverifier to version 0
    vm.prank(admin);
    vm.expectRevert("Version cannot be zero");
    rootVerifier.addSubVerifier(bytes32(0), newSubVerifier);
  }

  function testCannotAddZeroAddressSubVerifier() public {
    // Admin tries to add zero address as subverifier
    vm.prank(admin);
    vm.expectRevert("Subverifier cannot be zero address");
    rootVerifier.addSubVerifier(bytes32(uint256(2)), ZKPassportSubVerifier(address(0)));
  }

  function testCannotAddSubVerifierToExistingVersion() public {
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);

    // Admin tries to add subverifier to version 1 (already exists from setUp)
    vm.prank(admin);
    vm.expectRevert("Subverifier already exists for version");
    rootVerifier.addSubVerifier(VERIFIER_VERSION, newSubVerifier);
  }

  function testUpdateSubVerifier() public {
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    address oldSubVerifier = rootVerifier.getSubVerifier(VERIFIER_VERSION);

    // Admin updates subverifier
    vm.prank(admin);
    rootVerifier.updateSubVerifier(VERIFIER_VERSION, address(newSubVerifier));

    // Check that subverifier was updated
    assertEq(rootVerifier.getSubVerifier(VERIFIER_VERSION), address(newSubVerifier));
    assertTrue(rootVerifier.getSubVerifier(VERIFIER_VERSION) != oldSubVerifier);
  }

  function testOnlyAdminCanUpdateSubVerifier() public {
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);

    // User tries to update subverifier
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.updateSubVerifier(VERIFIER_VERSION, address(newSubVerifier));

    // Guardian tries to update subverifier
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.updateSubVerifier(VERIFIER_VERSION, address(newSubVerifier));
  }

  function testCannotUpdateSubVerifierToZeroAddress() public {
    // Admin tries to update subverifier to zero address
    vm.prank(admin);
    vm.expectRevert("Subverifier cannot be zero address");
    rootVerifier.updateSubVerifier(VERIFIER_VERSION, address(0));
  }

  function testCannotUpdateNonExistentSubVerifier() public {
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);

    // Admin tries to update non-existent subverifier
    vm.prank(admin);
    vm.expectRevert("Subverifier not found for version");
    rootVerifier.updateSubVerifier(bytes32(uint256(999)), address(newSubVerifier));
  }

  function testRemoveSubVerifier() public {
    // Add a new subverifier first
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    bytes32 newVersion = bytes32(uint256(2));
    vm.prank(admin);
    rootVerifier.addSubVerifier(newVersion, newSubVerifier);

    // Verify it was added
    assertEq(rootVerifier.getSubVerifier(newVersion), address(newSubVerifier));

    // Admin removes subverifier
    vm.prank(admin);
    rootVerifier.removeSubVerifier(newVersion);

    // Check that subverifier was removed
    assertEq(rootVerifier.getSubVerifier(newVersion), address(0));
  }

  function testOnlyAdminCanRemoveSubVerifier() public {
    // User tries to remove subverifier
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.removeSubVerifier(VERIFIER_VERSION);

    // Guardian tries to remove subverifier
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.removeSubVerifier(VERIFIER_VERSION);
  }

  function testCannotRemoveNonExistentSubVerifier() public {
    // Admin tries to remove non-existent subverifier
    vm.prank(admin);
    vm.expectRevert("Subverifier not found for version");
    rootVerifier.removeSubVerifier(bytes32(uint256(999)));
  }

  function testAddHelper() public {
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);
    bytes32 newVersion = bytes32(uint256(2));

    // Admin adds new helper
    vm.prank(admin);
    rootVerifier.addHelper(newVersion, address(newHelper));

    // Helper should be added (we can verify by trying to add again which should fail)
    vm.prank(admin);
    vm.expectRevert("Helper already exists for version");
    rootVerifier.addHelper(newVersion, address(newHelper));
  }

  function testOnlyAdminCanAddHelper() public {
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);
    bytes32 newVersion = bytes32(uint256(2));

    // User tries to add helper
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.addHelper(newVersion, address(newHelper));

    // Guardian tries to add helper
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.addHelper(newVersion, address(newHelper));
  }

  function testCannotAddHelperToZeroVersion() public {
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);

    // Admin tries to add helper to version 0
    vm.prank(admin);
    vm.expectRevert("Version cannot be zero");
    rootVerifier.addHelper(bytes32(0), address(newHelper));
  }

  function testCannotAddZeroAddressHelper() public {
    // Admin tries to add zero address as helper
    vm.prank(admin);
    vm.expectRevert("Helper cannot be zero address");
    rootVerifier.addHelper(bytes32(uint256(2)), address(0));
  }

  function testCannotAddHelperToExistingVersion() public {
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);

    // Admin tries to add helper to version 1 (already exists from setUp)
    vm.prank(admin);
    vm.expectRevert("Helper already exists for version");
    rootVerifier.addHelper(VERIFIER_VERSION, address(newHelper));
  }

  function testUpdateHelper() public {
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);

    // Admin updates helper
    vm.prank(admin);
    rootVerifier.updateHelper(VERIFIER_VERSION, address(newHelper));

    // Verify update by checking we can update again (different helper)
    ZKPassportHelper anotherHelper = new ZKPassportHelper(rootRegistry);
    vm.prank(admin);
    rootVerifier.updateHelper(VERIFIER_VERSION, address(anotherHelper));
  }

  function testOnlyAdminCanUpdateHelper() public {
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);

    // User tries to update helper
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.updateHelper(VERIFIER_VERSION, address(newHelper));

    // Guardian tries to update helper
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.updateHelper(VERIFIER_VERSION, address(newHelper));
  }

  function testCannotUpdateHelperToZeroAddress() public {
    // Admin tries to update helper to zero address
    vm.prank(admin);
    vm.expectRevert("Helper cannot be zero address");
    rootVerifier.updateHelper(VERIFIER_VERSION, address(0));
  }

  function testCannotUpdateNonExistentHelper() public {
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);

    // Admin tries to update non-existent helper
    vm.prank(admin);
    vm.expectRevert("Helper not found for version");
    rootVerifier.updateHelper(bytes32(uint256(999)), address(newHelper));
  }

  function testRemoveHelper() public {
    // Add a new helper first
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);
    bytes32 newVersion = bytes32(uint256(2));
    vm.prank(admin);
    rootVerifier.addHelper(newVersion, address(newHelper));

    // Admin removes helper
    vm.prank(admin);
    rootVerifier.removeHelper(newVersion);

    // Verify removal by checking we can add again
    vm.prank(admin);
    rootVerifier.addHelper(newVersion, address(newHelper));
  }

  function testOnlyAdminCanRemoveHelper() public {
    // User tries to remove helper
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.removeHelper(VERIFIER_VERSION);

    // Guardian tries to remove helper
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.removeHelper(VERIFIER_VERSION);
  }

  function testCannotRemoveNonExistentHelper() public {
    // Admin tries to remove non-existent helper
    vm.prank(admin);
    vm.expectRevert("Helper not found for version");
    rootVerifier.removeHelper(bytes32(uint256(999)));
  }

  function testTransferAdmin() public {
    // Admin transfers admin role
    vm.prank(admin);
    rootVerifier.transferAdmin(user);

    // Check that admin was updated
    assertEq(rootVerifier.admin(), user);

    // New admin should be able to add subverifier
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    vm.prank(user);
    rootVerifier.addSubVerifier(bytes32(uint256(2)), newSubVerifier);

    // Old admin should no longer be able to add subverifier
    ZKPassportSubVerifier anotherSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    vm.prank(admin);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.addSubVerifier(bytes32(uint256(3)), anotherSubVerifier);
  }

  function testCannotTransferAdminToZeroAddress() public {
    // Admin tries to transfer admin role to zero address
    vm.prank(admin);
    vm.expectRevert("Admin cannot be zero address");
    rootVerifier.transferAdmin(address(0));
  }

  function testOnlyAdminCanTransferAdmin() public {
    // User tries to transfer admin
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.transferAdmin(user);

    // Guardian tries to transfer admin
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.transferAdmin(user);
  }

  function testSetGuardian() public {
    // User cannot pause initially
    vm.prank(user);
    vm.expectRevert("Not authorized: admin or guardian only");
    rootVerifier.pause();

    // Admin sets guardian role to user
    vm.prank(admin);
    rootVerifier.setGuardian(user);

    // Check that guardian was updated
    assertEq(rootVerifier.guardian(), user);

    // New guardian should be able to pause
    vm.prank(user);
    rootVerifier.pause();
    assertTrue(rootVerifier.paused());

    // Unpause for next test
    vm.prank(admin);
    rootVerifier.unpause();

    // Old guardian should no longer be able to pause
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin or guardian only");
    rootVerifier.pause();
  }

  function testCanSetGuardianToZeroAddress() public {
    // Verify guardian is set initially
    assertEq(rootVerifier.guardian(), guardian);

    // Admin sets guardian role to zero address (removing the role)
    vm.prank(admin);
    rootVerifier.setGuardian(address(0));

    // Check that guardian was updated to zero
    assertEq(rootVerifier.guardian(), address(0));
  }

  function testOnlyAdminCanSetGuardian() public {
    // User tries to set guardian
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.setGuardian(user);

    // Guardian tries to set guardian
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.setGuardian(user);
  }

  function testUpdateConfig() public {
    bytes32 configKey = keccak256("test-config-key");
    bytes32 configValue = keccak256("test-config-value");

    // Initially, config should be zero
    assertEq(rootVerifier.config(configKey), bytes32(0));

    // Expect the ConfigUpdated event
    vm.expectEmit(true, false, false, true);
    emit ConfigUpdated(configKey, bytes32(0), configValue);

    // Admin updates config
    vm.prank(admin);
    rootVerifier.updateConfig(configKey, configValue);

    // Check that config was updated
    assertEq(rootVerifier.config(configKey), configValue);
  }

  function testUpdateConfigMultipleTimes() public {
    bytes32 configKey = keccak256("test-config-key");
    bytes32 configValue1 = keccak256("test-config-value-1");
    bytes32 configValue2 = keccak256("test-config-value-2");

    // Admin updates config first time
    vm.prank(admin);
    rootVerifier.updateConfig(configKey, configValue1);
    assertEq(rootVerifier.config(configKey), configValue1);

    // Expect the ConfigUpdated event with old value
    vm.expectEmit(true, false, false, true);
    emit ConfigUpdated(configKey, configValue1, configValue2);

    // Admin updates config second time
    vm.prank(admin);
    rootVerifier.updateConfig(configKey, configValue2);
    assertEq(rootVerifier.config(configKey), configValue2);
  }

  function testOnlyAdminCanUpdateConfig() public {
    bytes32 configKey = keccak256("test-config-key");
    bytes32 configValue = keccak256("test-config-value");

    // User tries to update config
    vm.prank(user);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.updateConfig(configKey, configValue);

    // Guardian tries to update config
    vm.prank(guardian);
    vm.expectRevert("Not authorized: admin only");
    rootVerifier.updateConfig(configKey, configValue);
  }

  function testMultipleConfigKeys() public {
    bytes32 configKey1 = keccak256("test-config-key-1");
    bytes32 configKey2 = keccak256("test-config-key-2");
    bytes32 configValue1 = keccak256("test-config-value-1");
    bytes32 configValue2 = keccak256("test-config-value-2");

    // Admin updates multiple config keys
    vm.startPrank(admin);
    rootVerifier.updateConfig(configKey1, configValue1);
    rootVerifier.updateConfig(configKey2, configValue2);
    vm.stopPrank();

    // Check that both configs were updated independently
    assertEq(rootVerifier.config(configKey1), configValue1);
    assertEq(rootVerifier.config(configKey2), configValue2);
  }

  function testSubverifierCountTracking() public {
    // Initial count should be 1 (from setUp)
    assertEq(rootVerifier.subverifierCount(), 1);

    // Add a new subverifier
    ZKPassportSubVerifier newSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    bytes32 newVersion = bytes32(uint256(2));
    vm.prank(admin);
    rootVerifier.addSubVerifier(newVersion, newSubVerifier);
    assertEq(rootVerifier.subverifierCount(), 2);

    // Add another subverifier
    ZKPassportSubVerifier anotherSubVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    bytes32 anotherVersion = bytes32(uint256(3));
    vm.prank(admin);
    rootVerifier.addSubVerifier(anotherVersion, anotherSubVerifier);
    assertEq(rootVerifier.subverifierCount(), 3);

    // Remove a subverifier
    vm.prank(admin);
    rootVerifier.removeSubVerifier(newVersion);
    assertEq(rootVerifier.subverifierCount(), 2);

    // Remove another subverifier
    vm.prank(admin);
    rootVerifier.removeSubVerifier(anotherVersion);
    assertEq(rootVerifier.subverifierCount(), 1);
  }

  function testHelperCountTracking() public {
    // Initial count should be 1 (from setUp)
    assertEq(rootVerifier.helperCount(), 1);

    // Add a new helper
    IRootRegistry rootRegistry = IRootRegistry(address(0x1234));
    ZKPassportHelper newHelper = new ZKPassportHelper(rootRegistry);
    bytes32 newVersion = bytes32(uint256(2));
    vm.prank(admin);
    rootVerifier.addHelper(newVersion, address(newHelper));
    assertEq(rootVerifier.helperCount(), 2);

    // Add another helper
    ZKPassportHelper anotherHelper = new ZKPassportHelper(rootRegistry);
    bytes32 anotherVersion = bytes32(uint256(3));
    vm.prank(admin);
    rootVerifier.addHelper(anotherVersion, address(anotherHelper));
    assertEq(rootVerifier.helperCount(), 3);

    // Remove a helper
    vm.prank(admin);
    rootVerifier.removeHelper(newVersion);
    assertEq(rootVerifier.helperCount(), 2);

    // Remove another helper
    vm.prank(admin);
    rootVerifier.removeHelper(anotherVersion);
    assertEq(rootVerifier.helperCount(), 1);
  }
}
