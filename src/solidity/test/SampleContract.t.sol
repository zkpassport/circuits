// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

import {console} from "forge-std/Test.sol";
import {ZKPassportRootVerifier} from "../src/ZKPassportRootVerifier.sol";
import {ServiceConfig, ProofVerificationParams, ProofVerificationData} from "../src/Types.sol";
import {SampleContract} from "../src/SampleContract.sol";
import {ZKPassportTest} from "./Utils.t.sol";

contract SampleContractTest is ZKPassportTest {
  SampleContract public sampleContract;

  function setUp() public {
    (ZKPassportRootVerifier verifier,) = deployZKPassport();
    sampleContract = new SampleContract(address(verifier));
  }

  function test_RegisterUser() public {
    // Load fixture data
    FixtureData memory data = loadFixture(fixtures.allSubproofs);

    // Warp the clock to the date the proof was generated
    uint256 currentDate = uint256(data.publicInputs[2]);
    vm.warp(currentDate);

    // The sender cannot call this function yet because they have not registered and been verified
    vm.expectRevert("User is not verified");
    sampleContract.doStuff();

    // Construct the ZKPassport verification params
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

    // Register the user
    bytes32 uniqueIdentifier = sampleContract.register(params, false);

    // The sender may now call this function because they have successfully registered with a valid proof
    sampleContract.doStuff();

    // Assert the user is verified and has the correct nationality and unique identifier
    assertEq(uniqueIdentifier, bytes32(uint256(0x171de101deed3f056917faecfe6cc04db2ef02689a8a483962a688948ce44461)));
    assertEq(sampleContract.userNationality(uniqueIdentifier), "AUS");
    assertEq(sampleContract.isVerified(uniqueIdentifier), true);
  }
}
