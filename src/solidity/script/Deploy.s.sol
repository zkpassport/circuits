// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier as OuterCount4Verifier} from "../src/ultra-honk-verifiers/OuterCount4.sol";
import {HonkVerifier as OuterCount5Verifier} from "../src/ultra-honk-verifiers/OuterCount5.sol";
import {HonkVerifier as OuterCount6Verifier} from "../src/ultra-honk-verifiers/OuterCount6.sol";
import {HonkVerifier as OuterCount7Verifier} from "../src/ultra-honk-verifiers/OuterCount7.sol";
import {HonkVerifier as OuterCount8Verifier} from "../src/ultra-honk-verifiers/OuterCount8.sol";
import {HonkVerifier as OuterCount9Verifier} from "../src/ultra-honk-verifiers/OuterCount9.sol";
import {HonkVerifier as OuterCount10Verifier} from "../src/ultra-honk-verifiers/OuterCount10.sol";
import {HonkVerifier as OuterCount11Verifier} from "../src/ultra-honk-verifiers/OuterCount11.sol";
import {HonkVerifier as OuterCount12Verifier} from "../src/ultra-honk-verifiers/OuterCount12.sol";
import {HonkVerifier as OuterCount13Verifier} from "../src/ultra-honk-verifiers/OuterCount13.sol";
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {stdJson} from "forge-std/StdJson.sol";

contract Deploy is Script {
  using stdJson for string;

  bytes32[] public vkeyHashes = [
    // Outer (4 subproofs)
    bytes32(hex"2c8e4c98562c77a540b8b023316558d38f5fd4deffe1a66be1697d9f5839846c"),
    // Outer (5 subproofs)
    bytes32(hex"0677b0e9f3c876427993f04e2ec4eea3fbf1e9363a62a679943c01964b83a583"),
    // Outer (6 subproofs)
    bytes32(hex"2f0366ca6880ea7948f7950db2c333160d4def928fa35a54e81ee85b323aa021"),
    // Outer (7 subproofs)
    bytes32(hex"1d741006ac1d4f10c8442dadf8769682c2ebb3e7a2f58d280e85f2716267bf8b"),
    // Outer (8 subproofs)
    bytes32(hex"039c1e0fbd7ddeb1890499d2f170ec6021e6c5f7c0c49755044acabea1fa0e96"),
    // Outer (9 subproofs)
    bytes32(hex"1c06373ea0afd29cc65af42b2ee1fac05d638ed2e404fc695f521c7011fa5f32"),
    // Outer (10 subproofs)
    bytes32(hex"02e191a068306c508f466c082d9bf86ef6530a423f7a067b35d1083266c4ad7e"),
    // Outer (11 subproofs)
    bytes32(hex"270bded62c09b938c8f31bc4b512848681080158182a88ebaa3f63b71c05a01a"),
    // Outer (12 subproofs)
    bytes32(hex"23163e1a43c894a20778c76c8a211f5fc9cd29cc96c2d6258998a2c8b996e643"),
    // Outer (13 subproofs)
    bytes32(hex"030bd4331d4a001e38b3b1c6a20c21f74f24f86ace935292bc1282661f3b1409")
  ];

  address[] public verifierAddresses = new address[](10);

  function run() public {
    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

    // Log the deployment
    console.log("Deploying Outer (4 subproofs) verifier...");
    // Deploy the contract
    verifierAddresses[0] = address(new OuterCount4Verifier());
    console.log("Outer (4 subproofs) verifier deployed at:", verifierAddresses[0]);

    console.log("Deploying Outer (5 subproofs) verifier...");
    verifierAddresses[1] = address(new OuterCount5Verifier());
    console.log("Outer (5 subproofs) verifier deployed at:", verifierAddresses[1]);

    console.log("Deploying Outer (6 subproofs) verifier...");
    verifierAddresses[2] = address(new OuterCount6Verifier());
    console.log("Outer (6 subproofs) verifier deployed at:", verifierAddresses[2]);

    console.log("Deploying Outer (7 subproofs) verifier...");
    verifierAddresses[3] = address(new OuterCount7Verifier());
    console.log("Outer (7 subproofs) verifier deployed at:", verifierAddresses[3]);

    console.log("Deploying Outer (8 subproofs) verifier...");
    verifierAddresses[4] = address(new OuterCount8Verifier());
    console.log("Outer (8 subproofs) verifier deployed at:", verifierAddresses[4]);

    console.log("Deploying Outer (9 subproofs) verifier...");
    verifierAddresses[5] = address(new OuterCount9Verifier());
    console.log("Outer (9 subproofs) verifier deployed at:", verifierAddresses[5]);

    console.log("Deploying Outer (10 subproofs) verifier...");
    verifierAddresses[6] = address(new OuterCount10Verifier());
    console.log("Outer (10 subproofs) verifier deployed at:", verifierAddresses[6]);

    console.log("Deploying Outer (11 subproofs) verifier...");
    verifierAddresses[7] = address(new OuterCount11Verifier());
    console.log("Outer (11 subproofs) verifier deployed at:", verifierAddresses[7]);

    console.log("Deploying Outer (12 subproofs) verifier...");
    verifierAddresses[8] = address(new OuterCount12Verifier());
    console.log("Outer (12 subproofs) verifier deployed at:", verifierAddresses[8]);

    console.log("Deploying Outer (13 subproofs) verifier...");
    verifierAddresses[9] = address(new OuterCount13Verifier());
    console.log("Outer (13 subproofs) verifier deployed at:", verifierAddresses[9]);

    console.log("Deploying ZKPassportVerifier...");
    address rootRegistry = vm.envAddress("ROOT_REGISTRY_ADDRESS");
    ZKPassportVerifier zkPassportVerifier = new ZKPassportVerifier(rootRegistry);
    console.log("ZKPassportVerifier deployed at:", address(zkPassportVerifier));

    // Add verifiers to ZKPassportVerifier
    console.log("Adding verifiers to ZKPassportVerifier...");
    zkPassportVerifier.addVerifiers(vkeyHashes, verifierAddresses);
    console.log("Verifiers added to ZKPassportVerifier");

    // Stop broadcasting transactions
    vm.stopBroadcast();

    // Create JSON for verifiers
    string memory verifiers = "verifiers";
    vm.serializeAddress(verifiers, "outer_count_4", verifierAddresses[0]);
    vm.serializeAddress(verifiers, "outer_count_5", verifierAddresses[1]);
    vm.serializeAddress(verifiers, "outer_count_6", verifierAddresses[2]);
    vm.serializeAddress(verifiers, "outer_count_7", verifierAddresses[3]);
    vm.serializeAddress(verifiers, "outer_count_8", verifierAddresses[4]);
    vm.serializeAddress(verifiers, "outer_count_9", verifierAddresses[5]);
    vm.serializeAddress(verifiers, "outer_count_10", verifierAddresses[6]);
    vm.serializeAddress(verifiers, "outer_count_11", verifierAddresses[7]);
    vm.serializeAddress(verifiers, "outer_count_12", verifierAddresses[8]);
    verifiers = vm.serializeAddress(verifiers, "outer_count_13", verifierAddresses[9]);

    // Create the main JSON object
    string memory mainJson = "main";

    // Add deployment details to the main JSON
    vm.serializeUint(mainJson, "chain_id", block.chainid);
    vm.serializeString(mainJson, "deployment_timestamp", vm.toString(block.timestamp));
    vm.serializeAddress(mainJson, "zk_passport_verifier", address(zkPassportVerifier));

    // Add verifiers object to the main JSON
    string memory finalJson = vm.serializeString(mainJson, "verifiers", verifiers);

    // Ensure deployments directory exists
    string memory deploymentsDir = "./deployments";
    if (!vm.exists(deploymentsDir)) {
      vm.createDir(deploymentsDir, true);
    }

    // Write the JSON to a file in the deployments folder
    string memory chainId = vm.toString(block.chainid);
    string memory outputPath = string.concat(deploymentsDir, "/deployment-", chainId, ".json");
    vm.writeJson(finalJson, outputPath);
    console.log("Deployment addresses written to:", outputPath);
    console.log("Don't forget to update the addresses in DeployWithExistingVerifiers.s.sol");
  }
}
