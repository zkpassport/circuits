// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier as OuterCount4Verifier} from "../src/OuterCount4.sol";
import {HonkVerifier as OuterCount5Verifier} from "../src/OuterCount5.sol";
import {HonkVerifier as OuterCount6Verifier} from "../src/OuterCount6.sol";
import {HonkVerifier as OuterCount7Verifier} from "../src/OuterCount7.sol";
import {HonkVerifier as OuterCount8Verifier} from "../src/OuterCount8.sol";
import {HonkVerifier as OuterCount9Verifier} from "../src/OuterCount9.sol";
import {HonkVerifier as OuterCount10Verifier} from "../src/OuterCount10.sol";
import {HonkVerifier as OuterCount11Verifier} from "../src/OuterCount11.sol";
import {HonkVerifier as OuterCount12Verifier} from "../src/OuterCount12.sol";
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {stdJson} from "forge-std/StdJson.sol";

contract Deploy is Script {
  using stdJson for string;

  bytes32[] public vkeyHashes = [
    // Outer (4 subproofs)
    bytes32(hex"15d407221176fb9572c702916ce0c237860ac6ac552a3afa45f9d957ec8f0621"),
    // Outer (5 subproofs)
    bytes32(hex"2ab349ef31f5d516da820a3f55f93c53f9c899b0b991c93fc341199cc1e3b36c"),
    // Outer (6 subproofs)
    bytes32(hex"2576d3f4f0897c17b1d2b7febd1314a57bb72afeca29edf523edfb07d4c14d9a"),
    // Outer (7 subproofs)
    bytes32(hex"27d0dcab9b2f13e212ceb496e7bdb2beae7dae38effc35ae2d1aa966ac9d7de1"),
    // Outer (8 subproofs)
    bytes32(hex"1e3e8957ace4ffc4fe414dce90542f1ea3a04c25a50c281335ccc5e8f111feec"),
    // Outer (9 subproofs)
    bytes32(hex"0529546d079df5832a12403f9537dc026d36e5a1fb3d7760ccaa38ba8339eef3"),
    // Outer (10 subproofs)
    bytes32(hex"22176867c431dcf4818884cf1127cb9499ddb9af8068c88b63303c66b8cade3a"),
    // Outer (11 subproofs)
    bytes32(hex"2f55019d8fd28cf77000af567e4d8fcb54ef0d4853825d61b14911904b20d1c5"),
    // Outer (12 subproofs)
    bytes32(hex"1fdff1847be0a0ac3af37e59d0f83b2a400c15be4049954dc82aba099b0c9924")
  ];

  function run() public {
    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

    // Log the deployment
    console.log("Deploying Outer (4 subproofs) verifier...");
    // Deploy the contract
    OuterCount4Verifier outerCount4Verifier = new OuterCount4Verifier();
    console.log("Outer (4 subproofs) verifier deployed at:", address(outerCount4Verifier));

    console.log("Deploying Outer (5 subproofs) verifier...");
    OuterCount5Verifier outerCount5Verifier = new OuterCount5Verifier();
    console.log("Outer (5 subproofs) verifier deployed at:", address(outerCount5Verifier));

    console.log("Deploying Outer (6 subproofs) verifier...");
    OuterCount6Verifier outerCount6Verifier = new OuterCount6Verifier();
    console.log("Outer (6 subproofs) verifier deployed at:", address(outerCount6Verifier));

    console.log("Deploying Outer (7 subproofs) verifier...");
    OuterCount7Verifier outerCount7Verifier = new OuterCount7Verifier();
    console.log("Outer (7 subproofs) verifier deployed at:", address(outerCount7Verifier));

    console.log("Deploying Outer (8 subproofs) verifier...");
    OuterCount8Verifier outerCount8Verifier = new OuterCount8Verifier();
    console.log("Outer (8 subproofs) verifier deployed at:", address(outerCount8Verifier));

    console.log("Deploying Outer (9 subproofs) verifier...");
    OuterCount9Verifier outerCount9Verifier = new OuterCount9Verifier();
    console.log("Outer (9 subproofs) verifier deployed at:", address(outerCount9Verifier));

    console.log("Deploying Outer (10 subproofs) verifier...");
    OuterCount10Verifier outerCount10Verifier = new OuterCount10Verifier();
    console.log("Outer (10 subproofs) verifier deployed at:", address(outerCount10Verifier));

    console.log("Deploying Outer (11 subproofs) verifier...");
    OuterCount11Verifier outerCount11Verifier = new OuterCount11Verifier();
    console.log("Outer (11 subproofs) verifier deployed at:", address(outerCount11Verifier));

    console.log("Deploying Outer (12 subproofs) verifier...");
    OuterCount12Verifier outerCount12Verifier = new OuterCount12Verifier();
    console.log("Outer (12 subproofs) verifier deployed at:", address(outerCount12Verifier));

    console.log("Deploying ZKPassportVerifier...");
    address rootRegistry = vm.envAddress("ROOT_REGISTRY_ADDRESS");
    ZKPassportVerifier zkPassportVerifier = new ZKPassportVerifier(rootRegistry);
    console.log("ZKPassportVerifier deployed at:", address(zkPassportVerifier));

    // Add verifiers to ZKPassportVerifier
    address[] memory verifierAddresses = new address[](9);
    verifierAddresses[0] = address(outerCount4Verifier);
    verifierAddresses[1] = address(outerCount5Verifier);
    verifierAddresses[2] = address(outerCount6Verifier);
    verifierAddresses[3] = address(outerCount7Verifier);
    verifierAddresses[4] = address(outerCount8Verifier);
    verifierAddresses[5] = address(outerCount9Verifier);
    verifierAddresses[6] = address(outerCount10Verifier);
    verifierAddresses[7] = address(outerCount11Verifier);
    verifierAddresses[8] = address(outerCount12Verifier);
    console.log("Adding verifiers to ZKPassportVerifier...");
    zkPassportVerifier.addVerifiers(vkeyHashes, verifierAddresses);
    console.log("Verifiers added to ZKPassportVerifier");

    // Stop broadcasting transactions
    vm.stopBroadcast();

    // Create JSON for verifiers
    string memory verifiers = "verifiers";
    vm.serializeAddress(verifiers, "outer_count_4", address(outerCount4Verifier));
    vm.serializeAddress(verifiers, "outer_count_5", address(outerCount5Verifier));
    vm.serializeAddress(verifiers, "outer_count_6", address(outerCount6Verifier));
    vm.serializeAddress(verifiers, "outer_count_7", address(outerCount7Verifier));
    vm.serializeAddress(verifiers, "outer_count_8", address(outerCount8Verifier));
    vm.serializeAddress(verifiers, "outer_count_9", address(outerCount9Verifier));
    vm.serializeAddress(verifiers, "outer_count_10", address(outerCount10Verifier));
    vm.serializeAddress(verifiers, "outer_count_11", address(outerCount11Verifier));
    verifiers = vm.serializeAddress(verifiers, "outer_count_12", address(outerCount12Verifier));

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
