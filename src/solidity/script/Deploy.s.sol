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
    bytes32(hex"2cb0301d4fccf542247d2164335a1ac1a94be519757be9a8f76556e95ad4110a"),
    // Outer (5 subproofs)
    bytes32(hex"20a5dfe7875cf4cb9fe6b4e13397434bc7b33ebb42431c09f9d2eb20f0f09a4d"),
    // Outer (6 subproofs)
    bytes32(hex"2fe35634ea36d09761105fc3b6dfb4883411171afddc6c2e146ae350a72b53d6"),
    // Outer (7 subproofs)
    bytes32(hex"2b7ee89fd25220e326fcc9eed4b5876a913cd660cc8e6c4392ea3a1e1d989f61"),
    // Outer (8 subproofs)
    bytes32(hex"17407da3db9149eea7c0a22ae09777c7408da8ad31e7aa7e689a224d84c6fbef"),
    // Outer (9 subproofs)
    bytes32(hex"0b5c94def57b9e2ec5ade654250770319a8cc1b7a3477bea2806b57b6721bf79"),
    // Outer (10 subproofs)
    bytes32(hex"1173f738a63900f154d8c6888f915270189f615ee9022553e16a5d768849ae20"),
    // Outer (11 subproofs)
    bytes32(hex"264d993757611bb8bf4d2f11700e68dfdcb52b1061d6730ebc0586dbd9970055"),
    // Outer (12 subproofs)
    bytes32(hex"1c9b4dbc93bcf1112ad3ffbd02015e088f8acd74e9043f13bd134f9fec9a42fe"),
    // Outer (13 subproofs)
    bytes32(hex"0b3b18a01c22280ed3f359f2ab624a49ac305300ec89e090772f6407e46300ba")
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
