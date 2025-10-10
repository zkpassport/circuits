// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {stdJson} from "forge-std/StdJson.sol";
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

contract Deploy is Script {
  using stdJson for string;

  bytes32[] public vkeyHashes = [
    // Outer (4 subproofs)
    bytes32(hex"1859ae7ba8693dec52124a4b875fee85c4151d15d024517b45646e2e1d5d3feb"),
    // Outer (5 subproofs)
    bytes32(hex"29c49bef320259ea2c624e4766fc81beaeeb8e937512abe9f07d5062fefbf858"),
    // Outer (6 subproofs)
    bytes32(hex"1cecf7f825a5dbca407661450184be3d29f2add71ddfa5eae0e32158b008ec89"),
    // Outer (7 subproofs)
    bytes32(hex"203dc27bc362397d3f0493315ab6aa4ed1a08d9c06da34a8fa4ca4a9435d3504"),
    // Outer (8 subproofs)
    bytes32(hex"254314c80a8cc3efc785643a0a6aeeba6ae268a45e69a98affd4a4155f01e186"),
    // Outer (9 subproofs)
    bytes32(hex"28b5def79e1214d43cc4e80a58ae74abe3ab90ad7413b5a6ed1d92bf54b2425c"),
    // Outer (10 subproofs)
    bytes32(hex"262367c2824e80a95f391e73c7535fc8f9f3f1d8cdd8b3c1a53657caa2606e1e"),
    // Outer (11 subproofs)
    bytes32(hex"1decfdc09512e3d9b67b9cc4a9d33c5b3ab3fb4509a16490020535bcff24d1de"),
    // Outer (12 subproofs)
    bytes32(hex"263b0f11d4296d15b55ec5a0b1a5456d92a894d66ed427d6e5c33223fac6fd50"),
    // Outer (13 subproofs)
    bytes32(hex"0c7ec713f16662ff7c088aca5f138b6d05c8990d3f0e6685f883c8246af4ca3b")
  ];

  address[] public verifierAddresses = new address[](10);

  function run() public {
    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

    // Load the ZKPassportVerifier from deployment file (deployment-{chainId}.json)
    string memory deploymentJson = vm.readFile(
      string.concat("./deployments/deployment-", vm.toString(block.chainid), ".json")
    );
    address zkPassportVerifierAddress = deploymentJson.readAddress(".zk_passport_verifier");
    ZKPassportVerifier zkPassportVerifier = ZKPassportVerifier(zkPassportVerifierAddress);
    console.log("ZKPassportVerifier loaded at:", zkPassportVerifierAddress);

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

    // Write the JSON to a file in the deployments folder
    string memory outputPath = string.concat(
      "./deployments/verifiers-c:",
      vm.toString(block.chainid),
      "-t:",
      vm.toString(block.timestamp),
      ".json"
    );
    vm.writeJson(finalJson, outputPath);
    console.log("Verifier addresses written to:", outputPath);
  }
}
