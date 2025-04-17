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
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {stdJson} from "forge-std/StdJson.sol";

contract Deploy is Script {
  using stdJson for string;

  bytes32[] public vkeyHashes = [
    // Outer (4 subproofs)
    bytes32(hex"008eb40d971a28de3157941b06eca6a9d97984855c415e1e6759b2c0f03b5540"),
    // Outer (5 subproofs)
    bytes32(hex"0c8c35f5c432db69fa4fca78209915f6d04684cd14bccc8f930f9fb8d3998bbc"),
    // Outer (6 subproofs)
    bytes32(hex"18b5a54dd4dbf07fa45d6a98b99e4059bb0451815893353cba0ed23a35db645a"),
    // Outer (7 subproofs)
    bytes32(hex"0a74b6f0d9229f0b8cf21e7b4ed4062dc173366fc8accb3ea09c5758643aa516"),
    // Outer (8 subproofs)
    bytes32(hex"10dc3ff4352429ba0cb98915698aeb9461e4c929860df9ce324b887c68d78e08"),
    // Outer (9 subproofs)
    bytes32(hex"1ad5e890551debb76e722e977143df02b409607fc6271d37f3ba1e38532859ad"),
    // Outer (10 subproofs)
    bytes32(hex"133b430a9eb889e77185dae5b0505ec9fa0c27e4e8e5b0887c7914954b9b8440"),
    // Outer (11 subproofs)
    bytes32(hex"069f039e7d9a3a64d963797f9a7232380dab2c2cd294c1d7864105b7caa6ea00")
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

    console.log("Deploying ZKPassportVerifier...");
    ZKPassportVerifier zkPassportVerifier = new ZKPassportVerifier();
    console.log("ZKPassportVerifier deployed at:", address(zkPassportVerifier));

    // Add verifiers to ZKPassportVerifier
    address[] memory verifierAddresses = new address[](8);
    verifierAddresses[0] = address(outerCount4Verifier);
    verifierAddresses[1] = address(outerCount5Verifier);
    verifierAddresses[2] = address(outerCount6Verifier);
    verifierAddresses[3] = address(outerCount7Verifier);
    verifierAddresses[4] = address(outerCount8Verifier);
    verifierAddresses[5] = address(outerCount9Verifier);
    verifierAddresses[6] = address(outerCount10Verifier);
    verifierAddresses[7] = address(outerCount11Verifier);
    console.log("Adding verifiers to ZKPassportVerifier...");
    zkPassportVerifier.addVerifiers(vkeyHashes, verifierAddresses);
    console.log("Verifiers added to ZKPassportVerifier");

    console.log("Setting certificate registry root...");
    zkPassportVerifier.addCertificateRegistryRoot(
      bytes32(hex"17f72a43f711983c607deb82b512cff23e949ba928b48ccb8759c587f06d6479")
    );
    console.log("Certificate registry root set");

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
    verifiers = vm.serializeAddress(verifiers, "outer_count_11", address(outerCount11Verifier));

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
  }
}
