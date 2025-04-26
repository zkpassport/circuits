// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
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

  address[] public verifierAddresses = [
    address(0x605946fcdF41e8c5Ff5b0059562AACE405d1C129),
    address(0x50e3745058be9155f2dF1fB8A5adF845AA5fAA92),
    address(0x3BD42C90f45969465F3b93bC00bDED8346810e61),
    address(0x63c26D62F5D53234BAf3C35E29dc02fE5C2d55D5),
    address(0xb413e98d2d416b78b41807be51D5929A21b66a60),
    address(0x4EC27F70Ab5e10D926D6dCc0AF4DEca30562fF86),
    address(0xD90b4C11Ef8e4005753C123755441F43341a63f4),
    address(0xaB6e5f7cCBf41E1afaCe9FaEA2c79934657430a2)
  ];

  function run() public {
    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

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
    verifiers = vm.serializeAddress(verifiers, "outer_count_11", verifierAddresses[7]);

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
