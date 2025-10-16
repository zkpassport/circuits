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

  address[] public verifierAddresses = [
    address(0xFaE3636d86e4604E8e862C4a12289D7591317ECc),
    address(0x2BB71DFA7A7f4Ee050a01F18b76f50b3B496be1b),
    address(0xBE721A6984C6179D187268dc2108d69ad93fd1bd),
    address(0x2d4e00D66a827A08A456Ab4f7A4eE9dDfF34DF5a),
    address(0xF18BF207EC357Fa211b1e60d1CDf29921198f0Ad),
    address(0x5Fe57Ea506aeb69Be166e15FEDcc94cB60D804C0),
    address(0x77fc39C00E0C4df7A9993962F619535DCe5AB656),
    address(0x91964BECE4dF2a5A3E878b5B6Fa13466e2d192Cf),
    address(0x259CC6e2eC9ea9493b307f032b75a35373f4FE3F),
    address(0xb68dE6E9ef2E2BBD5cC387a3cf2b5FeD714535d7)
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
  }
}
