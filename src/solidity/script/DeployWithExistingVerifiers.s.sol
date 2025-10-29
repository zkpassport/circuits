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
