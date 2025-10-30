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
