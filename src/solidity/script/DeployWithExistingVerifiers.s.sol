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
    bytes32(hex"0770a0542e389605af3e92d1c4838f9d33a430a68e7deecfbf0a523070a4145d"),
    // Outer (5 subproofs)
    bytes32(hex"1d33714b15cd8265d05f157883a92d9b420b965173299bac9a4cba51190b1322"),
    // Outer (6 subproofs)
    bytes32(hex"1bb78391bacf4c9daf784e55431caa31ea87bcd5ba92da57abcbcc40c4367967"),
    // Outer (7 subproofs)
    bytes32(hex"296d18dcc28e0ca6da82ffdb06c8844bbe27647e9eee8e802bc2004830a85716"),
    // Outer (8 subproofs)
    bytes32(hex"174c0f083d56e7adc34e7092ec1b91b058b164488069a67423af125740cd3970"),
    // Outer (9 subproofs)
    bytes32(hex"0316b62b169a4d4ef245d119251485fd507cce2834b5bd2d0bb32b25c5dd5572"),
    // Outer (10 subproofs)
    bytes32(hex"0167c195c083ed30cd5fe7873f5ba8f9ebb3f06e08260410e0af47b61a5dd1a5"),
    // Outer (11 subproofs)
    bytes32(hex"28a3e66a6907a03985e4b24f3abcfa358867404d12b058f0b27d880a51f10859"),
    // Outer (12 subproofs)
    bytes32(hex"1c81f163dd55398fd48bca2d6497ff50b3246ef29ac0009ab431e0ad8242a105"),
    // Outer (13 subproofs)
    bytes32(hex"0af493a9673656b75721ac93f242ebad0efde03aab2ae16b25be929c00e21b50")
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
