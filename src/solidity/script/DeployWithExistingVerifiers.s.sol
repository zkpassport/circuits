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
    bytes32(hex"069f039e7d9a3a64d963797f9a7232380dab2c2cd294c1d7864105b7caa6ea00"),
    // Outer (12 subproofs)
    bytes32(hex"0f4fa787b5033e1c36b21e2a5408947993bf160986b11bbf2f8e9a4bac24309b")
  ];

  address[] public verifierAddresses = [
    address(0x54D7862040FE1DC9d725673C1bb9188b4d22aEC5),
    address(0x19d2E6D1E08c9Dbf999eeCA91F0F63789874aC05),
    address(0x8ac98c8eD23Af17664a358a0256B7D554Be541b9),
    address(0xFc1399ee5379A5187ed87f534B0Fc4Ffd8eE065c),
    address(0x6309cc0bB4A81B4d486BD78ef55716947acdDE8F),
    address(0xDDd5864BC4b466b9DfFD8d676319d2E85ceD62b4),
    address(0x31Fe0B6d343Ba034C4a42BAc9F2709e5C864dC7C),
    address(0x98b94FcF3df6522EE86a1FC18Bbd8BeD6958089A),
    address(0x56879bFEfE37C5ccF7A66d3247D6Aa40D03BEa45)
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
    verifiers = vm.serializeAddress(verifiers, "outer_count_12", verifierAddresses[8]);

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
