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
    bytes32(hex"002cff3eaa65901b50ea3555d1a070ad7b23126851e2ad57bc1122ec5a4994b6"),
    // Outer (5 subproofs)
    bytes32(hex"04b98c6f867d6a7f86d514b72c3be8f41b7aa6f49fdc17514c9f9f0a2ac3ef9a"),
    // Outer (6 subproofs)
    bytes32(hex"1c25b26637e823b0105714fe5a11abd481fa89e616d178dfa9304f9018d71a7c"),
    // Outer (7 subproofs)
    bytes32(hex"037bacae76c618c185871f55813dc04f30472ee4f7a40de77cc5d25479a33b02"),
    // Outer (8 subproofs)
    bytes32(hex"08f8c30378dc56d31446be9982b2ecd878ffbdcca5bda478cb879f232f594bcf"),
    // Outer (9 subproofs)
    bytes32(hex"22ef7b9ab563c2644c49949bef17afae5a83c8f4ccea9afe6a73f4446fc3a1bc"),
    // Outer (10 subproofs)
    bytes32(hex"0e3f3d2965912c486a91f8a8fdc6357c8c877183eaa113caedcbd17526cbfc73"),
    // Outer (11 subproofs)
    bytes32(hex"048f929a5be0814a81e5c4e62305e5cd4d203fb5e56c9ae5f5990aeee8fcabb4"),
    // Outer (12 subproofs)
    bytes32(hex"0a967e84d1198f536a8a5c699045a5616b63de415e5cec99c19ca2ca85a0ed52")
  ];

  address[] public verifierAddresses = [
    address(0x65Bd288f4318e8A306801ebD82a4162eF86eb3FC),
    address(0x43Af964E1AD9473e1F6f2191D7235150084905cF),
    address(0x83D72b75DAa56d4824Bd34e31CAE4257d50dF568),
    address(0xce9da8FF5b338e2B08984a764dE1A2CbEf8571a2),
    address(0x19B9C870cA60Cb97292fe5D6e95c8D2A51CC4b75),
    address(0x262582FA03Ac4c36aecc5fd791EE1d0992DA79F9),
    address(0x734Eeff3B0e848395d1A596bde92f91f50e7d77C),
    address(0xF35075143f366046E91a895418677B8593962445),
    address(0x3e79F7dAa28ad340161675077919af0b26281B5c)
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
