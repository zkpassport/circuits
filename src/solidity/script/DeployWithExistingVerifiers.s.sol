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
    bytes32(hex"15d407221176fb9572c702916ce0c237860ac6ac552a3afa45f9d957ec8f0621"),
    // Outer (5 subproofs)
    bytes32(hex"2ab349ef31f5d516da820a3f55f93c53f9c899b0b991c93fc341199cc1e3b36c"),
    // Outer (6 subproofs)
    bytes32(hex"2576d3f4f0897c17b1d2b7febd1314a57bb72afeca29edf523edfb07d4c14d9a"),
    // Outer (7 subproofs)
    bytes32(hex"27d0dcab9b2f13e212ceb496e7bdb2beae7dae38effc35ae2d1aa966ac9d7de1"),
    // Outer (8 subproofs)
    bytes32(hex"1e3e8957ace4ffc4fe414dce90542f1ea3a04c25a50c281335ccc5e8f111feec"),
    // Outer (9 subproofs)
    bytes32(hex"0529546d079df5832a12403f9537dc026d36e5a1fb3d7760ccaa38ba8339eef3"),
    // Outer (10 subproofs)
    bytes32(hex"22176867c431dcf4818884cf1127cb9499ddb9af8068c88b63303c66b8cade3a"),
    // Outer (11 subproofs)
    bytes32(hex"2f55019d8fd28cf77000af567e4d8fcb54ef0d4853825d61b14911904b20d1c5"),
    // Outer (12 subproofs)
    bytes32(hex"1fdff1847be0a0ac3af37e59d0f83b2a400c15be4049954dc82aba099b0c9924")
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
