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
    bytes32(hex"1c9e0a53b95067a306ef0eadf8667fd624a8596fc260fd9de0f04995fcd2e52f"),
    // Outer (5 subproofs)
    bytes32(hex"1aca3f53ebb5ab91e1d7b9885d8822f242a79fac6b85e43aa76be8b137507b1a"),
    // Outer (6 subproofs)
    bytes32(hex"0f953a003267c88dc065e9b7684ac1d11ef9a5686ec1a83a580755f5876217a6"),
    // Outer (7 subproofs)
    bytes32(hex"0034095018ac7d700bee7f89f913e5964473d21461780baaef0e18c85b1d0460"),
    // Outer (8 subproofs)
    bytes32(hex"22044224e2eae3d918bf83aa08fcc8a4764f39c3ce03871ed0dfa9d2e3857bdb"),
    // Outer (9 subproofs)
    bytes32(hex"2c3ef223ed4a13a8cd14267bd88842942f8085084493788d478b0cb0f3bd2b1c"),
    // Outer (10 subproofs)
    bytes32(hex"163d556a18a7e9804e2c1fc281665ce3c9fe7dcbe5f91beb45c686f2dd77e207"),
    // Outer (11 subproofs)
    bytes32(hex"207f7f49e5b8a47b8194ae3b6caa5fc50e1c221693f53dd2166f626ddb9335b6"),
    // Outer (12 subproofs)
    bytes32(hex"20f92c983d45ce885ca88288d5f8e2a0b182fcb0f141b2477c72aa4bb8c416df")
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
