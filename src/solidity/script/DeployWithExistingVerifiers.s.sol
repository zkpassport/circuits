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
    bytes32(hex"1e7968a3ae35c0fe7745dec9a46ed719fe24fefa452c0675805a0b0bf54866d8"),
    // Outer (5 subproofs)
    bytes32(hex"0224c6293386f8ecf70f59dc041af91ab7cf90b9268b9e0ecfbd96f3d3e713a8"),
    // Outer (6 subproofs)
    bytes32(hex"2dba57165e97c1ca219fe7c8c134e11474e0f608c09a32c0f497f0dfe705ddc4"),
    // Outer (7 subproofs)
    bytes32(hex"14033dd4f864ce40aad49e54702e57a771c105ff6de2ebad49e8d4977f47ec71"),
    // Outer (8 subproofs)
    bytes32(hex"1022e0f55e81e5be7d28f20129d7c7b91b20f7cc752643d07dfffb980f122535"),
    // Outer (9 subproofs)
    bytes32(hex"2197791a2e2c71a7f76d99c04732c1e98acd709975f580a6fcdaa94f27efd732"),
    // Outer (10 subproofs)
    bytes32(hex"1a738923df6452846f31a9624354cc0211f48a33cade1d01b2d1ebe2e2dd8847"),
    // Outer (11 subproofs)
    bytes32(hex"114a570edf27e73722d930a50ebc8d5ab9febbda7be12122ff52e58989b11256"),
    // Outer (12 subproofs)
    bytes32(hex"12be9e815e9d30998c7324b4ee615b9e951bfad8659225ace3ae518c612c71c5")
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
