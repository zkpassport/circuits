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
    bytes32(hex"1fdff1847be0a0ac3af37e59d0f83b2a400c15be4049954dc82aba099b0c9924"),
    // Outer (13 subproofs)
    bytes32(hex"1fc14cf5b71709c9e08dea91c9708686f2fd3dcf4de8172fb4130712159169ae")
  ];

  address[] public verifierAddresses = [
    address(0x090182EB9088456F65AfE22d5a61C22884D64A42),
    address(0x02622888c339798905d9C64565560f38FC77c121),
    address(0xDd2a5dD6548b433C533a2b20861A2c7F78cdD7B0),
    address(0x5EC848eccB05BfCe45F4A287343858b0e94E8E1f),
    address(0x7B34489CCf615b07608A5CcF09ac64D764Eea61a),
    address(0xfc4DbCd1B00235640D8749682094d02FA16dC1d1),
    address(0xd07B187D98CD4Ca9bca28c43256Fba1Ee430F3d9),
    address(0xD503FeCac436D7Fd3c1da5789199899D6dE5EAd5),
    address(0x84a6Bfb31885f5Ee9e2d2A68Ab2040C254ed5787)
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
