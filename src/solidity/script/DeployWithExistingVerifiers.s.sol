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
    bytes32(hex"1419578b1eae95680b6e68a5e60513c9f2dc5bb28d03bc24e27f3496a6c2910f"),
    // Outer (5 subproofs)
    bytes32(hex"12b3086822e91aff819188d124a396b23d3ebdf9ab3e6fbb209585e3fcdebc5e"),
    // Outer (6 subproofs)
    bytes32(hex"05653ebab1ea4f706c1d46458774649515f6641311d9d107e126a4b486160095"),
    // Outer (7 subproofs)
    bytes32(hex"00932ef8d4286f5bed849bdd0d8d057ee1896070697898cfb7863ee5777c6e1a"),
    // Outer (8 subproofs)
    bytes32(hex"156d0cae8e80c75d64bec7ce4e242c3a685bccab2e5503de3f3177fa05edd9cd"),
    // Outer (9 subproofs)
    bytes32(hex"2c4eb7dc99a3d333619565ee4271f33f5c7d2967d74ad4da1d784cf72f6a6628"),
    // Outer (10 subproofs)
    bytes32(hex"04d9b824eb8f5281877525ddddc3eaa20346cc3dc113c8b30ea6c17c6e5e3037"),
    // Outer (11 subproofs)
    bytes32(hex"0de666646c1b8789226f13a0dbdd172e2f2787612420a2e2815d7d0ff32d5610"),
    // Outer (12 subproofs)
    bytes32(hex"240ec977633696dd2d3be0df8badd70247630625589d70150e39614cf91726b3")
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
