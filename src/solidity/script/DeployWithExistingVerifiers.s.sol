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
    bytes32(hex"2e6da383a7dab68f8dc3ba0c513ccc1f19779aa71c92bfc1dce15ec0b20a7716"),
    // Outer (5 subproofs)
    bytes32(hex"2ed0fa607a5cb8b3db61d0048c56d6f6ec0e892256b7b256b3ce363dd424223f"),
    // Outer (6 subproofs)
    bytes32(hex"012d8fa0197ceaa3da87ce457c565a5f261a54d6431b1a5affd0c298cfc5c9f6"),
    // Outer (7 subproofs)
    bytes32(hex"2d88ba2b93d3a51b231b5b0877beca075cd6286f6b6b15e8d37f75470499cbe5"),
    // Outer (8 subproofs)
    bytes32(hex"1620eb4f56b9fd8cccb0be5cf4ac834d4b251cabbd10d1d389a8645bc7502d77"),
    // Outer (9 subproofs)
    bytes32(hex"14810e1946e009bc75f60e347e5a40604856c982011e46b0088b72b56b4a9149"),
    // Outer (10 subproofs)
    bytes32(hex"0e4833870afbb3afe3f28c3563bbd5b8210c2c20eb80f7136aa17915271dd1fe"),
    // Outer (11 subproofs)
    bytes32(hex"286ae41f148dee27ba62a06296bd70c3c3bab5923a2a08a66f084c55dd7c9b59"),
    // Outer (12 subproofs)
    bytes32(hex"0f53549df70511d217455f59a1f60fc0296bd9487c9e75205f6fc1392300c79c"),
    // Outer (13 subproofs)
    bytes32(hex"03a7b2bada38f383f73d8ded68a7da77c0ca764a69f983e8702245834dd22207")
  ];

  address[] public verifierAddresses = [
    address(0x64E9bD7f679F8071D16998E08B58a063c73f44C8),
    address(0x4e57c1449073a4a95f7621403ec1C69D52CF9D5F),
    address(0x76097BEAd68a53EF0eA57306D66036D31be4b507),
    address(0x1c92d21Fed596d5d996C933C46fd20Ceb8e3b041),
    address(0xdDE3967db4b6781aDE41cf7c063a754CEfa1b57A),
    address(0xceF07773eE255d8555515F44afB8815A9f874e8A),
    address(0x99b76B1Bb194d5a42cB64082974a8a7874FF3457),
    address(0x3df13524C347a009c336Ec939dE088C9c15CC07B),
    address(0x00a27Ed99788c6c6D0bDbF839A08f37a81535297),
    address(0x342b62Eb25db2bEa154B6DF56e1C015af3a9e137)
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
