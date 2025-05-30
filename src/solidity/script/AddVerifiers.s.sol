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

  function run() public {
    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

    // Load the ZKPassportVerifier from deployment file (deployment-{chainId}.json)
    string memory deploymentsDir = "./deployments";
    string memory chainId = vm.toString(block.chainid);
    string memory deploymentPath = string.concat(deploymentsDir, "/deployment-", chainId, ".json");
    string memory deploymentJson = vm.readFile(deploymentPath);
    string memory zkPassportVerifierAddress = deploymentJson.readAddress("zk_passport_verifier");
    ZKPassportVerifier zkPassportVerifier = ZKPassportVerifier(vm.parseAddress(zkPassportVerifierAddress));
    console.log("ZKPassportVerifier loaded at:", address(zkPassportVerifier));

        // Log the deployment
    console.log("Deploying Outer (4 subproofs) verifier...");
    // Deploy the contract
    OuterCount4Verifier outerCount4Verifier = new OuterCount4Verifier();
    console.log("Outer (4 subproofs) verifier deployed at:", address(outerCount4Verifier));

    console.log("Deploying Outer (5 subproofs) verifier...");
    OuterCount5Verifier outerCount5Verifier = new OuterCount5Verifier();
    console.log("Outer (5 subproofs) verifier deployed at:", address(outerCount5Verifier));

    console.log("Deploying Outer (6 subproofs) verifier...");
    OuterCount6Verifier outerCount6Verifier = new OuterCount6Verifier();
    console.log("Outer (6 subproofs) verifier deployed at:", address(outerCount6Verifier));

    console.log("Deploying Outer (7 subproofs) verifier...");
    OuterCount7Verifier outerCount7Verifier = new OuterCount7Verifier();
    console.log("Outer (7 subproofs) verifier deployed at:", address(outerCount7Verifier));

    console.log("Deploying Outer (8 subproofs) verifier...");
    OuterCount8Verifier outerCount8Verifier = new OuterCount8Verifier();
    console.log("Outer (8 subproofs) verifier deployed at:", address(outerCount8Verifier));

    console.log("Deploying Outer (9 subproofs) verifier...");
    OuterCount9Verifier outerCount9Verifier = new OuterCount9Verifier();
    console.log("Outer (9 subproofs) verifier deployed at:", address(outerCount9Verifier));

    console.log("Deploying Outer (10 subproofs) verifier...");
    OuterCount10Verifier outerCount10Verifier = new OuterCount10Verifier();
    console.log("Outer (10 subproofs) verifier deployed at:", address(outerCount10Verifier));

    console.log("Deploying Outer (11 subproofs) verifier...");
    OuterCount11Verifier outerCount11Verifier = new OuterCount11Verifier();
    console.log("Outer (11 subproofs) verifier deployed at:", address(outerCount11Verifier));

    console.log("Deploying Outer (12 subproofs) verifier...");
    OuterCount12Verifier outerCount12Verifier = new OuterCount12Verifier();
    console.log("Outer (12 subproofs) verifier deployed at:", address(outerCount12Verifier));

    console.log("Deploying ZKPassportVerifier...");
    address rootRegistry = vm.envAddress("ROOT_REGISTRY_ADDRESS");
    ZKPassportVerifier zkPassportVerifier = new ZKPassportVerifier(rootRegistry);
    console.log("ZKPassportVerifier deployed at:", address(zkPassportVerifier));


    // Add verifiers to ZKPassportVerifier
    address[] memory verifierAddresses = new address[](9);
    verifierAddresses[0] = address(outerCount4Verifier);
    verifierAddresses[1] = address(outerCount5Verifier);
    verifierAddresses[2] = address(outerCount6Verifier);
    verifierAddresses[3] = address(outerCount7Verifier);
    verifierAddresses[4] = address(outerCount8Verifier);
    verifierAddresses[5] = address(outerCount9Verifier);
    verifierAddresses[6] = address(outerCount10Verifier);
    verifierAddresses[7] = address(outerCount11Verifier);
    verifierAddresses[8] = address(outerCount12Verifier);
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
    string memory outputPath = string.concat(deploymentsDir, "/verifiers-c:", chainId, "-t:", vm.toString(block.timestamp), ".json");
    vm.writeJson(finalJson, outputPath);
    console.log("Verifier addresses written to:", outputPath);
  }
}
