// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {HonkVerifier as OuterCount4Verifier} from "../src/OuterCount4.sol";
import {HonkVerifier as OuterCount5Verifier} from "../src/OuterCount5.sol";
import {HonkVerifier as OuterCount6Verifier} from "../src/OuterCount6.sol";
import {HonkVerifier as OuterCount7Verifier} from "../src/OuterCount7.sol";
import {HonkVerifier as OuterCount8Verifier} from "../src/OuterCount8.sol";
import {HonkVerifier as OuterCount9Verifier} from "../src/OuterCount9.sol";
import {HonkVerifier as OuterCount10Verifier} from "../src/OuterCount10.sol";
import {HonkVerifier as OuterCount11Verifier} from "../src/OuterCount11.sol";
import {HonkVerifier as OuterCount12Verifier} from "../src/OuterCount12.sol";

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

  function run() public {
    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

    // Load the ZKPassportVerifier from deployment file (deployment-{chainId}.json)
    string memory deploymentJson = vm.readFile(string.concat("./deployments/deployment-", vm.toString(block.chainid), ".json"));
    address zkPassportVerifierAddress = deploymentJson.readAddress(".zk_passport_verifier");
    ZKPassportVerifier zkPassportVerifier = ZKPassportVerifier(zkPassportVerifierAddress);
    console.log("ZKPassportVerifier loaded at:", zkPassportVerifierAddress);

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

    // Write the JSON to a file in the deployments folder
    string memory outputPath = string.concat("./deployments/verifiers-c:", vm.toString(block.chainid), "-t:", vm.toString(block.timestamp), ".json");
    vm.writeJson(finalJson, outputPath);
    console.log("Verifier addresses written to:", outputPath);
  }
}
