// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {HonkVerifier as OuterCount4Verifier} from "../src/ultra-honk-verifiers/OuterCount4.sol";
import {HonkVerifier as OuterCount5Verifier} from "../src/ultra-honk-verifiers/OuterCount5.sol";
import {HonkVerifier as OuterCount6Verifier} from "../src/ultra-honk-verifiers/OuterCount6.sol";
import {HonkVerifier as OuterCount7Verifier} from "../src/ultra-honk-verifiers/OuterCount7.sol";
import {HonkVerifier as OuterCount8Verifier} from "../src/ultra-honk-verifiers/OuterCount8.sol";
import {HonkVerifier as OuterCount9Verifier} from "../src/ultra-honk-verifiers/OuterCount9.sol";
import {HonkVerifier as OuterCount10Verifier} from "../src/ultra-honk-verifiers/OuterCount10.sol";
import {HonkVerifier as OuterCount11Verifier} from "../src/ultra-honk-verifiers/OuterCount11.sol";
import {HonkVerifier as OuterCount12Verifier} from "../src/ultra-honk-verifiers/OuterCount12.sol";
import {HonkVerifier as OuterCount13Verifier} from "../src/ultra-honk-verifiers/OuterCount13.sol";

contract Deploy is Script {
  using stdJson for string;

  bytes32[] public vkeyHashes = [
    // Outer (4 subproofs)
    bytes32(hex"0770a0542e389605af3e92d1c4838f9d33a430a68e7deecfbf0a523070a4145d"),
    // Outer (5 subproofs)
    bytes32(hex"1d33714b15cd8265d05f157883a92d9b420b965173299bac9a4cba51190b1322"),
    // Outer (6 subproofs)
    bytes32(hex"1bb78391bacf4c9daf784e55431caa31ea87bcd5ba92da57abcbcc40c4367967"),
    // Outer (7 subproofs)
    bytes32(hex"296d18dcc28e0ca6da82ffdb06c8844bbe27647e9eee8e802bc2004830a85716"),
    // Outer (8 subproofs)
    bytes32(hex"174c0f083d56e7adc34e7092ec1b91b058b164488069a67423af125740cd3970"),
    // Outer (9 subproofs)
    bytes32(hex"0316b62b169a4d4ef245d119251485fd507cce2834b5bd2d0bb32b25c5dd5572"),
    // Outer (10 subproofs)
    bytes32(hex"0167c195c083ed30cd5fe7873f5ba8f9ebb3f06e08260410e0af47b61a5dd1a5"),
    // Outer (11 subproofs)
    bytes32(hex"28a3e66a6907a03985e4b24f3abcfa358867404d12b058f0b27d880a51f10859"),
    // Outer (12 subproofs)
    bytes32(hex"1c81f163dd55398fd48bca2d6497ff50b3246ef29ac0009ab431e0ad8242a105"),
    // Outer (13 subproofs)
    bytes32(hex"0af493a9673656b75721ac93f242ebad0efde03aab2ae16b25be929c00e21b50")
  ];

  address[] public verifierAddresses = new address[](10);

  function run() public {
    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

    // Load the ZKPassportVerifier from deployment file (deployment-{chainId}.json)
    string memory deploymentJson = vm.readFile(
      string.concat("./deployments/deployment-", vm.toString(block.chainid), ".json")
    );
    address zkPassportVerifierAddress = deploymentJson.readAddress(".zk_passport_verifier");
    ZKPassportVerifier zkPassportVerifier = ZKPassportVerifier(zkPassportVerifierAddress);
    console.log("ZKPassportVerifier loaded at:", zkPassportVerifierAddress);

    // Log the deployment
    console.log("Deploying Outer (4 subproofs) verifier...");
    // Deploy the contract
    verifierAddresses[0] = address(new OuterCount4Verifier());
    console.log("Outer (4 subproofs) verifier deployed at:", verifierAddresses[0]);

    console.log("Deploying Outer (5 subproofs) verifier...");
    verifierAddresses[1] = address(new OuterCount5Verifier());
    console.log("Outer (5 subproofs) verifier deployed at:", verifierAddresses[1]);

    console.log("Deploying Outer (6 subproofs) verifier...");
    verifierAddresses[2] = address(new OuterCount6Verifier());
    console.log("Outer (6 subproofs) verifier deployed at:", verifierAddresses[2]);

    console.log("Deploying Outer (7 subproofs) verifier...");
    verifierAddresses[3] = address(new OuterCount7Verifier());
    console.log("Outer (7 subproofs) verifier deployed at:", verifierAddresses[3]);

    console.log("Deploying Outer (8 subproofs) verifier...");
    verifierAddresses[4] = address(new OuterCount8Verifier());
    console.log("Outer (8 subproofs) verifier deployed at:", verifierAddresses[4]);

    console.log("Deploying Outer (9 subproofs) verifier...");
    verifierAddresses[5] = address(new OuterCount9Verifier());
    console.log("Outer (9 subproofs) verifier deployed at:", verifierAddresses[5]);

    console.log("Deploying Outer (10 subproofs) verifier...");
    verifierAddresses[6] = address(new OuterCount10Verifier());
    console.log("Outer (10 subproofs) verifier deployed at:", verifierAddresses[6]);

    console.log("Deploying Outer (11 subproofs) verifier...");
    verifierAddresses[7] = address(new OuterCount11Verifier());
    console.log("Outer (11 subproofs) verifier deployed at:", verifierAddresses[7]);

    console.log("Deploying Outer (12 subproofs) verifier...");
    verifierAddresses[8] = address(new OuterCount12Verifier());
    console.log("Outer (12 subproofs) verifier deployed at:", verifierAddresses[8]);

    console.log("Deploying Outer (13 subproofs) verifier...");
    verifierAddresses[9] = address(new OuterCount13Verifier());
    console.log("Outer (13 subproofs) verifier deployed at:", verifierAddresses[9]);

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

    // Write the JSON to a file in the deployments folder
    string memory outputPath = string.concat(
      "./deployments/verifiers-c:",
      vm.toString(block.chainid),
      "-t:",
      vm.toString(block.timestamp),
      ".json"
    );
    vm.writeJson(finalJson, outputPath);
    console.log("Verifier addresses written to:", outputPath);
  }
}
