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
    bytes32(hex"2d05d8c59bcb034d6c0947f71b7cab4f20706f5205467f8641927aa7032035c9"),
    // Outer (5 subproofs)
    bytes32(hex"0d59716a55e35e9dbf1b2169a15281a7d2c806852d899ba6992c4451a62fe5e1"),
    // Outer (6 subproofs)
    bytes32(hex"2e4378a990bcdbb8068a451f336e8d6c37ef50053f6ee6dff567a9ad9d786c08"),
    // Outer (7 subproofs)
    bytes32(hex"30142ef95674be7570d6896ba215f87ae8052724ff3e9f40ed82e42a40a0a4dd"),
    // Outer (8 subproofs)
    bytes32(hex"2745d0c664aa931b664fe261149c89f70331ec7b723b5b102c154e81e976568b"),
    // Outer (9 subproofs)
    bytes32(hex"1b8b6d04a153554d3450bade2b3e2d722060a6658a34f3b0340997d8d5ed92f8"),
    // Outer (10 subproofs)
    bytes32(hex"11019f15da6896d28e7030548bf432a4cf3913f5b9acf6d00ecded72a4708693"),
    // Outer (11 subproofs)
    bytes32(hex"23918a2569d5ec2bc4348dc4778610204fa325ee3113ed86e6bb3537690f41e4"),
    // Outer (12 subproofs)
    bytes32(hex"1a2efda2d85319516ed674ff53e93965b697027d0bef8aa45d0499d576bce119")
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
