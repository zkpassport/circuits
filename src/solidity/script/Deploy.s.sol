// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport

/*
 * Deploy.s.sol
 *
 * Deploys the ZKPassport root verifier, subverifier, helper, and proof verifiers
 * for outer circuits (supporting 4-13 subproofs).
 */

pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
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
import {IRootRegistry} from "../src/IRootRegistry.sol";
import {ZKPassportRootVerifier} from "../src/ZKPassportRootVerifier.sol";
import {ZKPassportSubVerifier as ZKPassportSubVerifierV1} from "../src/ZKPassportSubVerifier.sol";
import {ZKPassportHelper as ZKPassportHelperV1} from "../src/ZKPassportHelper.sol";
import {ProofVerifier} from "../src/Types.sol";

contract Deploy is Script {
  using stdJson for string;

  bytes32 public SUB_VERIFIER_VERSION;

  bytes32[] public vkeyHashes = [
    // Outer (4 subproofs)
    bytes32(hex"0a3390816e5af7359b589b74a49a0210ca7f8024c497af8eca6081e4cbc1505c"),
    // Outer (5 subproofs)
    bytes32(hex"287292eb9eace872ef64278a828b54d51b79e1ddd159e6582bf8826d1cc860ba"),
    // Outer (6 subproofs)
    bytes32(hex"156252c4c996e9fb3e77f4787dae33e73f9d5c6f06b57c12e87ebdaf35c9edab"),
    // Outer (7 subproofs)
    bytes32(hex"252dbc42921b3236ad115da32541c953bd20a09043e575df2e9ed274448bb093"),
    // Outer (8 subproofs)
    bytes32(hex"257869d29c689652f48f8957a22c398490410858eb881967a9b8caab7b86b8bb"),
    // Outer (9 subproofs)
    bytes32(hex"0fb22360a2d0c81a4ebf0a55c474df97c053ae406980dcf0047c7c451d893401"),
    // Outer (10 subproofs)
    bytes32(hex"2efa10b806e2e7edba75c35cd2659dc2d74e8f0f040876eb014ae6f5056e3dc0"),
    // Outer (11 subproofs)
    bytes32(hex"03cb373a16d51d7b462e9a21f6d2f34fc1009da12f0cfd6f1041e0afffcf8acc"),
    // Outer (12 subproofs)
    bytes32(hex"2b5579a92c9a4b48a8c60ed14395bf1d2f965ebd469c096a182fa8fe8285d0bd"),
    // Outer (13 subproofs)
    bytes32(hex"1e3076a5fc04a825e4a817320106b943e848c2d04f703091d0e0fee3df900ef5")
  ];
  address[] public proofVerifiers = new address[](10);

  function run() public {
    SUB_VERIFIER_VERSION = vm.envOr("SUB_VERIFIER_VERSION", bytes32(uint256(1)));

    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

    // Deploy the root verifier
    console.log("Deploying ZKPassportRootVerifier...");
    address admin = vm.envAddress("ROOT_VERIFIER_ADMIN_ADDRESS");
    address guardian = vm.envAddress("ROOT_VERIFIER_GUARDIAN_ADDRESS");
    IRootRegistry rootRegistry = IRootRegistry(vm.envAddress("ROOT_REGISTRY_ADDRESS"));
    ZKPassportRootVerifier rootVerifier = new ZKPassportRootVerifier(admin, guardian, rootRegistry);
    console.log("ZKPassportRootVerifier deployed at:", address(rootVerifier));

    // Deploy the sub verifier
    console.log("Deploying ZKPassportSubVerifierV1...");
    ZKPassportSubVerifierV1 subVerifier = new ZKPassportSubVerifierV1(admin, rootVerifier);
    console.log("ZKPassportSubVerifierV1 deployed at:", address(subVerifier));

    // Add the sub verifier to the root verifier
    console.log("Adding sub verifier to root verifier...");
    rootVerifier.addSubVerifier(SUB_VERIFIER_VERSION, subVerifier);
    console.log("Sub verifier added to root verifier");

    // Deploy the helper
    console.log("Deploying ZKPassportHelperV1...");
    ZKPassportHelperV1 helper = new ZKPassportHelperV1(rootRegistry);
    console.log("ZKPassportHelperV1 deployed at:", address(helper));

    // Add the helper to the root verifier
    console.log("Adding helper to root verifier...");
    rootVerifier.addHelper(SUB_VERIFIER_VERSION, address(helper));
    console.log("Helper added to root verifier");

    // Deploy the proof verifiers
    console.log("Deploying Outer (4 subproofs) proof verifier...");
    proofVerifiers[0] = address(new OuterCount4Verifier());
    console.log("Outer (4 subproofs) proof verifier deployed at:", proofVerifiers[0]);

    console.log("Deploying Outer (5 subproofs) proof verifier...");
    proofVerifiers[1] = address(new OuterCount5Verifier());
    console.log("Outer (5 subproofs) proof verifier deployed at:", proofVerifiers[1]);

    console.log("Deploying Outer (6 subproofs) proof verifier...");
    proofVerifiers[2] = address(new OuterCount6Verifier());
    console.log("Outer (6 subproofs) proof verifier deployed at:", proofVerifiers[2]);

    console.log("Deploying Outer (7 subproofs) proof verifier...");
    proofVerifiers[3] = address(new OuterCount7Verifier());
    console.log("Outer (7 subproofs) proof verifier deployed at:", proofVerifiers[3]);

    console.log("Deploying Outer (8 subproofs) proof verifier...");
    proofVerifiers[4] = address(new OuterCount8Verifier());
    console.log("Outer (8 subproofs) proof verifier deployed at:", proofVerifiers[4]);

    console.log("Deploying Outer (9 subproofs) proof verifier...");
    proofVerifiers[5] = address(new OuterCount9Verifier());
    console.log("Outer (9 subproofs) proof verifier deployed at:", proofVerifiers[5]);

    console.log("Deploying Outer (10 subproofs) proof verifier...");
    proofVerifiers[6] = address(new OuterCount10Verifier());
    console.log("Outer (10 subproofs) proof verifier deployed at:", proofVerifiers[6]);

    console.log("Deploying Outer (11 subproofs) proof verifier...");
    proofVerifiers[7] = address(new OuterCount11Verifier());
    console.log("Outer (11 subproofs) proof verifier deployed at:", proofVerifiers[7]);

    console.log("Deploying Outer (12 subproofs) proof verifier...");
    proofVerifiers[8] = address(new OuterCount12Verifier());
    console.log("Outer (12 subproofs) proof verifier deployed at:", proofVerifiers[8]);

    console.log("Deploying Outer (13 subproofs) proof verifier...");
    proofVerifiers[9] = address(new OuterCount13Verifier());
    console.log("Outer (13 subproofs) proof verifier deployed at:", proofVerifiers[9]);

    // Add proof verifiers to the sub verifier
    console.log("Adding proof verifiers to the sub verifier...");
    ProofVerifier[] memory proofVerifiersArray = new ProofVerifier[](10);
    for (uint256 i = 0; i < 10; i++) {
      proofVerifiersArray[i] = ProofVerifier({vkeyHash: vkeyHashes[i], verifier: proofVerifiers[i]});
    }
    subVerifier.addProofVerifiers(proofVerifiersArray);
    console.log("Proof verifiers added to the sub verifier");

    // Stop broadcasting transactions
    vm.stopBroadcast();

    // Create the main JSON object with deployment details
    string memory mainJson = "main";
    vm.serializeUint(mainJson, "chain_id", block.chainid);
    vm.serializeString(mainJson, "deployment_timestamp", vm.toString(block.timestamp));
    vm.serializeAddress(mainJson, "root_verifier", address(rootVerifier));
    string memory subVerifierVersion = vm.toString(uint256(SUB_VERIFIER_VERSION));
    string memory subVerifierVersionString = string.concat("v", subVerifierVersion);
    vm.serializeAddress(mainJson, string.concat("sub_verifier_", subVerifierVersionString), address(subVerifier));
    vm.serializeAddress(mainJson, string.concat("helper_", subVerifierVersionString), address(helper));
    // Add proof verifiers to JSON artifact
    string memory proofVerifiersJson = "proof_verifiers";
    vm.serializeAddress(proofVerifiersJson, "outer_count_4", proofVerifiers[0]);
    vm.serializeAddress(proofVerifiersJson, "outer_count_5", proofVerifiers[1]);
    vm.serializeAddress(proofVerifiersJson, "outer_count_6", proofVerifiers[2]);
    vm.serializeAddress(proofVerifiersJson, "outer_count_7", proofVerifiers[3]);
    vm.serializeAddress(proofVerifiersJson, "outer_count_8", proofVerifiers[4]);
    vm.serializeAddress(proofVerifiersJson, "outer_count_9", proofVerifiers[5]);
    vm.serializeAddress(proofVerifiersJson, "outer_count_10", proofVerifiers[6]);
    vm.serializeAddress(proofVerifiersJson, "outer_count_11", proofVerifiers[7]);
    vm.serializeAddress(proofVerifiersJson, "outer_count_12", proofVerifiers[8]);
    proofVerifiersJson = vm.serializeAddress(proofVerifiersJson, "outer_count_13", proofVerifiers[9]);
    mainJson = vm.serializeString(mainJson, "proof_verifiers", proofVerifiersJson);
    string memory finalJson = vm.serializeString(mainJson, "main", mainJson);

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
    console.log("Don't forget to update the addresses in DeployWithExistingVerifiers.s.sol");
  }
}
