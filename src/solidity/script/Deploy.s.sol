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
    bytes32(hex"2cb0301d4fccf542247d2164335a1ac1a94be519757be9a8f76556e95ad4110a"),
    // Outer (5 subproofs)
    bytes32(hex"20a5dfe7875cf4cb9fe6b4e13397434bc7b33ebb42431c09f9d2eb20f0f09a4d"),
    // Outer (6 subproofs)
    bytes32(hex"2fe35634ea36d09761105fc3b6dfb4883411171afddc6c2e146ae350a72b53d6"),
    // Outer (7 subproofs)
    bytes32(hex"2b7ee89fd25220e326fcc9eed4b5876a913cd660cc8e6c4392ea3a1e1d989f61"),
    // Outer (8 subproofs)
    bytes32(hex"17407da3db9149eea7c0a22ae09777c7408da8ad31e7aa7e689a224d84c6fbef"),
    // Outer (9 subproofs)
    bytes32(hex"0b5c94def57b9e2ec5ade654250770319a8cc1b7a3477bea2806b57b6721bf79"),
    // Outer (10 subproofs)
    bytes32(hex"1173f738a63900f154d8c6888f915270189f615ee9022553e16a5d768849ae20"),
    // Outer (11 subproofs)
    bytes32(hex"264d993757611bb8bf4d2f11700e68dfdcb52b1061d6730ebc0586dbd9970055"),
    // Outer (12 subproofs)
    bytes32(hex"1c9b4dbc93bcf1112ad3ffbd02015e088f8acd74e9043f13bd134f9fec9a42fe"),
    // Outer (13 subproofs)
    bytes32(hex"0b3b18a01c22280ed3f359f2ab624a49ac305300ec89e090772f6407e46300ba")
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
