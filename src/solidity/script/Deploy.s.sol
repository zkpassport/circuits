// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier as OuterCount4Verifier} from "../src/OuterCount4.sol";
import {HonkVerifier as OuterCount5Verifier} from "../src/OuterCount5.sol";
import {HonkVerifier as OuterCount6Verifier} from "../src/OuterCount6.sol";
import {HonkVerifier as OuterCount7Verifier} from "../src/OuterCount7.sol";
import {HonkVerifier as OuterCount8Verifier} from "../src/OuterCount8.sol";
import {HonkVerifier as OuterCount9Verifier} from "../src/OuterCount9.sol";
import {HonkVerifier as OuterCount10Verifier} from "../src/OuterCount10.sol";
import {HonkVerifier as OuterCount11Verifier} from "../src/OuterCount11.sol";
import {HonkVerifier as OuterCount12Verifier} from "../src/OuterCount12.sol";
import {HonkVerifier as OuterCount13Verifier} from "../src/OuterCount13.sol";
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {stdJson} from "forge-std/StdJson.sol";

contract Deploy is Script {
  using stdJson for string;

  bytes32[] public vkeyHashes = [
    // Outer (4 subproofs)
    bytes32(hex"13b02e22ebd1599ef37e8ba16c504b375fd06ae65c19c51109adac2d75519a30"),
    // Outer (5 subproofs)
    bytes32(hex"0ebd82e03a810dc40a9b92ddaf4c4a879389164c2ae3a742013bffc0f676f9b4"),
    // Outer (6 subproofs)
    bytes32(hex"1746693d7f42609b8892b08cbb99ace6ffe81446003adb0256278e775b2dc63b"),
    // Outer (7 subproofs)
    bytes32(hex"099167b4c74af51660ddb39418c793817a8cc7ed596d5796bd9fa2faf7ec6c43"),
    // Outer (8 subproofs)
    bytes32(hex"184b56f705be652c433eae833746bd36dca743cccf131eae7f782169e391065d"),
    // Outer (9 subproofs)
    bytes32(hex"128b774ebb19aad0631ebdd9f2a33a6e1f69c31ce36b260526f0c77c4ed355e8"),
    // Outer (10 subproofs)
    bytes32(hex"04ba57621c89fe3ff86ac6b728dbce2c077388825003a282133d931c9edb41a3"),
    // Outer (11 subproofs)
    bytes32(hex"0c35e44eca4e970fae8fa15a7729da53f05a61eed520d5a3977fb936d0026050"),
    // Outer (12 subproofs)
    bytes32(hex"0177e4167ac0c7994cfdcba40c98567bc6666ae56e0ae4c39c32f051d4c0aabb"),
    // Outer (13 subproofs)
    bytes32(hex"0c3fe7b41c2cb501bf9ead31d08ff446613f439b1b2169bbdeee56501d9abd3a")
  ];

  address[] public verifierAddresses = new address[](10);

  function run() public {
    // Load the private key from environment variable
    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

    // Start broadcasting transactions
    vm.startBroadcast(deployerPrivateKey);

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
    console.log("Don't forget to update the addresses in DeployWithExistingVerifiers.s.sol");
  }
}
