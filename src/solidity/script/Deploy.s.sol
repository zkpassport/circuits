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
import {stdJson} from "forge-std/StdJson.sol";

contract Deploy is Script {
    using stdJson for string;

    function run() public {
        // Load the private key from environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        // Start broadcasting transactions
        vm.startBroadcast(deployerPrivateKey);
        
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
        
        // Stop broadcasting transactions
        vm.stopBroadcast();
        
        // Create JSON for verifiers
        string memory verifiers = "verifiers";
        vm.serializeAddress(verifiers, "outerCount4", address(outerCount4Verifier));
        vm.serializeAddress(verifiers, "outerCount5", address(outerCount5Verifier));
        vm.serializeAddress(verifiers, "outerCount6", address(outerCount6Verifier));
        vm.serializeAddress(verifiers, "outerCount7", address(outerCount7Verifier));
        vm.serializeAddress(verifiers, "outerCount8", address(outerCount8Verifier));
        vm.serializeAddress(verifiers, "outerCount9", address(outerCount9Verifier));
        vm.serializeAddress(verifiers, "outerCount10", address(outerCount10Verifier));
        verifiers = vm.serializeAddress(verifiers, "outerCount11", address(outerCount11Verifier));
        
        // Create the main JSON object
        string memory mainJson = "main";
        
        // Add deployment details to the main JSON
        vm.serializeUint(mainJson, "chainId", block.chainid);
        vm.serializeString(mainJson, "deploymentTimestamp", vm.toString(block.timestamp));
        
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