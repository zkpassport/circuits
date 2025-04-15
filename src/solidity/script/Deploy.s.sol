// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {HonkVerifier} from "../src/OuterCount4.sol";

contract Deploy is Script {
    function run() public returns (HonkVerifier) {
        // Load the private key from environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        // Start broadcasting transactions
        vm.startBroadcast(deployerPrivateKey);
        
        // Log the deployment
        console.log("Deploying Outer (4 subproofs) verifier...");
        
        // Deploy the contract
        HonkVerifier verifier = new HonkVerifier();
        
        // Log the contract address
        console.log("Outer (4 subproofs) verifier deployed at:", address(verifier));
        
        // Stop broadcasting transactions
        vm.stopBroadcast();
        
        return verifier;
    }
} 