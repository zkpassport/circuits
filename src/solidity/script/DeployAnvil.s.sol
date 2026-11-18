pragma solidity ^0.8.30;

import {console} from "forge-std/Script.sol";
import {DeployBase} from "./DeployBase.s.sol";
import {RootVerifier} from "@zkpassport/registry-contracts/RootVerifier.sol";
import {RootRegistry} from "@zkpassport/registry-contracts/RootRegistry.sol";
import {SubVerifier} from "@zkpassport/registry-contracts/SubVerifier.sol";
import {VerifierHelper} from "@zkpassport/registry-contracts/VerifierHelper.sol";
import {ProofVerifier} from "@zkpassport/registry-contracts/lib/Types.sol";
import {MockRootRegistry} from "../test/MockRootRegistry.sol";

contract DeployAnvil is DeployBase {
    function run() external {
        bytes32 globalOprfPkHash = vm.envBytes32("GLOBAL_OPRF_PK_HASH");
        bytes32 circuitVersion = vm.envBytes32("CIRCUIT_VERSION");

        vm.startBroadcast();

        address admin = msg.sender;
        address guardian = msg.sender;

        // 1. Root registry - using the mock one that always passes.
        MockRootRegistry mockRegistry = new MockRootRegistry();

        // 2. Root verifier and sub verifier.
        RootVerifier rootVerifier = new RootVerifier(admin, guardian, RootRegistry(address(mockRegistry)));
        SubVerifier subVerifier = new SubVerifier(admin, rootVerifier, globalOprfPkHash);
        VerifierHelper verifierHelper = new VerifierHelper(RootRegistry(address(mockRegistry)));

        // 3. The proof verifiers of the circuits in evm-verifiers.json
        console.log("Proof verifiers:");
        ProofVerifier[] memory proofVerifiers = _deployProofVerifiers(_readEvmVerifiers());
        subVerifier.addProofVerifiers(proofVerifiers);

        // 5. Register the SubVerifier + helper under the circuit version.
        rootVerifier.addSubVerifier(circuitVersion, subVerifier);
        rootVerifier.addHelper(circuitVersion, address(verifierHelper));

        vm.stopBroadcast();

        console.log("=== Anvil deployment complete ===");
        console.log("MockRootRegistry:       ", address(mockRegistry));
        console.log("RootVerifier:           ", address(rootVerifier));
        console.log("SubVerifier:            ", address(subVerifier));
        console.log("VerifierHelper:         ", address(verifierHelper));
        console.log("admin/guardian:         ", admin);
        console.log("circuitVersion:");
        console.logBytes32(circuitVersion);
        console.log("globalOPRFPubKeyHash:");
        console.logBytes32(globalOprfPkHash);
    }
}
