pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";
import {RootVerifier} from "@zkpassport/registry-contracts/RootVerifier.sol";
import {RootRegistry} from "@zkpassport/registry-contracts/RootRegistry.sol";
import {SubVerifier} from "@zkpassport/registry-contracts/SubVerifier.sol";
import {VerifierHelper} from "@zkpassport/registry-contracts/VerifierHelper.sol";
import {ProofVerifier} from "@zkpassport/registry-contracts/lib/Types.sol";
import {MockRootRegistry} from "../test/MockRootRegistry.sol";
import {HonkVerifier as OuterCount4} from "../src/ultra-honk-verifiers/OuterCount4.sol";
import {HonkVerifier as OuterCount5} from "../src/ultra-honk-verifiers/OuterCount5.sol";
import {HonkVerifier as OuterCount6} from "../src/ultra-honk-verifiers/OuterCount6.sol";
import {HonkVerifier as OuterCount7} from "../src/ultra-honk-verifiers/OuterCount7.sol";
import {HonkVerifier as OuterCount8} from "../src/ultra-honk-verifiers/OuterCount8.sol";
import {HonkVerifier as OuterCount9} from "../src/ultra-honk-verifiers/OuterCount9.sol";
import {HonkVerifier as OuterCount10} from "../src/ultra-honk-verifiers/OuterCount10.sol";
import {HonkVerifier as OuterCount11} from "../src/ultra-honk-verifiers/OuterCount11.sol";
import {HonkVerifier as OuterCount12} from "../src/ultra-honk-verifiers/OuterCount12.sol";
import {HonkVerifier as OuterCount13} from "../src/ultra-honk-verifiers/OuterCount13.sol";

contract DeployAnvil is Script {
    uint256 constant FIRST_OUTER = 4;
    uint256 constant NUM_OUTER = 10;
    string constant PACKAGED_DIR = "../../target/packaged/circuits/";

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

        // 3. Outer circuits
        address[NUM_OUTER] memory outerVerifiers;
        outerVerifiers[0] = address(new OuterCount4());
        outerVerifiers[1] = address(new OuterCount5());
        outerVerifiers[2] = address(new OuterCount6());
        outerVerifiers[3] = address(new OuterCount7());
        outerVerifiers[4] = address(new OuterCount8());
        outerVerifiers[5] = address(new OuterCount9());
        outerVerifiers[6] = address(new OuterCount10());
        outerVerifiers[7] = address(new OuterCount11());
        outerVerifiers[8] = address(new OuterCount12());
        outerVerifiers[9] = address(new OuterCount13());

        ProofVerifier[] memory proofVerifiers = new ProofVerifier[](NUM_OUTER);
        for (uint256 i = 0; i < NUM_OUTER; i++) {
            uint256 count = 4 + i;
            string memory path = string.concat(PACKAGED_DIR, "outer_evm_count_", vm.toString(count), ".json");
            bytes32 vkeyHash = vm.parseJsonBytes32(vm.readFile(path), ".vkey_hash");
            proofVerifiers[i] = ProofVerifier({vkeyHash: vkeyHash, verifier: outerVerifiers[i]});
        }
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
        for (uint256 i = 0; i < NUM_OUTER; i++) {
            console.log("  outer_count_", FIRST_OUTER + i, outerVerifiers[i]);
        }
    }
}
