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
import {HonkVerifier as OuterAttestedIosCount2} from "../src/ultra-honk-verifiers/OuterAttestedIosCount2.sol";
import {HonkVerifier as OuterAttestedIosCount3} from "../src/ultra-honk-verifiers/OuterAttestedIosCount3.sol";
import {HonkVerifier as OuterAttestedIosCount4} from "../src/ultra-honk-verifiers/OuterAttestedIosCount4.sol";
import {HonkVerifier as OuterAttestedIosCount5} from "../src/ultra-honk-verifiers/OuterAttestedIosCount5.sol";
import {HonkVerifier as OuterAttestedIosCount6} from "../src/ultra-honk-verifiers/OuterAttestedIosCount6.sol";
import {HonkVerifier as OuterAttestedIosCount7} from "../src/ultra-honk-verifiers/OuterAttestedIosCount7.sol";
import {HonkVerifier as OuterAttestedIosCount8} from "../src/ultra-honk-verifiers/OuterAttestedIosCount8.sol";
import {HonkVerifier as OuterAttestedIosCount9} from "../src/ultra-honk-verifiers/OuterAttestedIosCount9.sol";
import {HonkVerifier as OuterAttestedIosCount10} from "../src/ultra-honk-verifiers/OuterAttestedIosCount10.sol";
import {HonkVerifier as OuterAttestedIosCount11} from "../src/ultra-honk-verifiers/OuterAttestedIosCount11.sol";
import {HonkVerifier as OuterAttestedAndroidCount2} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount2.sol";
import {HonkVerifier as OuterAttestedAndroidCount3} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount3.sol";
import {HonkVerifier as OuterAttestedAndroidCount4} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount4.sol";
import {HonkVerifier as OuterAttestedAndroidCount5} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount5.sol";
import {HonkVerifier as OuterAttestedAndroidCount6} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount6.sol";
import {HonkVerifier as OuterAttestedAndroidCount7} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount7.sol";
import {HonkVerifier as OuterAttestedAndroidCount8} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount8.sol";
import {HonkVerifier as OuterAttestedAndroidCount9} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount9.sol";
import {HonkVerifier as OuterAttestedAndroidCount10} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount10.sol";
import {HonkVerifier as OuterAttestedAndroidCount11} from "../src/ultra-honk-verifiers/OuterAttestedAndroidCount11.sol";

contract DeployAnvil is Script {
    uint256 constant FIRST_OUTER = 4;
    uint256 constant NUM_OUTER = 30;
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
        outerVerifiers[10] = address(new OuterAttestedIosCount2());
        outerVerifiers[11] = address(new OuterAttestedIosCount3());
        outerVerifiers[12] = address(new OuterAttestedIosCount4());
        outerVerifiers[13] = address(new OuterAttestedIosCount5());
        outerVerifiers[14] = address(new OuterAttestedIosCount6());
        outerVerifiers[15] = address(new OuterAttestedIosCount7());
        outerVerifiers[16] = address(new OuterAttestedIosCount8());
        outerVerifiers[17] = address(new OuterAttestedIosCount9());
        outerVerifiers[18] = address(new OuterAttestedIosCount10());
        outerVerifiers[19] = address(new OuterAttestedIosCount11());
        outerVerifiers[20] = address(new OuterAttestedAndroidCount2());
        outerVerifiers[21] = address(new OuterAttestedAndroidCount3());
        outerVerifiers[22] = address(new OuterAttestedAndroidCount4());
        outerVerifiers[23] = address(new OuterAttestedAndroidCount5());
        outerVerifiers[24] = address(new OuterAttestedAndroidCount6());
        outerVerifiers[25] = address(new OuterAttestedAndroidCount7());
        outerVerifiers[26] = address(new OuterAttestedAndroidCount8());
        outerVerifiers[27] = address(new OuterAttestedAndroidCount9());
        outerVerifiers[28] = address(new OuterAttestedAndroidCount10());
        outerVerifiers[29] = address(new OuterAttestedAndroidCount11());

        ProofVerifier[] memory proofVerifiers = new ProofVerifier[](NUM_OUTER);
        for (uint256 i = 0; i < NUM_OUTER; i++) {
            string memory path = string.concat(PACKAGED_DIR, _outerEvmName(i), ".json");
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
            console.log(" ", _outerEvmName(i), outerVerifiers[i]);
        }
    }

    // The packaged EVM outer circuit verified by outerVerifiers[i]: 10 chip ones, then 10 Tier 2
    // ones for iOS and 10 for Android
    function _outerEvmName(uint256 i) internal pure returns (string memory) {
        if (i < 10) return string.concat("outer_evm_count_", vm.toString(FIRST_OUTER + i));
        string memory platform = i < 20 ? "ios" : "android";
        return string.concat("outer_evm_attested_", platform, "_count_", vm.toString(2 + (i - 10) % 10));
    }
}
