// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport

/*
 * DeploySubVerifier.s.sol
 *
 * Deploys the UltraHonk proof verifier of each circuit in evm-verifiers.json, deploys a SubVerifier
 * (canonical contract imported from the registry-contracts package), wires the proof verifiers +
 * their vkey hashes, sets the default OPRF public key hash, and transfers admin to
 * the final ADMIN_ADDRESS. Does NOT register the SubVerifier with the RootVerifier — that
 * registration is performed by the RootVerifier admin (a Safe multisig) outside this script.
 *
 * The broadcaster is the temporary admin during deployment so it can call admin-only setup
 * functions (addProofVerifiers, setGlobalOPRFPubKeyHash). Admin is transferred to
 * ADMIN_ADDRESS at the end of the script.
 *
 * Required env vars:
 *   PRIVATE_KEY              - deployer key (becomes temporary admin)
 *   CHAIN_ID                 - chain the RPC must be on; the script reverts on a mismatch
 *   ROOT_VERIFIER_ADDRESS    - already-deployed RootVerifier this SubVerifier targets
 *   ADMIN_ADDRESS            - final admin (e.g. multisig) for the new SubVerifier
 *   SUB_VERIFIER_VERSION     - non-zero bytes32 semver key. Recorded in the addresses JSON only.
 *   GLOBAL_OPRF_PUB_KEY_HASH - non-zero protocol-default OPRF pubkey hash, passed to the
 *                              SubVerifier constructor. Salted proofs fail while it is zero.
 */

pragma solidity ^0.8.30;

import {console} from "forge-std/Script.sol";
import {DeployBase} from "./DeployBase.s.sol";
import {RootVerifier} from "@zkpassport/registry-contracts/RootVerifier.sol";
import {SubVerifier} from "@zkpassport/registry-contracts/SubVerifier.sol";
import {ProofVerifier} from "@zkpassport/registry-contracts/lib/Types.sol";

contract DeploySubVerifier is DeployBase {
  bytes32 public SUB_VERIFIER_VERSION;

  function setUp() public {}

  function run() public {
    // Validate env
    _requireChainId();
    SUB_VERIFIER_VERSION = vm.envBytes32("SUB_VERIFIER_VERSION");
    require(SUB_VERIFIER_VERSION != bytes32(0), "SUB_VERIFIER_VERSION must be set");
    address adminAddress = vm.envAddress("ADMIN_ADDRESS");
    require(adminAddress != address(0), "ADMIN_ADDRESS must be set");
    RootVerifier rootVerifier = RootVerifier(vm.envAddress("ROOT_VERIFIER_ADDRESS"));
    require(address(rootVerifier) != address(0), "ROOT_VERIFIER_ADDRESS must be set");
    bytes32 globalOPRFPubKeyHash = vm.envBytes32("GLOBAL_OPRF_PUB_KEY_HASH");
    require(globalOPRFPubKeyHash != bytes32(0), "GLOBAL_OPRF_PUB_KEY_HASH must be set");

    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
    address deployer = vm.addr(deployerPrivateKey);
    vm.startBroadcast(deployerPrivateKey);

    // Deploy the proof verifiers of the circuits in evm-verifiers.json.
    console.log("Deploying proof verifiers...");
    EvmVerifier[] memory verifiers = _readEvmVerifiers();
    ProofVerifier[] memory pvArray = _deployProofVerifiers(verifiers);

    // Deploy the SubVerifier with the broadcaster as temporary admin.
    console.log("Deploying SubVerifier...");
    SubVerifier subVerifier = new SubVerifier(deployer, rootVerifier, globalOPRFPubKeyHash);
    console.log("SubVerifier deployed at:", address(subVerifier));

    // Wire proof verifiers (admin-only on SubVerifier).
    subVerifier.addProofVerifiers(pvArray);
    console.log("Proof verifiers added");

    // Hand admin over to the final admin (e.g. multisig).
    subVerifier.transferAdmin(adminAddress);
    console.log("Admin transferred to:", adminAddress);

    vm.stopBroadcast();

    _writeAddresses(rootVerifier, subVerifier, adminAddress, verifiers, pvArray);

    console.log("");
    console.log("Next: RootVerifier admin (multisig) calls addSubVerifier(version, %s)", address(subVerifier));
  }

  function _writeAddresses(
    RootVerifier rootVerifier,
    SubVerifier subVerifier,
    address adminAddress,
    EvmVerifier[] memory verifiers,
    ProofVerifier[] memory pvArray
  ) internal {
    string memory versionStr = _versionString(SUB_VERIFIER_VERSION);

    // proof_verifiers object keyed by circuit
    string memory pvJson;
    for (uint256 i = 0; i < verifiers.length; i++) {
      pvJson = vm.serializeAddress("pv", verifiers[i].circuit, pvArray[i].verifier);
    }

    // version object: { address, admin, root_verifier, proof_verifiers, deployed_at }
    string memory versionJson = "subverifier_version";
    vm.serializeAddress(versionJson, "address", address(subVerifier));
    vm.serializeAddress(versionJson, "admin", adminAddress);
    vm.serializeAddress(versionJson, "root_verifier", address(rootVerifier));
    vm.serializeUint(versionJson, "deployed_at", block.timestamp);
    versionJson = vm.serializeString(versionJson, "proof_verifiers", pvJson);

    // sub_verifier_versions: { "<version>": { ... } }
    string memory section = "sub_verifier_versions";
    section = vm.serializeString(section, versionStr, versionJson);

    _writeToAddresses("sub_verifier_versions", section);
  }

  function _versionString(bytes32 version) internal pure returns (string memory) {
    if (version == bytes32(0)) return "unversioned";
    uint256 v = uint256(version);
    return string.concat(
      vm.toString(uint16(v >> 240)), ".", vm.toString(uint16(v >> 224)), ".", vm.toString(uint16(v >> 208))
    );
  }
}
