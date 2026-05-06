// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport

/*
 * DeployVerifierHelper.s.sol
 *
 * Validates required env vars, deploys a VerifierHelper (canonical contract imported from
 * the registry-contracts package), and writes the deployed address into the shared
 * deployments JSON. Does NOT register the helper with the RootVerifier — that registration
 * is performed by the RootVerifier admin (a Safe multisig) outside this script.
 *
 * VerifierHelper has no admin state (no setters, no ownable surface), so there is no
 * admin transfer step. It only reads from RootRegistry at verification time.
 *
 * Required env vars:
 *   PRIVATE_KEY            - deployer key
 *   ROOT_REGISTRY_ADDRESS  - the RootRegistry the helper will read from
 *
 * Optional env vars:
 *   SUB_VERIFIER_VERSION   - bytes32 semver key. Recorded in the addresses JSON only.
 *                             Defaults to bytes32(0) (rendered as "unversioned").
 */

pragma solidity ^0.8.30;

import {console} from "forge-std/Script.sol";
import {DeployBase} from "./DeployBase.s.sol";
import {RootRegistry} from "@zkpassport/registry-contracts/RootRegistry.sol";
import {VerifierHelper} from "@zkpassport/registry-contracts/VerifierHelper.sol";

contract DeployVerifierHelper is DeployBase {
  bytes32 public SUB_VERIFIER_VERSION;

  function setUp() public {}

  function run() public {
    // Validate env
    SUB_VERIFIER_VERSION = vm.envOr("SUB_VERIFIER_VERSION", bytes32(0));
    RootRegistry rootRegistry = RootRegistry(vm.envAddress("ROOT_REGISTRY_ADDRESS"));
    require(address(rootRegistry) != address(0), "ROOT_REGISTRY_ADDRESS must be set");

    uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
    vm.startBroadcast(deployerPrivateKey);

    console.log("Deploying VerifierHelper...");
    VerifierHelper helper = new VerifierHelper(rootRegistry);
    console.log("VerifierHelper deployed at:", address(helper));

    vm.stopBroadcast();

    _writeAddresses(rootRegistry, helper);

    console.log("");
    console.log("Next: RootVerifier admin (multisig) calls addHelper(version, %s)", address(helper));
  }

  function _writeAddresses(RootRegistry rootRegistry, VerifierHelper helper) internal {
    string memory versionStr = _versionString(SUB_VERIFIER_VERSION);

    string memory versionJson = "helper_version";
    vm.serializeAddress(versionJson, "address", address(helper));
    vm.serializeAddress(versionJson, "root_registry", address(rootRegistry));
    versionJson = vm.serializeUint(versionJson, "deployed_at", block.timestamp);

    string memory section = "verifier_helper_versions";
    section = vm.serializeString(section, versionStr, versionJson);

    _writeToAddresses("verifier_helper_versions", section);
  }

  function _versionString(bytes32 version) internal pure returns (string memory) {
    if (version == bytes32(0)) return "unversioned";
    uint256 v = uint256(version);
    return string.concat(
      vm.toString(uint16(v >> 240)), ".", vm.toString(uint16(v >> 224)), ".", vm.toString(uint16(v >> 208))
    );
  }
}
