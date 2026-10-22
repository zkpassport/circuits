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
 *   CHAIN_ID               - chain the RPC must be on; the script reverts on a mismatch
 *   ROOT_REGISTRY_ADDRESS  - the RootRegistry the helper will read from
 *   SUB_VERIFIER_VERSION   - non-zero bytes32 semver key. Recorded in the addresses JSON only.
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
    _requireChainId();
    SUB_VERIFIER_VERSION = vm.envBytes32("SUB_VERIFIER_VERSION");
    require(SUB_VERIFIER_VERSION != bytes32(0), "SUB_VERIFIER_VERSION must be set");
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
    string memory section = "verifier_helper_versions";
    string memory versionStr = _versionString(SUB_VERIFIER_VERSION);
    string memory sectionJson;

    // Writing the section replaces it whole, so carry over every other version it records
    string memory addresses = _readAddresses();
    string[] memory recordedVersions = _recordedVersions(addresses, section);
    for (uint256 i = 0; i < recordedVersions.length; i++) {
      if (keccak256(bytes(recordedVersions[i])) == keccak256(bytes(versionStr))) {
        continue;
      }
      string memory entryPath = _versionEntryPath(section, recordedVersions[i]);
      _requireFieldCount(addresses, entryPath, 3);
      string memory recordedJson = _serializeHelperEntry(
        recordedVersions[i],
        vm.parseJsonAddress(addresses, string.concat(entryPath, ".address")),
        vm.parseJsonAddress(addresses, string.concat(entryPath, ".root_registry")),
        vm.parseJsonUint(addresses, string.concat(entryPath, ".deployed_at"))
      );
      sectionJson = vm.serializeString(section, recordedVersions[i], recordedJson);
    }

    string memory deployedJson =
      _serializeHelperEntry(versionStr, address(helper), address(rootRegistry), block.timestamp);
    sectionJson = vm.serializeString(section, versionStr, deployedJson);

    _writeToAddresses(section, sectionJson);
  }

  /// One verifier_helper_versions entry: { address, root_registry, deployed_at }.
  function _serializeHelperEntry(string memory version, address helper, address rootRegistry, uint256 deployedAt)
    internal
    returns (string memory)
  {
    string memory entryKey = string.concat("helper_", version);
    vm.serializeAddress(entryKey, "address", helper);
    vm.serializeAddress(entryKey, "root_registry", rootRegistry);
    return vm.serializeUint(entryKey, "deployed_at", deployedAt);
  }

  function _versionString(bytes32 version) internal pure returns (string memory) {
    if (version == bytes32(0)) return "unversioned";
    uint256 v = uint256(version);
    return string.concat(
      vm.toString(uint16(v >> 240)), ".", vm.toString(uint16(v >> 224)), ".", vm.toString(uint16(v >> 208))
    );
  }
}
