// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport

/*
 * DeployBase.s.sol
 *
 * Shared base contract for circuits-side deploy scripts. Provides helpers for writing
 * deployment data into the shared addresses file, mirroring the pattern used by the
 * registry-contracts deploy scripts.
 */

pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

abstract contract DeployBase is Script {
  string internal constant DEPLOYMENTS_DIR = "./deployments";

  function _ensureDeploymentsDir() internal {
    if (!vm.exists(DEPLOYMENTS_DIR)) {
      vm.createDir(DEPLOYMENTS_DIR, true);
    }
  }

  function _chainIdStr() internal view returns (string memory) {
    return vm.toString(block.chainid);
  }

  /// Revert unless the RPC's chain matches the CHAIN_ID env var, so a wrong --rpc-url can't
  /// deploy to an unintended network.
  function _requireChainId() internal view {
    uint256 expectedChainId = vm.envUint("CHAIN_ID");
    require(
      block.chainid == expectedChainId,
      string.concat("CHAIN_ID is ", vm.toString(expectedChainId), " but the RPC is on chain ", _chainIdStr())
    );
  }

  function _addressesFilePath() internal view returns (string memory) {
    return string.concat(DEPLOYMENTS_DIR, "/addresses-", _chainIdStr(), ".json");
  }

  /// Contents of `addresses-<chainId>.json`, or an empty object when the file does not exist yet.
  function _readAddresses() internal view returns (string memory) {
    string memory path = _addressesFilePath();
    if (!vm.exists(path)) {
      return "{}";
    }
    return vm.readFile(path);
  }

  /// Version keys recorded under the top-level `section` of `addresses`, or none when the section is missing.
  function _recordedVersions(string memory addresses, string memory section) internal view returns (string[] memory) {
    string memory sectionPath = string.concat(".", section);
    if (!vm.keyExistsJson(addresses, sectionPath)) {
      return new string[](0);
    }
    return vm.parseJsonKeys(addresses, sectionPath);
  }

  /// JSON path of `version`'s entry in `section`. The version is quoted because a version such as
  /// "0.21.1" contains dots, which an unquoted path would read as nested keys.
  function _versionEntryPath(string memory section, string memory version) internal pure returns (string memory) {
    return string.concat(".", section, "['", version, "']");
  }

  /// Revert unless the object at `path` has exactly `fieldCount` fields, so an entry copied field by
  /// field cannot silently lose one.
  function _requireFieldCount(string memory json, string memory path, uint256 fieldCount) internal pure {
    require(vm.parseJsonKeys(json, path).length == fieldCount, string.concat("Unexpected fields in ", path));
  }

  /// Write a serialized JSON object to a top-level key in `addresses-<chainId>.json`, replacing that
  /// key's whole value.
  function _writeToAddresses(string memory key, string memory json) internal {
    _ensureDeploymentsDir();
    string memory path = _addressesFilePath();
    if (!vm.exists(path)) {
      vm.writeJson("{}", path);
    }
    vm.writeJson(json, path, string.concat(".", key));
    console.log("Updated addresses file:", path);
  }
}
