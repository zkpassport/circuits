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

  /// Write a serialized JSON object to a top-level key in `addresses-<chainId>.json`.
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
