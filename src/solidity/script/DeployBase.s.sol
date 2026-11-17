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
import {ProofVerifier} from "@zkpassport/registry-contracts/lib/Types.sol";

abstract contract DeployBase is Script {
  string internal constant DEPLOYMENTS_DIR = "./deployments";
  /// The circuits verified on chain, written by src/ts/scripts/circuit-packager.ts
  string internal constant EVM_VERIFIERS_PATH = "./evm-verifiers.json";

  /// An entry of evm-verifiers.json. The fields are in alphabetical order, the order parseJson
  /// decodes a JSON object's keys in.
  struct EvmVerifier {
    string circuit;
    string contractFile;
    bytes32 vkeyHash;
  }

  function _readEvmVerifiers() internal view returns (EvmVerifier[] memory verifiers) {
    verifiers = abi.decode(vm.parseJson(vm.readFile(EVM_VERIFIERS_PATH)), (EvmVerifier[]));
    require(verifiers.length > 0, "evm-verifiers.json lists no verifiers: package the circuits");
  }

  /// Deploys the HonkVerifier of each of evm-verifiers.json's circuits, paired with its vkey hash
  function _deployProofVerifiers(EvmVerifier[] memory verifiers)
    internal
    returns (ProofVerifier[] memory proofVerifiers)
  {
    proofVerifiers = new ProofVerifier[](verifiers.length);
    for (uint256 i = 0; i < verifiers.length; i++) {
      address verifier = deployCode(string.concat(verifiers[i].contractFile, ":HonkVerifier"));
      proofVerifiers[i] = ProofVerifier({vkeyHash: verifiers[i].vkeyHash, verifier: verifier});
      console.log(" ", verifiers[i].circuit, verifier);
    }
  }

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
