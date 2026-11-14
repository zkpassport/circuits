// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/ultra-honk-verifiers/OuterAttestedIdCount2.sol";

/**
 * A Tier 2 (attested ID) outer EVM proof against the packaged OuterAttestedIdCount2 verifier: a
 * proof of outer_attested_id_count_2 over attested_id_ios_evm and disclose_bytes_evm, written to
 * test/fixtures/tier2 by generate-fixtures. The RootVerifier and SubVerifier path is tested with
 * such a proof in zkpassport-packages' registry-contracts (Tier2Verification.t.sol).
 */
contract Tier2VerifierTest is Test {
  HonkVerifier verifier;
  bytes proof;
  bytes32[] publicInputs;

  function setUp() public {
    string memory dir = string.concat(vm.projectRoot(), "/test/fixtures/tier2/");
    proof = vm.parseBytes(string.concat("0x", vm.readFile(string.concat(dir, "proof.hex"))));
    publicInputs = vm.parseJsonBytes32Array(vm.readFile(string.concat(dir, "public_inputs.json")), "");
    verifier = new HonkVerifier();
  }

  function _verifies(bytes memory _proof, bytes32[] memory _publicInputs) internal view returns (bool) {
    try verifier.verify(_proof, _publicInputs) returns (bool valid) {
      return valid;
    } catch {
      return false;
    }
  }

  function test_VerifiesTheTier2OuterProof() public view {
    assertTrue(_verifies(proof, publicInputs));
  }

  function test_RefusesAChangedPublicInput() public view {
    bytes32[] memory changed = publicInputs;
    // The credential scheme, the last public input: 200 (iOS) read as 201 (Android)
    changed[changed.length - 1] = bytes32(uint256(201));
    assertFalse(_verifies(proof, changed));
  }

  function test_RefusesAChangedProof() public view {
    bytes memory changed = bytes.concat(proof);
    changed[100] = changed[100] ^ 0x01;
    assertFalse(_verifies(changed, publicInputs));
  }
}
