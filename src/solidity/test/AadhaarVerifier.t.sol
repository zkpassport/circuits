// SPDX-License-Identifier: Apache-2.0
// Copyright © 2026 ZKPassport

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier} from "../src/ultra-honk-verifiers/OuterAadhaarCount3.sol";

contract AadhaarVerifierTest is Test {
  HonkVerifier verifier;
  bytes proof;
  bytes32[] publicInputs;

  function setUp() public {
    string memory dir = string.concat(vm.projectRoot(), "/test/fixtures/aadhaar/");
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

  function test_VerifiesTheAadhaarOuterProof() public view {
    assertTrue(_verifies(proof, publicInputs));
  }

  function test_RefusesAnotherCertificateRegistryRoot() public view {
    bytes32[] memory changed = publicInputs;
    changed[0] = bytes32(uint256(1));
    assertFalse(_verifies(proof, changed));
  }

  function test_RefusesAnotherVerificationMethod() public view {
    bytes32[] memory changed = publicInputs;
    changed[changed.length - 1] = bytes32(uint256(100));
    assertFalse(_verifies(proof, changed));
  }
}
