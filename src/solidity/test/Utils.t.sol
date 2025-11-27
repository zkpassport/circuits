// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";
import {StdConstants} from "forge-std/StdConstants.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {ZKPassportRootVerifier} from "../src/ZKPassportRootVerifier.sol";
import {ZKPassportSubVerifier} from "../src/ZKPassportSubVerifier.sol";
import {ZKPassportHelper} from "../src/ZKPassportHelper.sol";
import {HonkVerifier as OuterVerifier5} from "../src/ultra-honk-verifiers/OuterCount5.sol";
import {HonkVerifier as OuterVerifier13} from "../src/ultra-honk-verifiers/OuterCount13.sol";
import {ProofVerifier} from "../src/Types.sol";
import {IRootRegistry} from "../src/IRootRegistry.sol";
import {MockRootRegistry} from "./MockRootRegistry.sol";

abstract contract ZKPassportTest is Test {
  using stdJson for string;

  bytes32 constant VERIFIER_VERSION = bytes32(uint256(1));
  string constant FIXTURES_CONFIG_PATH = "./test/fixtures/config.json";

  struct FixtureConfig {
    bytes32 vkeyHash;
    address verifier;
    string proof;
    string publicInputs;
    string committedInputs;
  }

  struct FixtureData {
    bytes proof;
    bytes32[] publicInputs;
    bytes committedInputs;
  }

  struct Fixtures {
    FixtureConfig valid;
    FixtureConfig allSubproofs;
  }

  Fixtures fixtures;

  constructor() {
    string memory fixturesJson = vm.readFile(FIXTURES_CONFIG_PATH);

    fixtures.valid = FixtureConfig({
      vkeyHash: fixturesJson.readBytes32(".valid.vkey_hash"),
      verifier: address(new OuterVerifier5()),
      proof: fixturesJson.readString(".valid.proof"),
      publicInputs: fixturesJson.readString(".valid.public_inputs"),
      committedInputs: fixturesJson.readString(".valid.committed_inputs")
    });

    fixtures.allSubproofs = FixtureConfig({
      vkeyHash: fixturesJson.readBytes32(".all_subproofs.vkey_hash"),
      verifier: address(new OuterVerifier13()),
      proof: fixturesJson.readString(".all_subproofs.proof"),
      publicInputs: fixturesJson.readString(".all_subproofs.public_inputs"),
      committedInputs: fixturesJson.readString(".all_subproofs.committed_inputs")
    });
  }

  function deployZKPassport() internal returns (ZKPassportRootVerifier, ZKPassportSubVerifier) {
    // Use labeled test accounts
    address admin = makeAddr("admin");
    address guardian = makeAddr("guardian");
    // Deploy mock root registry
    IRootRegistry rootRegistry = new MockRootRegistry();
    // Deploy root verifier
    ZKPassportRootVerifier rootVerifier = new ZKPassportRootVerifier(admin, guardian, rootRegistry);
    // Deploy sub verifier
    ZKPassportSubVerifier subVerifier = new ZKPassportSubVerifier(admin, rootVerifier);
    // Add sub verifier to root verifier
    vm.prank(admin);
    rootVerifier.addSubVerifier(VERIFIER_VERSION, subVerifier);
    // Deploy proof verifiers
    ProofVerifier[] memory proofVerifiers = new ProofVerifier[](2);
    proofVerifiers[0] = ProofVerifier({vkeyHash: fixtures.valid.vkeyHash, verifier: fixtures.valid.verifier});
    proofVerifiers[1] =
      ProofVerifier({vkeyHash: fixtures.allSubproofs.vkeyHash, verifier: fixtures.allSubproofs.verifier});
    // Add proof verifiers to sub verifier
    vm.prank(admin);
    subVerifier.addProofVerifiers(proofVerifiers);
    // Deploy helper
    ZKPassportHelper helper = new ZKPassportHelper(rootRegistry);
    // Add helper to root verifier
    vm.prank(admin);
    rootVerifier.addHelper(VERIFIER_VERSION, address(helper));
    // Return the root verifier and sub verifier
    return (rootVerifier, subVerifier);
  }

  /**
   * @dev Load fixture data from config
   */
  function loadFixture(FixtureConfig memory config) internal view returns (FixtureData memory) {
    return FixtureData({
      proof: loadBytesFromFile(config.proof),
      publicInputs: loadBytes32FromFile(config.publicInputs),
      committedInputs: loadBytesFromFile(config.committedInputs)
    });
  }

  /**
   * @dev Helper function to log the approx gas cost for an operation
   */
  function logGas(string memory name) internal {
    uint256 gasUsed = vm.stopSnapshotGas();
    console.log(name);
    console.log(gasUsed);
  }

  /**
   * @dev Helper function to load proof data from a file
   */
  function loadBytesFromFile(string memory filePath) internal view returns (bytes memory) {
    // Try to read the file as a string
    string memory proofHex;

    try vm.readFile(filePath) returns (string memory content) {
      proofHex = content;

      // Check if content starts with 0x
      if (bytes(proofHex).length > 2 && bytes(proofHex)[0] == "0" && bytes(proofHex)[1] == "x") {
        proofHex = slice(proofHex, 2, bytes(proofHex).length - 2);
      }

      // Try to parse the bytes
      try vm.parseBytes(proofHex) returns (bytes memory parsedBytes) {
        return parsedBytes;
      } catch Error(string memory) {
        revert("Failed to parse proof bytes");
      } catch {
        revert("Failed to parse proof bytes");
      }
    } catch Error(string memory) {
      revert("Failed to load proof from file");
    } catch {
      revert("Failed to load proof from file");
    }
  }

  /**
   * @dev Helper function to load public inputs from a file
   */
  function loadBytes32FromFile(string memory filePath) internal view returns (bytes32[] memory) {
    try vm.readFile(filePath) returns (string memory inputsJson) {
      // Parse the inputs from the file
      string[] memory inputs = vm.parseJsonStringArray(inputsJson, ".inputs");
      bytes32[] memory result = new bytes32[](inputs.length);

      for (uint256 i = 0; i < inputs.length; i++) {
        result[i] = vm.parseBytes32(inputs[i]);
      }

      return result;
    } catch Error(string memory) {
      revert("Failed to load inputs from file");
    } catch {
      revert("Failed to load inputs from file");
    }
  }

  /**
   * @dev Helper function to slice a string
   */
  function slice(string memory s, uint256 start, uint256 length) internal pure returns (string memory) {
    bytes memory b = bytes(s);
    require(start + length <= b.length, "String slice out of bounds");

    bytes memory result = new bytes(length);
    for (uint256 i = 0; i < length; i++) {
      result[i] = b[start + i];
    }

    return string(result);
  }
}
