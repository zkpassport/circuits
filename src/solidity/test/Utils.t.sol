// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test, console} from "forge-std/Test.sol";

abstract contract TestUtils is Test {
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
      } catch Error(string memory reason) {
        revert("Failed to parse proof bytes");
      } catch {
        revert("Failed to parse proof bytes");
      }
    } catch Error(string memory reason) {
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

      for (uint i = 0; i < inputs.length; i++) {
        result[i] = vm.parseBytes32(inputs[i]);
      }

      return result;
    } catch Error(string memory reason) {
      revert("Failed to load inputs from file");
    } catch {
      revert("Failed to load inputs from file");
    }
  }

  /**
   * @dev Helper function to slice a string
   */
  function slice(string memory s, uint start, uint length) internal pure returns (string memory) {
    bytes memory b = bytes(s);
    require(start + length <= b.length, "String slice out of bounds");

    bytes memory result = new bytes(length);
    for (uint i = 0; i < length; i++) {
      result[i] = b[start + i];
    }

    return string(result);
  }
}
