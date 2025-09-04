// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

// Missing tests for all fns.
library StringUtils {
  function equals(string memory a, string memory b) internal pure returns (bool) {
    return keccak256(bytes(a)) == keccak256(bytes(b));
  }

  function isEmpty(string memory a) internal pure returns (bool) {
    return bytes(a).length == 0;
  }

  function getWeightedBytes(string memory a) internal pure returns (uint256) {
    uint256 length = bytes(a).length;
    uint256 sum = 0;
    for (uint256 i = length - 1; i > 0; i--) {
      sum += uint256(uint8(bytes(a)[length - 1 - i])) * 2 ** (i * 8);
    }
    return sum;
  }

  /**
   * @dev Converts a uint256 to its ASCII string decimal representation.
   * @param value The uint256 value to convert
   * @return The string representation of the uint256 value
   */
  function toString(uint256 value) internal pure returns (string memory) {
    // Special case for 0
    if (value == 0) {
      return "0";
    }

    // Find the length of the decimal representation
    uint256 temp = value;
    uint256 digits;
    while (temp != 0) {
      digits++;
      temp /= 10;
    }

    // Create a bytes array of the appropriate length
    bytes memory buffer = new bytes(digits);

    // Fill the buffer from right to left
    while (value != 0) {
      digits -= 1;
      buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
      value /= 10;
    }

    return string(buffer);
  }
}
