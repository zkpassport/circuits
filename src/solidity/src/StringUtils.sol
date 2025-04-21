// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

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
}
