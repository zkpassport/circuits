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
}
