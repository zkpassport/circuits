// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IRootRegistry} from "../src/Types.sol";

contract MockRootRegistry is IRootRegistry {
  function latestRoot(bytes32) external pure returns (bytes32) {
    return bytes32(uint256(1));
  }

  function isRootValid(bytes32, bytes32, uint256) external pure returns (bool) {
    return true;
  }

  function isRootValidAtTimestamp(bytes32, bytes32, uint256) external pure returns (bool) {
    return true;
  }
}

