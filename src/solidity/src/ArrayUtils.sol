// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {StringUtils} from "./StringUtils.sol";

library ArrayUtils {
  function isSortedAscending(string[] memory array) internal pure returns (bool) {
    for (uint256 i = 1; i < array.length; i++) {
      // Ignore empty strings
      if (StringUtils.isEmpty(array[i])) {
        continue;
      }
      if (StringUtils.getWeightedBytes(array[i]) < StringUtils.getWeightedBytes(array[i - 1])) {
        return false;
      }
    }
    return true;
  }
}
