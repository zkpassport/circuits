// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

import {IRootRegistry} from "../src/IRootRegistry.sol";

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

