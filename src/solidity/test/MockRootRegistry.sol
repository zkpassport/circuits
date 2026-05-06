// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

/**
 * @notice Standalone mock that matches the subset of `RootRegistry`'s ABI exercised by
 *         SubVerifier and VerifierHelper. Used in test setup as
 *         `RootRegistry(address(new MockRootRegistry()))`. Always reports roots as valid.
 */
contract MockRootRegistry {
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
