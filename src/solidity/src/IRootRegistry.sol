// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

/**
 * @title IRootRegistry
 * @dev Interface for the ZKPassport RootRegistry contract
 */
interface IRootRegistry {
  function latestRoot(bytes32 registryId) external view returns (bytes32);
  function isRootValid(bytes32 registryId, bytes32 root, uint256 timestamp) external view returns (bool);
  function isRootValidAtTimestamp(bytes32 registryId, bytes32 root, uint256 timestamp) external view returns (bool);
}
