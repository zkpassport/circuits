// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title IRootRegistry
 * @dev Interface for a root registry
 */
 // I guess the impl is in some other repo?
interface IRootRegistry {
  function latestRoot(bytes32 registryId) external view returns (bytes32);

  function isRootValid(bytes32 registryId, bytes32 root) external view returns (bool);

  function isRootValidAtTimestamp(
    bytes32 registryId,
    bytes32 root,
    uint256 timestamp
  ) external view returns (bool);
}
