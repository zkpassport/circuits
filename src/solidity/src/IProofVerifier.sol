// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

/**
 * @title IProofVerifier
 * @dev Interface for a ZKPassport proof verifier
 */
interface IProofVerifier {
  function verify(bytes calldata _proof, bytes32[] calldata _publicInputs) external view returns (bool);
}
