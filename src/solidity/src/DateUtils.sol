// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

library DateUtils {
  /**
   * @dev Validates if a date is within a validity period
   * @param timestamp The timestamp in seconds since the Unix epoch
   * @param validityPeriodInSeconds The validity period in seconds
   * @return True if the date is valid and within the validity period
   */
  function isDateValid(
    uint256 timestamp,
    uint256 validityPeriodInSeconds
  ) internal view returns (bool) {
    uint256 validityPeriodTimestamp = timestamp + validityPeriodInSeconds;
    return
      block.timestamp >= timestamp &&
      validityPeriodTimestamp > timestamp &&
      validityPeriodTimestamp > block.timestamp;
  }
}
