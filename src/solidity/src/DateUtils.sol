// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

library DateUtils {
  // Constants
  uint256 constant UNIX_EPOCH_START_YEAR = 1970;
  uint256 constant UNIX_EPOCH_START_MONTH = 1;
  uint256 constant UNIX_EPOCH_START_DAY = 1;

  // Constants for timestamp calculation
  uint256 constant SECONDS_PER_DAY = 86400;
  uint256 constant SECONDS_PER_HOUR = 3600;
  uint256 constant SECONDS_PER_MINUTE = 60;
  uint256 constant DAYS_PER_WEEK = 7;

  /**
   * @dev Converts an ASCII code to a number
   * @param asciiCode The ASCII code to convert
   * @return The number represented by the ASCII code
   */
  function asciiCodeToNumber(bytes1 asciiCode) internal pure returns (uint256) {
    return uint8(asciiCode) - 48;
  }

  /**
   * @dev Checks if a year is a leap year
   * @param year The year to check
   * @return True if the year is a leap year, false otherwise
   */
  function isLeapYear(uint256 year) internal pure returns (bool) {
    if (year % 4 != 0) return false;
    if (year % 100 != 0) return true;
    if (year % 400 != 0) return false;
    return true;
  }

  /**
   * @dev Gets the number of days in a specific month
   * @param month The month (1-12)
   * @param year The year (to check for leap years)
   * @return The number of days in the month
   */
  function getDaysInMonth(uint256 month, uint256 year) internal pure returns (uint256) {
    require(month >= 1 && month <= 12, "Invalid month");

    // February special case for leap years
    if (month == 2) {
      return isLeapYear(year) ? 29 : 28;
    }

    // For all other months
    if (month == 4 || month == 6 || month == 9 || month == 11) {
      return 30;
    }

    // Months with 31 days
    return 31;
  }

  /**
   * @dev Converts a date bytes to a UNIX timestamp
   * @param date The date bytes in this format: YYYYMMDD
   * @return The UNIX timestamp in seconds
   */
  function getTimestampFromDate(bytes memory date) internal pure returns (uint256) {
    uint256 year = asciiCodeToNumber(date[0]) *
      1000 +
      asciiCodeToNumber(date[1]) *
      100 +
      asciiCodeToNumber(date[2]) *
      10 +
      asciiCodeToNumber(date[3]);
    uint256 month = asciiCodeToNumber(date[4]) * 10 + asciiCodeToNumber(date[5]);
    uint256 day = asciiCodeToNumber(date[6]) * 10 + asciiCodeToNumber(date[7]);
    require(year >= UNIX_EPOCH_START_YEAR, "Year before UNIX epoch");
    require(month >= 1 && month <= 12, "Invalid month");
    require(day >= 1 && day <= getDaysInMonth(month, year), "Invalid day");

    // Count days before current year
    uint256 totalDays = 0;
    for (uint256 y = UNIX_EPOCH_START_YEAR; y < year; y++) {
      totalDays += isLeapYear(y) ? 366 : 365;
    }

    // Count days before current month
    for (uint256 m = 1; m < month; m++) {
      totalDays += getDaysInMonth(m, year);
    }

    // Add days in current month
    totalDays += day - 1; // Subtract 1 because we want days since epoch start

    // Convert to seconds (86400 seconds in a day)
    return totalDays * SECONDS_PER_DAY;
  }

  /**
   * @dev Validates if a date is within a validity period
   * @param date The date bytes in this format: YYYYMMDD
   * @param validityPeriodInDays The validity period in days
   * @return True if the date is valid and within the validity period
   */
  function isDateValid(
    bytes memory date,
    uint256 validityPeriodInDays
  ) internal view returns (bool) {
    uint256 timestamp = getTimestampFromDate(date);
    uint256 validityPeriodTimestamp = timestamp + validityPeriodInDays * SECONDS_PER_DAY;
    return
      block.timestamp >= timestamp &&
      validityPeriodTimestamp > timestamp &&
      validityPeriodTimestamp > block.timestamp;
  }
}
