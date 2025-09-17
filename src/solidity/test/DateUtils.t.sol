// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test} from "forge-std/Test.sol";
import {DateUtils} from "../src/DateUtils.sol";
import {TestUtils} from "./Utils.t.sol";

contract DateUtilsTest is TestUtils {
  uint256 constant CURRENT_DATE = 1756239313;

  function test_isDateValid() public {
    vm.warp(CURRENT_DATE);

    // The date passed is one second away from falling out of the validity period
    // so it should be valid
    assertTrue(DateUtils.isDateValid(CURRENT_DATE - 1 days + 1 seconds, 1 days));
    // The date passed just reached the end of the validity period
    // so it should not be valid
    assertFalse(DateUtils.isDateValid(CURRENT_DATE - 1 days, 1 days));
    // The date passed is one second out of the end of the validity period
    // so it should not be valid
    assertFalse(DateUtils.isDateValid(CURRENT_DATE - 1 days - 1 seconds, 1 days));

    // The date passed is one second away from falling out of the validity period
    // so it should be valid
    assertTrue(DateUtils.isDateValid(CURRENT_DATE - 1 days, 1 days + 1 seconds));
    // The date passed just reached the end of the validity period
    // so it should not be valid
    assertFalse(DateUtils.isDateValid(CURRENT_DATE - 1 days, 1 days));
    // The date passed is one second out of the end of the validity period
    // so it should not be valid
    assertFalse(DateUtils.isDateValid(CURRENT_DATE - 1 days, 1 days - 1 seconds));

    // The date passed is equal to the current block timestamp
    // so it should be valid
    assertTrue(DateUtils.isDateValid(CURRENT_DATE, 1 days));

    // The date passed is one second after the current block timestamp
    // so it should not be valid
    assertFalse(DateUtils.isDateValid(CURRENT_DATE + 1 seconds, 1 days));

    // The validity period is 0 seconds
    // so it should not be valid
    assertFalse(DateUtils.isDateValid(CURRENT_DATE, 0));

    // The validity period is 1 second
    // so it should be valid
    assertTrue(DateUtils.isDateValid(CURRENT_DATE, 1 seconds));
  }
}