// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test} from "forge-std/Test.sol";
import {StringUtils} from "../src/StringUtils.sol";
import {TestUtils} from "./Utils.t.sol";

contract StringUtilsTest is TestUtils {
  function test_equals() public {
    assertTrue(StringUtils.equals("hello", "hello"));
    assertFalse(StringUtils.equals("hello", "hell0"));
    assertFalse(StringUtils.equals("hello", "hello "));
  }

  function test_isEmpty() public {
    assertTrue(StringUtils.isEmpty(""));
    assertFalse(StringUtils.isEmpty("hello"));
    assertFalse(StringUtils.isEmpty("hello "));
    assertFalse(StringUtils.isEmpty(" "));
  }
}