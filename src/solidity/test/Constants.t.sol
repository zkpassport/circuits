// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {Test} from "forge-std/Test.sol";
import {CommittedInputLen} from "../src/Constants.sol";
import {TestUtils} from "./Utils.t.sol";

contract ConstantsTest is TestUtils {
  function test_CommittedInputLen() public {
    // Check that the committed inputs lengths are consistent
    // to make sure they are not edited by mistake
    require(CommittedInputLen.INCL_NATIONALITY == CommittedInputLen.EXCL_NATIONALITY, "Inclusion nationality and exclusion nationality committed inputs should have the same length");
    require(CommittedInputLen.INCL_NATIONALITY == CommittedInputLen.INCL_ISSUING_COUNTRY, "Inclusion nationality and issuing country committed inputs should have the same length");
    require(CommittedInputLen.INCL_NATIONALITY == CommittedInputLen.EXCL_ISSUING_COUNTRY, "Inclusion nationality and exclusion issuing country committed inputs should have the same length");
    require(CommittedInputLen.INCL_ISSUING_COUNTRY == CommittedInputLen.EXCL_ISSUING_COUNTRY, "Inclusion issuing country and exclusion issuing country committed inputs should have the same length");
    require(CommittedInputLen.INCL_ISSUING_COUNTRY == CommittedInputLen.EXCL_NATIONALITY, "Inclusion issuing country and exclusion nationality committed inputs should have the same length");
    require(CommittedInputLen.INCL_ISSUING_COUNTRY == CommittedInputLen.INCL_NATIONALITY, "Inclusion issuing country and inclusion nationality committed inputs should have the same length");
    require(CommittedInputLen.COMPARE_EXPIRY == CommittedInputLen.COMPARE_BIRTHDATE, "Compare expiry and compare birthdate committed inputs should have the same length");
  }
}