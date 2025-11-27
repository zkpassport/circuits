// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {CommittedInputLen} from "../src/Constants.sol";
import {ZKPassportTest} from "./Utils.t.sol";

contract ConstantsTest is ZKPassportTest {
  function test_CommittedInputLen() public pure {
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
