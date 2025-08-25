// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

bytes32 constant SANCTIONS_TREES_ROOT = 0x27cea23b989f5246d6577568d11cff22537f10fb47729dc004d1bf464ce37bd3;

library CommittedInputLen {
    uint256 constant COMPARE_AGE = 7;
    uint256 constant COMPARE_BIRTHDATE = 13;
    uint256 constant COMPARE_EXPIRY = 13;
    uint256 constant DISCLOSE_BYTES = 181;
    uint256 constant INCL_ISSUING_COUNTRY = 601;
    uint256 constant EXCL_ISSUING_COUNTRY = 601;
    uint256 constant INCL_NATIONALITY = 601;
    uint256 constant EXCL_NATIONALITY = 601;
    uint256 constant BIND = 501;
    uint256 constant SANCTIONS = 33;
}

