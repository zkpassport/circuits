// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IVerifier} from "../src/OuterCount4.sol";
import {console} from "forge-std/console.sol";

contract ZKPassportVerifier {
    // Constants
    uint256 constant UNIX_EPOCH_START_YEAR = 1970;
    uint256 constant UNIX_EPOCH_START_MONTH = 1;
    uint256 constant UNIX_EPOCH_START_DAY = 1;

    // Constants for timestamp calculation
    uint256 constant SECONDS_PER_DAY = 86400;
    uint256 constant SECONDS_PER_HOUR = 3600;
    uint256 constant SECONDS_PER_MINUTE = 60;
    uint256 constant DAYS_PER_WEEK = 7;
    
    // Array of days in each month (non-leap year)
    uint8[12] private DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    address public admin;
    bool public paused;

    mapping(bytes32 => address) public vkeyHashToVerifier;

    // Events
    event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
    event PausedStatusChanged(bool paused);
    event ZKPassportVerifierDeployed(address indexed admin, uint256 timestamp);
    event VerifierAdded(bytes32 indexed vkeyHash, address indexed verifier);
    event VerifierRemoved(bytes32 indexed vkeyHash);

    /**
     * @dev Constructor
     */
    constructor() {
        admin = msg.sender;
        emit ZKPassportVerifierDeployed(admin, block.timestamp);
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized: admin only");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "Contract is paused");
        _;
    }
    
    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Admin cannot be zero address");
        address oldAdmin = admin;
        admin = newAdmin;
        emit AdminUpdated(oldAdmin, newAdmin);
    }

    function setPaused(bool _paused) external onlyAdmin {
        paused = _paused;
        emit PausedStatusChanged(_paused);
    }

    function addVerifiers(bytes32[] calldata vkeyHashes, address[] calldata verifiers) external onlyAdmin whenNotPaused {
        for (uint256 i = 0; i < vkeyHashes.length; i++) {
            vkeyHashToVerifier[vkeyHashes[i]] = verifiers[i];
            emit VerifierAdded(vkeyHashes[i], verifiers[i]);
        }
    }

    function removeVerifiers(bytes32[] calldata vkeyHashes) external onlyAdmin whenNotPaused {
        for (uint256 i = 0; i < vkeyHashes.length; i++) {
            delete vkeyHashToVerifier[vkeyHashes[i]];
            emit VerifierRemoved(vkeyHashes[i]);
        }
    }

    function asciiCodeToNumber(bytes32 asciiCode) internal pure returns (uint256) {
        return uint256(asciiCode) - 48;
    }

    /**
     * @dev Helper function to check if a year is a leap year
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
     * @dev Helper function to get days in a specific month
     * @param month The month (1-12)
     * @param year The year (to check for leap years)
     * @return The number of days in the month
     */
    function getDaysInMonth(uint256 month, uint256 year) internal view returns (uint256) {
        require(month >= 1 && month <= 12, "Invalid month");
        
        // February special case for leap years
        if (month == 2 && isLeapYear(year)) {
            return 29;
        }
        
        // Arrays in Solidity are 0-indexed, but months are 1-indexed
        return DAYS_IN_MONTH[month - 1];
    }

    /**
     * @dev Helper function to get the timestamp from the date
     * @param date The date in this format: [Y1, Y2, Y3, Y4, M1, M2, D1, D2]
     * @return The UNIX timestamp in seconds
     */
    function getTimestampFromDate(bytes32[] memory date) internal view returns (uint256) {
        uint256 year = asciiCodeToNumber(date[0]) * 1000 + asciiCodeToNumber(date[1]) * 100 + asciiCodeToNumber(date[2]) * 10 + asciiCodeToNumber(date[3]);
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
        totalDays += day - 1;  // Subtract 1 because we want days since epoch start
        
        // Convert to seconds (86400 seconds in a day)
        return totalDays * SECONDS_PER_DAY;
    }

    function checkDate(bytes32[] memory publicInputs, uint256 validityPeriodInDays) internal view returns (bool) {
        bytes32[] memory currentDate = new bytes32[](8);
        for (uint256 i = 1; i < 9; i++) {
            currentDate[i - 1] = publicInputs[i];
        }
        uint256 timestamp = getTimestampFromDate(currentDate);
        uint256 validityPeriodTimestamp = timestamp + validityPeriodInDays * SECONDS_PER_DAY;
        return block.timestamp <= timestamp && validityPeriodTimestamp > timestamp && validityPeriodTimestamp > block.timestamp;
    }

    function verifyCommittedInputs(bytes32[] memory paramCommitments, bytes calldata committedInputs, uint256[] memory committedInputCounts) internal view returns (bool) {
        uint256 offset = 0;
        for (uint256 i = 0; i < committedInputCounts.length; i++) {
            // One byte is dropped inside the circuit as BN254 is limited to 254 bits
            bytes32 calculatedCommitment = sha256(abi.encodePacked(committedInputs[offset:offset + committedInputCounts[i]])) >> 8;
            require(calculatedCommitment == paramCommitments[i], "Invalid commitment");
            offset += committedInputCounts[i];
        }
        return true;
    }

    function verifyProof(
        bytes32 vkeyHash,
        bytes calldata proof, 
        bytes32[] calldata publicInputs, 
        bytes calldata committedInputs, 
        uint256[] calldata committedInputCounts, 
        uint256 validityPeriodInDays
    ) external view returns (bool, bytes32) {
        address verifier = vkeyHashToVerifier[vkeyHash];
        require(verifier != address(0), "Verifier not found");
        // We remove the last 16 public inputs from the count cause they are part of the aggregation object
        // and not the actual public inputs of the circuit
        uint256 actualPublicInputCount = publicInputs.length - 16;
        // TODO: verify the certificate registry root
        // bytes32 certificateRegistryRoot = publicInputs[0];
        // Checks the date of the proof
        require(checkDate(publicInputs, validityPeriodInDays), "Proof expired");
        // Extracts the commitments from the public inputs
        bytes32[] memory paramCommitments = new bytes32[](actualPublicInputCount - 12);
        for (uint256 i = 11; i < actualPublicInputCount - 1; i++) {
            paramCommitments[i - 11] = publicInputs[i];
        }
        // Verifies the commitments against the committed inputs
        require(verifyCommittedInputs(paramCommitments, committedInputs, committedInputCounts), "Invalid committed inputs");
        // Verifies the proof
        return (IVerifier(verifier).verify(proof, publicInputs), publicInputs[actualPublicInputCount - 1]);
    }
}