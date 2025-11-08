// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

import {ZKPassportRootVerifier} from "./ZKPassportRootVerifier.sol";
import {ZKPassportHelper} from "./ZKPassportHelper.sol";
import {DisclosedData, ProofVerificationParams} from "./Types.sol";

contract SampleContract {
  // ZKPassport Verifier contract
  ZKPassportRootVerifier public zkPassportVerifier;

  // Unique identifier => whether it was verified or not
  mapping(bytes32 => bool) public isVerified;

  // Unique identifier => nationality
  mapping(bytes32 => string) public userNationality;

  // User address => unique identifier
  mapping(address => bytes32) public userUniqueIdentifier;

  // Replace with your domain name
  string internal constant validDomain = "zkpassport.id";

  // Replace with your usage scope (e.g. "registration")
  string internal constant validScope = "bigproof";

  // Errors
  error InvalidProof();
  error InvalidScope();
  error InvalidDomain();
  error InvalidBoundAddress(address _expected, address _received);
  error InvalidChainId(uint256 _expected, uint256 _received);
  error InvalidAge();
  error InvalidCountry();
  error InvalidValidityPeriod();
  error InvalidFaceMatch();
  error ExtraDiscloseDataNonZero();
  error SybilDetected(bytes32 _nullifier);
  error AttesterDoesNotExist(address _attester);
  error NoNullifier();
  error MerkleProofInvalid();

  // Excluded countries list
  string internal constant PKR = "PRK";
  string internal constant UKR = "UKR";
  string internal constant IRN = "IRN";
  string internal constant CUB = "CUB";

  // Minimum age
  uint8 public constant MIN_AGE = 18;

  // Validity period in seconds
  uint256 public constant VALIDITY_PERIOD = 7 days;

  // Pass the address of the ZKPassport Root Verifier
  constructor(address _zkPassportVerifier) {
    require(_zkPassportVerifier != address(0), "ZKPassport Root Verifier cannot be zero address");
    zkPassportVerifier = ZKPassportRootVerifier(_zkPassportVerifier);
  }

  /**
   * @notice Register a user using a ZKPassport proof
   * @dev No need to understand what the parameters are, the getSolidityVerifierParameters function
   * in the ZKPassport TypeScript's SDK will get them for you so you can pass it to your contract
   */
  function register(
    ProofVerificationParams calldata params,
    // Disclosed data are formatted differently between
    // passports and ID cards
    // You can ask the user to disclose their document type
    // and the SDK will tell you which one they have
    bool isIDCard
  ) public returns (bytes32) {

    // Verify the proof
    (bool verified, bytes32 uniqueIdentifier, ZKPassportHelper helper) = zkPassportVerifier.verify(params);
    require(verified, "Proof is invalid");
    require(!isVerified[uniqueIdentifier], "User already verified");

    // Verify the proof was generated for the correct domain name
    require(helper.verifyScopes(params.proofVerificationData.publicInputs, validDomain, validScope), "Invalid domain or scope");

    // Verify the age is above or equal to the minimum age
    require(helper.isAgeAboveOrEqual(MIN_AGE, params.committedInputs), "Age is not 18+");

    // Verify the nationality exclusion list used in the proof
    string[] memory nationalityExclusionList = new string[](3);
    nationalityExclusionList[0] = "ESP";
    nationalityExclusionList[1] = "ITA";
    nationalityExclusionList[2] = "PRT";
    require(helper.isNationalityOut(nationalityExclusionList, params.committedInputs), "Nationality is part of the exclusion list");

    // Get the disclosed data (includes the nationality)
    DisclosedData memory disclosedData = helper.getDisclosedData(
      params.committedInputs,
      isIDCard
    );

    // If all good, mark the user as verified
    isVerified[uniqueIdentifier] = true;

    // Store the nationality for later use
    userNationality[uniqueIdentifier] = disclosedData.nationality;

    // Attach the unique identifier to the user address
    // So they don't have to run the check again if they use the same address
    userUniqueIdentifier[msg.sender] = uniqueIdentifier;
    return uniqueIdentifier;
  }

  /**
   * @notice Unregister a user from the contract
   * @dev This function will delete the user's unique identifier and nationality from the contract
   */
  function unregister() public {
    require(userUniqueIdentifier[msg.sender] != bytes32(0), "User is not verified");
    delete isVerified[userUniqueIdentifier[msg.sender]];
    delete userNationality[userUniqueIdentifier[msg.sender]];
    delete userUniqueIdentifier[msg.sender];
  }

  function doStuff() public view {
    // Check the user is verified and registered
    require(userUniqueIdentifier[msg.sender] != bytes32(0), "User is not verified");
    // Everything that follows will be conditioned on the sender being registered with a valid proof
    // and meeting all the conditions in the register function
    // Build the rest of your logic here...
  }
}
