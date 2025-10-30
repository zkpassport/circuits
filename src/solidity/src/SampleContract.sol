// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {DateUtils} from "../src/DateUtils.sol";
import {StringUtils} from "../src/StringUtils.sol";
import {DisclosedData, ProofVerificationParams} from "../src/Types.sol";
import {ZKPassportVerifier} from "../src/ZKPassportVerifier.sol";
import {ZKPassportRootVerifier} from "../src/ZKPassportRootVerifier.sol";
import {console} from "forge-std/console.sol";

contract SampleContract {
  address public admin;
  uint256 public constant ZKPASSPORT_VERIFIER_VERSION = 1;
  ZKPassportRootVerifier public zkPassportRootVerifier;
  // Unique Identifier => whether it was verified or not
  mapping(bytes32 => bool) public isVerified;
  // Unique Identifier => nationality
  mapping(bytes32 => string) public userNationality;
  // User address => unique identifier
  mapping(address => bytes32) public userUniqueIdentifier;
  string public validDomain;
  string public validScope;

  constructor() {
    admin = msg.sender;
    // Replace with your domain name
    validDomain = "zkpassport.id";
    // Replace with the scope you specified in the SDK
    validScope = "bigproof";
  }

  modifier onlyAdmin() {
    require(msg.sender == admin, "Only admin can call this function");
    _;
  }

  function setZKPassportVerifier(address _verifier) public onlyAdmin {
    zkPassportRootVerifier = ZKPassportRootVerifier(_verifier);
  }

  function setDomain(string calldata _domain) public onlyAdmin {
    validDomain = _domain;
  }

  function setSubscope(string calldata _subscope) public onlyAdmin {
    validScope = _subscope;
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
    // Get the current verifier from the ZKPassportRootVerifier
    ZKPassportVerifier verifier = ZKPassportVerifier(zkPassportRootVerifier.getVerifier(ZKPASSPORT_VERIFIER_VERSION));
    // Verify the proof
    (bool verified, bytes32 uniqueIdentifier) = verifier.verifyProof(params);
    require(verified, "Proof is invalid");
    require(!isVerified[uniqueIdentifier], "User already verified");
    // Check the proof was generated using your domain name (scope) and the subscope
    // you specified
    require(
      verifier.verifyScopes(params.proofVerificationData.publicInputs, validDomain, validScope),
      "Invalid domain or scope"
    );
    require(verifier.isAgeAboveOrEqual(18, params.commitments), "Age is not 18+");
    DisclosedData memory disclosedData = verifier.getDisclosedData(
      params.commitments,
      isIDCard
    );
    string[] memory nationalityExclusionList = new string[](3);
    nationalityExclusionList[0] = "ESP";
    nationalityExclusionList[1] = "ITA";
    nationalityExclusionList[2] = "PRT";
    require(verifier.isNationalityOut(nationalityExclusionList, params.commitments), "Nationality is part of the exclusion list");

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

  function doStuff() public {
    // Check the user is verified and registered
    require(userUniqueIdentifier[msg.sender] != bytes32(0), "User is not verified");
    // Everything that follows will be conditioned on the sender being registered with a valid proof
    // and meeting all the conditions in the register function
    // Build the rest of your logic here...
  }
}
