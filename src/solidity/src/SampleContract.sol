// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {DateUtils} from "../src/DateUtils.sol";
import {StringUtils} from "../src/StringUtils.sol";
import {ArrayUtils} from "../src/ArrayUtils.sol";
import {ZKPassportVerifier, ProofType, ProofVerificationParams} from "../src/ZKPassportVerifier.sol";
import {console} from "forge-std/console.sol";

contract SampleContract {
  address public admin;
  ZKPassportVerifier public zkPassportVerifier;

  // Unique Identifier => whether it was verified or not
  mapping(bytes32 => bool) public isVerified;
  // Unique Identifier => nationality
  mapping(bytes32 => string) public userNationality;
  // User address => unique identifier
  mapping(address => bytes32) public userUniqueIdentifier;
  string public validScope;
  string public validSubscope;

  constructor() {
    admin = msg.sender;
    // Replace with your domain name
    validScope = "zkpassport.id";
    // Replace with the scope you specified in the SDK
    validSubscope = "bigproof";
  }

  modifier onlyAdmin() {
    require(msg.sender == admin, "Only admin can call this function");
    _;
  }

  function setZKPassportVerifier(address _zkPassportVerifier) public onlyAdmin {
    zkPassportVerifier = ZKPassportVerifier(_zkPassportVerifier);
  }

  function setScope(string calldata _scope) public onlyAdmin {
    validScope = _scope;
  }

  function setSubscope(string calldata _subscope) public onlyAdmin {
    validSubscope = _subscope;
  }

  function checkAge(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) internal view {
    // Get the age condition checked in the proof
    (uint256 currentDate, uint8 minAge, uint8 maxAge) = zkPassportVerifier.getAgeProofInputs(
      committedInputs,
      committedInputCounts
    );
    // Possible bug: the `currentDate` from this disclosure proof is not being asserted to equal
    // the `currentDate` public input of the Outer proof. This means they could be different dates!
    // That feels like it could lead to vulnerabilities / unexpected behaviour.
    
    // Make sure the date used for the proof makes sense
    require(block.timestamp >= currentDate, "Date used in proof is in the future");
    // This is the condition for checking the age is 18 or above
    // Max age is set to 0 and therefore ignored in the proof, so it's equivalent to no upper limit
    // Min age is set to 18, so the user needs to be at least 18 years old
    require(minAge == 18 && maxAge == 0, "User needs to be above 18");
  }

  function getNationality(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts,
    bool isIDCard
  ) internal view returns (string memory) {
    // Get the disclosed bytes of data from the proof
    (, bytes memory disclosedBytes) = zkPassportVerifier.getDiscloseProofInputs(
      committedInputs,
      committedInputCounts
    );
    // Get the nationality from the disclosed data and ignore the rest
    // Passing the disclosed bytes returned by the previous function
    // this function will format it for you so you can use the data you need
    // Potentially dangerous if a developer mis-counts these many commas. Consider returning structs instead. 
    (, , string memory nationality, , , , , ) = zkPassportVerifier.getDisclosedData(
      disclosedBytes,
      isIDCard
    );
    return nationality;
  }

  // UX suggestion: it looks like `committedInputs` and `committedInputCounts` will always be passed
  // around as a pair everywhere. Consider wrapping them in a struct, and giving the struct a less
  // jargony name, like 'RevealedData` (or something...) so that this app-developer-side code is easier for a non-cryptographer to grasp.
  // The app developer (who will write a version of this smart contract) can then just pass around this
  // new struct as an opaque blob of data to any of the neat getter functions you've exposed.
  function checkNationalityExclusion(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) internal view {
    string[] memory nationalityExclusionList = zkPassportVerifier.getCountryProofInputs(
      committedInputs,
      committedInputCounts,
      ProofType.NATIONALITY_EXCLUSION
    );
    // The exclusion check relies on the country list being sorted in
    // ascending order, if it is not, then the proof has no value.
    // ^^^ Consider amending this comment, since now the circuit enforces
    // the ordering.
    require(
      ArrayUtils.isSortedAscending(nationalityExclusionList),
      "Nationality exclusion countries must be sorted in ascending order"
    ); // You can get rid of this `require` now.

    // Let's check the exclusion list checked what we expect
    // Here we expect Spain, Italy and Portugal
    require(
      StringUtils.equals(nationalityExclusionList[0], "ESP") &&
        StringUtils.equals(nationalityExclusionList[1], "ITA") &&
        StringUtils.equals(nationalityExclusionList[2], "PRT"),
      "Not the expected exclusion list"
    );
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
    // As a possible alternative to this `isIDCard` percolating through your stack,
    // perhaps the disclosure circuit could output data in a format that's uniform
    // for both passports and id cards: For each data type, choose the larger byte length,
    // and expose those uniform lengths from the circuit to the verifier.
    // It looks like `isIDCard` is only needed for the "disclose" proof type, to it might
    // not be too big a change? It's up to you, of course :)
    bool isIDCard
  ) public returns (bytes32) {
    (bool verified, bytes32 uniqueIdentifier) = zkPassportVerifier.verifyProof(params);
    require(verified, "Proof is invalid");
    require(!isVerified[uniqueIdentifier], "User already verified");
    // Check the proof was generated using your domain name (scope) and the subscope
    // you specified
    require(
      zkPassportVerifier.verifyScopes(params.publicInputs, validScope, validSubscope),
      "Invalid scope or subscope"
    );
    checkAge(params.committedInputs, params.committedInputCounts);
    string memory nationality = getNationality(
      params.committedInputs,
      params.committedInputCounts,
      isIDCard
    );
    checkNationalityExclusion(params.committedInputs, params.committedInputCounts);

    // If all good, mark the user as verified
    isVerified[uniqueIdentifier] = true;
    // Store the nationality for later use
    userNationality[uniqueIdentifier] = nationality;
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
