// SPDX-License-Identifier: Apache-2.0
// Copyright © 2025 ZKPassport
/*
 ______ _     _  _____  _______ _______ _______  _____   _____   ______ _______
  ____/ |____/  |_____] |_____| |______ |______ |_____] |     | |_____/    |
 /_____ |    \_ |       |     | ______| ______| |       |_____| |    \_    |

*/

pragma solidity ^0.8.30;

import {IRootRegistry} from "./IRootRegistry.sol";
import {DateUtils} from "./DateUtils.sol";
import {StringUtils} from "./StringUtils.sol";
import {InputsExtractor} from "./InputsExtractor.sol";
import {SECONDS_BETWEEN_1900_AND_1970, PublicInput, AppAttest, RegistryID} from "./Constants.sol";
import {ProofType, DisclosedData, BoundData, FaceMatchMode, Environment, OS} from "./Types.sol";

contract ZKPassportHelper {
  IRootRegistry public immutable rootRegistry;

  constructor(IRootRegistry _rootRegistry) {
    require(address(_rootRegistry) != address(0), "Root registry cannot be zero address");
    rootRegistry = _rootRegistry;
  }

  /**
   * @notice Gets the data disclosed by the proof
   * @param committedInputs The committed inputs
   * @param isIDCard Whether the proof is an ID card
   * @return disclosedData The data disclosed by the proof
   */
  function getDisclosedData(bytes calldata committedInputs, bool isIDCard)
    external
    pure
    returns (DisclosedData memory disclosedData)
  {
    (, bytes memory discloseBytes) = InputsExtractor.getDiscloseProofInputs(committedInputs);
    disclosedData = InputsExtractor.getDisclosedData(discloseBytes, isIDCard);
  }

  /**
   * @notice Checks if the age is above or equal to the given age
   * @param minAge The age must be above or equal to this age
   * @param committedInputs The committed inputs
   * @return True if the age is above or equal to the given age, false otherwise
   */
  function isAgeAboveOrEqual(uint8 minAge, bytes calldata committedInputs) public pure returns (bool) {
    (uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(committedInputs);
    require(max == 0, "The proof upper bound must be 0, please use isAgeBetween instead");
    return minAge == min;
  }

  /**
   * @notice Checks if the age is above the given age
   * @param minAge The age must be above this age
   * @param committedInputs The committed inputs
   * @return True if the age is above the given age, false otherwise
   */
  function isAgeAbove(uint8 minAge, bytes calldata committedInputs) public pure returns (bool) {
    return isAgeAboveOrEqual(minAge + 1, committedInputs);
  }

  /**
   * @notice Checks if the age is in the given range
   * @param minAge The age must be greater than or equal to this age
   * @param maxAge The age must be less than or equal to this age
   * @param committedInputs The committed inputs
   * @return True if the age is in the given range, false otherwise
   */
  function isAgeBetween(uint8 minAge, uint8 maxAge, bytes calldata committedInputs) public pure returns (bool) {
    (uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(committedInputs);
    require(minAge <= maxAge, "Min age must be less than or equal to max age");
    require(min != 0, "The proof lower bound must be non-zero, please use isAgeBelowOrEqual instead");
    require(max != 0, "The proof upper bound must be non-zero, please use isAgeAboveOrEqual instead");
    return minAge == min && maxAge == max;
  }

  /**
   * @notice Checks if the age is below or equal to the given age
   * @param maxAge The age must be below or equal to this age
   * @param committedInputs The committed inputs
   * @return True if the age is below or equal to the given age, false otherwise
   */
  function isAgeBelowOrEqual(uint8 maxAge, bytes calldata committedInputs) public pure returns (bool) {
    (uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(committedInputs);
    require(min == 0, "The proof lower bound must be 0, please use isAgeBetween instead");
    return maxAge == max;
  }

  /**
   * @notice Checks if the age is below the given age
   * @param maxAge The age must be below this age
   * @param committedInputs The committed inputs
   * @return True if the age is below the given age, false otherwise
   */
  function isAgeBelow(uint8 maxAge, bytes calldata committedInputs) public pure returns (bool) {
    require(maxAge > 0, "Max age must be greater than 0");
    return isAgeBelowOrEqual(maxAge - 1, committedInputs);
  }

  /**
   * @notice Checks if the age is equal to the given age
   * @param age The age must be equal to this age
   * @param committedInputs The committed inputs
   * @return True if the age is equal to the given age, false otherwise
   */
  function isAgeEqual(uint8 age, bytes calldata committedInputs) public pure returns (bool) {
    return isAgeBetween(age, age, committedInputs);
  }

  function _isDateAfterOrEqual(uint256 minDate, ProofType proofType, bytes calldata committedInputs)
    private
    pure
    returns (bool)
  {
    (uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(committedInputs, proofType);
    require(proofType == ProofType.BIRTHDATE || proofType == ProofType.EXPIRY_DATE, "Invalid proof type");
    if (proofType == ProofType.BIRTHDATE) {
      require(max == 0, "The proof upper bound must be 0, please use isBirthdateBetween instead");
      // Birthdate comparison dates use 1900 as the starting epoch so the proof can take in value
      // prior to 1970, so we need to subtract the difference between 1900 and 1970 (starting UNIX epoch)
      return minDate == min - SECONDS_BETWEEN_1900_AND_1970;
    } else {
      require(max == 0, "The proof upper bound must be 0, please use isExpiryDateBetween instead");
      return minDate == min;
    }
  }

  function _isDateBetween(uint256 minDate, uint256 maxDate, ProofType proofType, bytes calldata committedInputs)
    private
    pure
    returns (bool)
  {
    (uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(committedInputs, proofType);
    require(minDate <= maxDate, "Min date must be less than or equal to max date");
    require(proofType == ProofType.BIRTHDATE || proofType == ProofType.EXPIRY_DATE, "Invalid proof type");
    if (proofType == ProofType.BIRTHDATE) {
      require(min != 0, "The proof lower bound must be non-zero, please use isBirthdateBelowOrEqual instead");
      require(max != 0, "The proof upper bound must be non-zero, please use isBirthdateAboveOrEqual instead");
      // Birthdate comparison dates use 1900 as the starting epoch so the proof can take in values
      // prior to 1970, so we need to subtract the difference between 1900 and 1970 (starting UNIX epoch)
      return minDate == min - SECONDS_BETWEEN_1900_AND_1970 && maxDate == max - SECONDS_BETWEEN_1900_AND_1970;
    } else {
      require(min != 0, "The proof lower bound must be non-zero, please use isExpiryDateBelowOrEqual instead");
      require(max != 0, "The proof upper bound must be non-zero, please use isExpiryDateAboveOrEqual instead");
      return minDate == min && maxDate == max;
    }
  }

  function _isDateBeforeOrEqual(uint256 maxDate, ProofType proofType, bytes calldata committedInputs)
    private
    pure
    returns (bool)
  {
    (uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(committedInputs, proofType);
    require(min == 0, "The proof lower bound must be 0, please use _isDateBetween instead");
    require(proofType == ProofType.BIRTHDATE || proofType == ProofType.EXPIRY_DATE, "Invalid proof type");
    if (proofType == ProofType.BIRTHDATE) {
      require(max != 0, "The proof upper bound must be non-zero, please use isBirthdateAboveOrEqual instead");
      // Birthdate comparison dates use 1900 as the starting epoch so the proof can take in value
      // prior to 1970, so we need to subtract the difference between 1900 and 1970 (starting UNIX epoch)
      return maxDate == max - SECONDS_BETWEEN_1900_AND_1970;
    } else {
      require(max != 0, "The proof upper bound must be non-zero, please use isExpiryDateAboveOrEqual instead");
      return maxDate == max;
    }
  }

  /**
   * @notice Checks if the birthdate is after or equal to the given date
   * @param minDate The birthdate must be after or equal to this date
   * @param committedInputs The committed inputs
   * @return True if the birthdate is after or equal to the given date, false otherwise
   */
  function isBirthdateAfterOrEqual(uint256 minDate, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateAfterOrEqual(minDate, ProofType.BIRTHDATE, committedInputs);
  }

  /**
   * @notice Checks if the birthdate is after the given date
   * @param minDate The birthdate must be after this date
   * @param committedInputs The committed inputs
   * @return True if the birthdate is after the given date, false otherwise
   */
  function isBirthdateAfter(uint256 minDate, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateAfterOrEqual(minDate + 1 days, ProofType.BIRTHDATE, committedInputs);
  }

  /**
   * @notice Checks if the birthdate is between the given dates
   * @param minDate The birthdate must be after or equal to this date
   * @param maxDate The birthdate must be before or equal to this date
   * @param committedInputs The committed inputs
   * @return True if the birthdate is between the given dates, false otherwise
   */
  function isBirthdateBetween(uint256 minDate, uint256 maxDate, bytes calldata committedInputs)
    public
    pure
    returns (bool)
  {
    return _isDateBetween(minDate, maxDate, ProofType.BIRTHDATE, committedInputs);
  }

  /**
   * @notice Checks if the birthdate is before or equal to the given date
   * @param maxDate The birthdate must be before or equal to this date
   * @param committedInputs The committed inputs
   * @return True if the birthdate is before or equal to the given date, false otherwise
   */
  function isBirthdateBeforeOrEqual(uint256 maxDate, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateBeforeOrEqual(maxDate, ProofType.BIRTHDATE, committedInputs);
  }

  /**
   * @notice Checks if the birthdate is before the given date
   * @param maxDate The birthdate must be before this date
   * @param committedInputs The committed inputs
   * @return True if the birthdate is before the given date, false otherwise
   */
  function isBirthdateBefore(uint256 maxDate, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateBeforeOrEqual(maxDate - 1 days, ProofType.BIRTHDATE, committedInputs);
  }

  /**
   * @notice Checks if the birthdate is equal to the given date
   * @param date The birthdate must be equal to this date
   * @param committedInputs The committed inputs
   * @return True if the birthdate is equal to the given date, false otherwise
   */
  function isBirthdateEqual(uint256 date, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateBetween(date, date, ProofType.BIRTHDATE, committedInputs);
  }

  /**
   * @notice Checks if the expiry date is after or equal to the given date
   * @param minDate The expiry date must be after or equal to this date
   * @param committedInputs The committed inputs
   * @return True if the expiry date is after or equal to the given date, false otherwise
   */
  function isExpiryDateAfterOrEqual(uint256 minDate, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateAfterOrEqual(minDate, ProofType.EXPIRY_DATE, committedInputs);
  }

  /**
   * @notice Checks if the expiry date is after the given date
   * @param minDate The expiry date must be after this date
   * @param committedInputs The committed inputs
   * @return True if the expiry date is after the given date, false otherwise
   */
  function isExpiryDateAfter(uint256 minDate, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateAfterOrEqual(minDate + 1 days, ProofType.EXPIRY_DATE, committedInputs);
  }

  /**
   * @notice Checks if the expiry date is between the given dates
   * @param minDate The expiry date must be after or equal to this date
   * @param maxDate The expiry date must be before or equal to this date
   * @param committedInputs The committed inputs
   * @return True if the expiry date is between the given dates, false otherwise
   */
  function isExpiryDateBetween(uint256 minDate, uint256 maxDate, bytes calldata committedInputs)
    public
    pure
    returns (bool)
  {
    return _isDateBetween(minDate, maxDate, ProofType.EXPIRY_DATE, committedInputs);
  }

  /**
   * @notice Checks if the expiry date is before or equal to the given date
   * @param maxDate The expiry date must be before or equal to this date
   * @param committedInputs The committed inputs
   * @return True if the expiry date is before or equal to the given date, false otherwise
   */
  function isExpiryDateBeforeOrEqual(uint256 maxDate, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateBeforeOrEqual(maxDate, ProofType.EXPIRY_DATE, committedInputs);
  }

  /**
   * @notice Checks if the expiry date is before the given date
   * @param maxDate The expiry date must be before this date
   * @param committedInputs The committed inputs
   * @return True if the expiry date is before the given date, false otherwise
   */
  function isExpiryDateBefore(uint256 maxDate, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateBeforeOrEqual(maxDate - 1 days, ProofType.EXPIRY_DATE, committedInputs);
  }

  /**
   * @notice Checks if the expiry date is equal to the given date
   * @param date The expiry date must be equal to this date
   * @param committedInputs The committed inputs
   * @return True if the expiry date is equal to the given date, false otherwise
   */
  function isExpiryDateEqual(uint256 date, bytes calldata committedInputs) public pure returns (bool) {
    return _isDateBetween(date, date, ProofType.EXPIRY_DATE, committedInputs);
  }

  function isCountryInOrOut(string[] memory countryList, ProofType proofType, bytes calldata committedInputs)
    private
    pure
    returns (bool)
  {
    (string[] memory inputCountryList, uint256 inputCountryListLength) =
      InputsExtractor.getCountryProofInputs(committedInputs, proofType);
    if (countryList.length != inputCountryListLength) {
      return false;
    }
    for (uint256 i = 0; i < inputCountryListLength; i++) {
      if (!StringUtils.equals(countryList[i], inputCountryList[i])) {
        return false;
      }
    }
    return true;
  }

  /**
   * @notice Checks if the nationality is in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * @param committedInputs The committed inputs
   * @return True if the nationality is in the list of countries, false otherwise
   */
  function isNationalityIn(string[] memory countryList, bytes calldata committedInputs) external pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.NATIONALITY_INCLUSION, committedInputs);
  }

  /**
   * @notice Checks if the issuing country is in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * @param committedInputs The committed inputs
   * @return True if the issuing country is in the list of countries, false otherwise
   */
  function isIssuingCountryIn(string[] memory countryList, bytes calldata committedInputs)
    external
    pure
    returns (bool)
  {
    return isCountryInOrOut(countryList, ProofType.ISSUING_COUNTRY_INCLUSION, committedInputs);
  }

  /**
   * @notice Checks if the nationality is not in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * Note: The list of countries must be sorted in alphabetical order
   * @param committedInputs The committed inputs
   * @return True if the nationality is not in the list of countries, false otherwise
   */
  function isNationalityOut(string[] memory countryList, bytes calldata committedInputs) external pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.NATIONALITY_EXCLUSION, committedInputs);
  }

  /**
   * @notice Checks if the issuing country is not in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * Note: The list of countries must be sorted in alphabetical order
   * @param committedInputs The committed inputs
   * @return True if the issuing country is not in the list of countries, false otherwise
   */
  function isIssuingCountryOut(string[] memory countryList, bytes calldata committedInputs)
    external
    pure
    returns (bool)
  {
    return isCountryInOrOut(countryList, ProofType.ISSUING_COUNTRY_EXCLUSION, committedInputs);
  }

  /**
   * @notice Gets the data bound to the proof
   * @param committedInputs The committed inputs
   * @return boundData The data bound to the proof
   */
  function getBoundData(bytes calldata committedInputs) external pure returns (BoundData memory boundData) {
    bytes memory data = InputsExtractor.getBindProofInputs(committedInputs);
    (boundData.senderAddress, boundData.chainId, boundData.customData) = InputsExtractor.getBoundData(data);
  }

  /**
   * @notice Checks if the sanctions root is valid against the expected sanction list(s)
   * @param currentTimestamp The current timestamp (preferably from the proof rather than the block timestamp).
   * This is used to check the validity of the sanctions root at that specific time.
   * @param isStrict Whether the sanctions check was strict or not
   * @param committedInputs The committed inputs
   * @return True if the sanctions root is valid against the expected sanction list(s), false otherwise
   */
  function isSanctionsRootValid(uint256 currentTimestamp, bool isStrict, bytes calldata committedInputs)
    external
    view
    returns (bool)
  {
    return _isSanctionsRootValid(currentTimestamp, isStrict, committedInputs);
  }

  function _isSanctionsRootValid(uint256 currentTimestamp, bool isStrict, bytes calldata committedInputs)
    internal
    view
    returns (bool)
  {
    (bytes32 proofSanctionsRoot, bool retrievedIsStrict) = InputsExtractor.getSanctionsProofInputs(committedInputs);
    require(isStrict == retrievedIsStrict, "Invalid sanctions check mode");
    return rootRegistry.isRootValid(RegistryID.SANCTIONS, proofSanctionsRoot, currentTimestamp);
  }

  /**
   * @notice Enforces that the proof checks against the expected sanction list(s)
   * @param currentTimestamp The current timestamp (preferably from the proof rather than the block timestamp).
   * This is used to check the validity of the sanctions root at that specific time.
   * @param isStrict Whether the sanctions check was strict or not
   * @param committedInputs The committed inputs
   */
  function enforceSanctionsRoot(uint256 currentTimestamp, bool isStrict, bytes calldata committedInputs) external view {
    bool isValid = _isSanctionsRootValid(currentTimestamp, isStrict, committedInputs);
    require(isValid, "Invalid sanctions registry root");
  }

  /**
   * @notice Checks if the proof is tied to a FaceMatch verification
   * @param faceMatchMode The FaceMatch mode expected to be used in the verification
   * @param os The operating system on which the proof should have been generated (Any (0), iOS (1), Android (2))
   * @param committedInputs The committed inputs
   * @return True if the proof is tied to a valid FaceMatch verification, false otherwise
   */
  function isFaceMatchVerified(FaceMatchMode faceMatchMode, OS os, bytes calldata committedInputs)
    external
    pure
    returns (bool)
  {
    (
      bytes32 rootKeyHash,
      Environment environment,
      bytes32 appIdHash,
      bytes32 integrityPublicKeyHash,
      FaceMatchMode retrievedFaceMatchMode
    ) = InputsExtractor.getFacematchProofInputs(committedInputs);
    bool isProduction = environment == Environment.PRODUCTION;
    bool isCorrectMode = retrievedFaceMatchMode == faceMatchMode;
    bool isCorrectRootKeyHash = (rootKeyHash == AppAttest.APPLE_ROOT_KEY_HASH && (os == OS.IOS || os == OS.ANY))
      || (rootKeyHash == AppAttest.GOOGLE_RSA_ROOT_KEY_HASH && (os == OS.ANDROID || os == OS.ANY));
    bool isCorrectAppIdHash = (appIdHash == AppAttest.IOS_APP_ID_HASH && (os == OS.IOS || os == OS.ANY))
      || (appIdHash == AppAttest.ANDROID_APP_ID_HASH && (os == OS.ANDROID || os == OS.ANY));
    // The integrity public key hash is 0 for iOS as it's logic specific to Android
    bool isCorrectIntegrityPublicKeyHash = (integrityPublicKeyHash == bytes32(0) && (os == OS.IOS || os == OS.ANY))
      || (integrityPublicKeyHash == AppAttest.ANDROID_INTEGRITY_PUBLIC_KEY_HASH && (os == OS.ANDROID || os == OS.ANY));
    return
      isProduction && isCorrectMode && isCorrectRootKeyHash && isCorrectAppIdHash && isCorrectIntegrityPublicKeyHash;
  }

  /**
   * @notice Gets the timestamp the proof was generated at
   * @param publicInputs The public inputs of the proof
   * @return The timestamp the proof was generated at
   */
  function getProofTimestamp(bytes32[] calldata publicInputs) external pure returns (uint256) {
    return uint256(publicInputs[PublicInput.CURRENT_DATE_INDEX]);
  }

  /**
   * @notice Verifies that the proof was generated for the given scope (domain) and subscope (service scope)
   * @param publicInputs The public inputs of the proof
   * @param scope The scope (domain) to check against
   * @param subscope The subscope (service scope) to check against
   * @return True if valid, false otherwise
   */
  function verifyScopes(bytes32[] calldata publicInputs, string calldata scope, string calldata subscope)
    external
    pure
    returns (bool)
  {
    // One byte is dropped at the end
    // What we call scope internally is derived from the domain
    bytes32 scopeHash = StringUtils.isEmpty(scope) ? bytes32(0) : sha256(abi.encodePacked(scope)) >> 8;
    // What we call the subscope internally is the service scope specified manually in the SDK
    bytes32 subscopeHash = StringUtils.isEmpty(subscope) ? bytes32(0) : sha256(abi.encodePacked(subscope)) >> 8;
    return
      publicInputs[PublicInput.SCOPE_INDEX] == scopeHash && publicInputs[PublicInput.SUBSCOPE_INDEX] == subscopeHash;
  }
}
