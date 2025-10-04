// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IVerifier} from "../src/ultra-honk-verifiers/OuterCount4.sol";
import {DateUtils} from "../src/DateUtils.sol";
import {StringUtils} from "../src/StringUtils.sol";
import {IRootRegistry} from "../src/IRootRegistry.sol";
import {InputsExtractor} from "../src/InputsExtractor.sol";
import {CommittedInputLen, MRZIndex, MRZLength, SECONDS_BETWEEN_1900_AND_1970, PublicInput, AppAttest} from "../src/Constants.sol";
import {ProofType, ProofVerificationParams, BoundDataIdentifier, DisclosedData, BoundData, FaceMatchMode, Environment, NullifierType, Commitments, ServiceConfig, OS} from "../src/Types.sol";

contract ZKPassportVerifier {
  bytes32 public constant CERTIFICATE_REGISTRY_ID = bytes32(uint256(1));
  bytes32 public constant CIRCUIT_REGISTRY_ID = bytes32(uint256(2));
  bytes32 public constant SANCTIONS_REGISTRY_ID = bytes32(uint256(3));

  address public admin;
  bool public paused;

  // Mapping from vkey hash of each Outer Circuit to its Ultra Honk Verifier address
  mapping(bytes32 => address) public vkeyHashToVerifier;

  // Maybe make this immutable as this should most likely not change
  IRootRegistry public rootRegistry;

  // Events
  event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
  event PausedStatusChanged(bool paused);
  event ZKPassportVerifierDeployed(address indexed admin, uint256 timestamp);
  event VerifierAdded(bytes32 indexed vkeyHash, address indexed verifier);
  event VerifierRemoved(bytes32 indexed vkeyHash);
  event CertificateRegistryRootAdded(bytes32 indexed certificateRegistryRoot);
  event CertificateRegistryRootRemoved(bytes32 indexed certificateRegistryRoot);
  event SanctionsTreesRootUpdates(bytes32 indexed _sanctionsTreesRoot);

  /**
   * @dev Constructor
   */
  constructor(address _rootRegistry) {
    require(_rootRegistry != address(0), "Root registry cannot be zero address");
    admin = msg.sender;
    rootRegistry = IRootRegistry(_rootRegistry);
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

  function addVerifiers(
    bytes32[] calldata vkeyHashes,
    address[] calldata verifiers
  ) external onlyAdmin {
    for (uint256 i = 0; i < vkeyHashes.length; i++) {
      vkeyHashToVerifier[vkeyHashes[i]] = verifiers[i];
      emit VerifierAdded(vkeyHashes[i], verifiers[i]);
    }
  }

  function removeVerifiers(bytes32[] calldata vkeyHashes) external onlyAdmin {
    for (uint256 i = 0; i < vkeyHashes.length; i++) {
      delete vkeyHashToVerifier[vkeyHashes[i]];
      emit VerifierRemoved(vkeyHashes[i]);
    }
  }

  function updateRootRegistry(address _rootRegistry) external onlyAdmin {
    require(_rootRegistry != address(0), "Root registry cannot be zero address");
    rootRegistry = IRootRegistry(_rootRegistry);
  }

  function checkDate(
    bytes32[] memory publicInputs,
    uint256 validityPeriodInSeconds
  ) internal view returns (bool) {
    uint256 currentDateTimeStamp = uint256(publicInputs[PublicInput.CURRENT_DATE_INDEX]);
    return DateUtils.isDateValid(currentDateTimeStamp, validityPeriodInSeconds);
  }

  /**
   * @notice Gets the data disclosed by the proof
   * @param commitments The commitments
   * @param isIDCard Whether the proof is an ID card
   * @return disclosedData The data disclosed by the proof
   */
  function getDisclosedData(    
    Commitments calldata commitments,
    bool isIDCard
  ) public pure returns (DisclosedData memory disclosedData) {
    (, bytes memory discloseBytes) = InputsExtractor.getDiscloseProofInputs(commitments);
    disclosedData = InputsExtractor.getDisclosedData(discloseBytes, isIDCard);
  }

  /**
   * @notice Checks if the age is above or equal to the given age
   * @param minAge The age must be above or equal to this age
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the age is above or equal to the given age, false otherwise
   */
  function isAgeAboveOrEqual(
    uint8 minAge,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    (uint256 currentDate, uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(commitments);
    require(DateUtils.isDateValid(currentDate, serviceConfig.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(max == 0, "The proof upper bound must be 0, please use isAgeBetween instead");
    return minAge == min;
  }

  /**
   * @notice Checks if the age is above the given age
   * @param minAge The age must be above this age
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the age is above the given age, false otherwise
   */
  function isAgeAbove(
    uint8 minAge,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isAgeAboveOrEqual(minAge + 1, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the age is in the given range
   * @param minAge The age must be greater than or equal to this age
   * @param maxAge The age must be less than or equal to this age
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the age is in the given range, false otherwise
   */
  function isAgeBetween(
    uint8 minAge,
    uint8 maxAge,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    (uint256 currentDate, uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(commitments);
    require(DateUtils.isDateValid(currentDate, serviceConfig.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(minAge <= maxAge, "Min age must be less than or equal to max age");
    require(min != 0, "The proof lower bound must be non-zero, please use isAgeBelowOrEqual instead");
    require(max != 0, "The proof upper bound must be non-zero, please use isAgeAboveOrEqual instead");
    return minAge == min && maxAge == max;
  }

  /**
   * @notice Checks if the age is below or equal to the given age
   * @param maxAge The age must be below or equal to this age
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the age is below or equal to the given age, false otherwise
   */
  function isAgeBelowOrEqual(
    uint8 maxAge,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    (uint256 currentDate, uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(commitments);
    require(DateUtils.isDateValid(currentDate, serviceConfig.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(min == 0, "The proof lower bound must be 0, please use isAgeBetween instead");
    return maxAge == max;
  }

  /**
   * @notice Checks if the age is below the given age
   * @param maxAge The age must be below this age
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the age is below the given age, false otherwise
   */
  function isAgeBelow(
    uint8 maxAge,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    require(maxAge > 0, "Max age must be greater than 0");
    return isAgeBelowOrEqual(maxAge - 1, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the age is equal to the given age
   * @param age The age must be equal to this age
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the age is equal to the given age, false otherwise
   */
  function isAgeEqual(
    uint8 age,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isAgeBetween(age, age, commitments, serviceConfig);
  }

  function isDateAfterOrEqual(
    uint256 minDate,
    ProofType proofType,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) private view returns (bool) {
    (uint256 currentDate, uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(commitments, proofType);
    require(DateUtils.isDateValid(currentDate, serviceConfig.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
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

  function isDateBetween(
    uint256 minDate,
    uint256 maxDate,
    ProofType proofType,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) private view returns (bool) {
    (uint256 currentDate, uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(commitments, proofType);
    require(DateUtils.isDateValid(currentDate, serviceConfig.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
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

  function isDateBeforeOrEqual(
    uint256 maxDate,
    ProofType proofType,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) private view returns (bool) {
    (uint256 currentDate, uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(commitments, proofType);
    require(DateUtils.isDateValid(currentDate, serviceConfig.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(min == 0, "The proof lower bound must be 0, please use isDateBetween instead");
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
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the birthdate is after or equal to the given date, false otherwise
   */
  function isBirthdateAfterOrEqual(
    uint256 minDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateAfterOrEqual(minDate, ProofType.BIRTHDATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the birthdate is after the given date
   * @param minDate The birthdate must be after this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the birthdate is after the given date, false otherwise
   */
  function isBirthdateAfter(
    uint256 minDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateAfterOrEqual(minDate + 1 days, ProofType.BIRTHDATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the birthdate is between the given dates
   * @param minDate The birthdate must be after or equal to this date
   * @param maxDate The birthdate must be before or equal to this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the birthdate is between the given dates, false otherwise
   */
  function isBirthdateBetween(
    uint256 minDate,
    uint256 maxDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateBetween(minDate, maxDate, ProofType.BIRTHDATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the birthdate is before or equal to the given date
   * @param maxDate The birthdate must be before or equal to this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the birthdate is before or equal to the given date, false otherwise
   */
  function isBirthdateBeforeOrEqual(
    uint256 maxDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateBeforeOrEqual(maxDate, ProofType.BIRTHDATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the birthdate is before the given date
   * @param maxDate The birthdate must be before this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the birthdate is before the given date, false otherwise
   */
  function isBirthdateBefore(
    uint256 maxDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateBeforeOrEqual(maxDate - 1 days, ProofType.BIRTHDATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the birthdate is equal to the given date
   * @param date The birthdate must be equal to this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the birthdate is equal to the given date, false otherwise
   */
  function isBirthdateEqual(
    uint256 date,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateBetween(date, date, ProofType.BIRTHDATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the expiry date is after or equal to the given date
   * @param minDate The expiry date must be after or equal to this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the expiry date is after or equal to the given date, false otherwise
   */
  function isExpiryDateAfterOrEqual(
    uint256 minDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateAfterOrEqual(minDate, ProofType.EXPIRY_DATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the expiry date is after the given date
   * @param minDate The expiry date must be after this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the expiry date is after the given date, false otherwise
   */
  function isExpiryDateAfter(
    uint256 minDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateAfterOrEqual(minDate + 1 days, ProofType.EXPIRY_DATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the expiry date is between the given dates
   * @param minDate The expiry date must be after or equal to this date
   * @param maxDate The expiry date must be before or equal to this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the expiry date is between the given dates, false otherwise
   */
  function isExpiryDateBetween(
    uint256 minDate,
    uint256 maxDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateBetween(minDate, maxDate, ProofType.EXPIRY_DATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the expiry date is before or equal to the given date
   * @param maxDate The expiry date must be before or equal to this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the expiry date is before or equal to the given date, false otherwise
   */
  function isExpiryDateBeforeOrEqual(
    uint256 maxDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateBeforeOrEqual(maxDate, ProofType.EXPIRY_DATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the expiry date is before the given date
   * @param maxDate The expiry date must be before this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the expiry date is before the given date, false otherwise
   */
  function isExpiryDateBefore(
    uint256 maxDate,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateBeforeOrEqual(maxDate - 1 days, ProofType.EXPIRY_DATE, commitments, serviceConfig);
  }

  /**
   * @notice Checks if the expiry date is equal to the given date
   * @param date The expiry date must be equal to this date
   * @param commitments The commitments
   * @param serviceConfig The service config
   * @return True if the expiry date is equal to the given date, false otherwise
   */
  function isExpiryDateEqual(
    uint256 date,
    Commitments calldata commitments,
    ServiceConfig calldata serviceConfig
  ) public view returns (bool) {
    return isDateBetween(date, date, ProofType.EXPIRY_DATE, commitments, serviceConfig);
  }

  function isCountryInOrOut(
    string[] memory countryList,
    ProofType proofType,
    Commitments calldata commitments
  ) private pure returns (bool) {
    (string[] memory inputCountryList, uint256 inputCountryListLength) = InputsExtractor.getCountryProofInputs(commitments, proofType);
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
   * @param commitments The commitments
   * @return True if the nationality is in the list of countries, false otherwise
   */
  function isNationalityIn(
    string[] memory countryList,
    Commitments calldata commitments
  ) public pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.NATIONALITY_INCLUSION, commitments);
  }

  /**
   * @notice Checks if the issuing country is in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * @param commitments The commitments
   * @return True if the issuing country is in the list of countries, false otherwise
   */
  function isIssuingCountryIn(
    string[] memory countryList,
    Commitments calldata commitments
  ) public pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.ISSUING_COUNTRY_INCLUSION, commitments);
  }

  /**
   * @notice Checks if the nationality is not in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * Note: The list of countries must be sorted in alphabetical order
   * @param commitments The commitments
   * @return True if the nationality is not in the list of countries, false otherwise
   */
  function isNationalityOut(
    string[] memory countryList,
    Commitments calldata commitments
  ) public pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.NATIONALITY_EXCLUSION, commitments);
  }

  /**
   * @notice Checks if the issuing country is not in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * Note: The list of countries must be sorted in alphabetical order
   * @param commitments The commitments
   * @return True if the issuing country is not in the list of countries, false otherwise
   */
  function isIssuingCountryOut(
    string[] memory countryList,
    Commitments calldata commitments
  ) public pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.ISSUING_COUNTRY_EXCLUSION, commitments);
  }

  /**
   * @notice Gets the data bound to the proof
   * @param commitments The commitments
   * @return boundData The data bound to the proof
   */
  function getBoundData(
    Commitments calldata commitments
  ) public pure returns (BoundData memory boundData) {
    bytes memory data = InputsExtractor.getBindProofInputs(commitments);
    (boundData.senderAddress, boundData.chainId, boundData.customData) = InputsExtractor.getBoundData(data);
  }

  /**
   * @notice Enforces that the proof checks against the expected sanction list(s)
   * @param commitments The commitments
   */
  function enforceSanctionsRoot(
    Commitments calldata commitments
  ) public view {
    bytes32 proofSanctionsRoot = InputsExtractor.getSanctionsProofInputs(commitments);
    _validateSanctionsRoot(proofSanctionsRoot);
  }

  /**
   * @notice Checks if the proof is tied to a FaceMatch verification
   * @param faceMatchMode The FaceMatch mode expected to be used in the verification
   * @param os The operating system on which the proof should have been generated (Any (0), iOS (1), Android (2))
   * @param commitments The commitments
   * @return True if the proof is tied to a valid FaceMatch verification, false otherwise
   */
  function isFaceMatchVerified(
    FaceMatchMode faceMatchMode,
    OS os,
    Commitments calldata commitments
  ) public pure returns (bool) {
    (bytes32 rootKeyHash, Environment environment, bytes32 appId, FaceMatchMode retrievedFaceMatchMode) = InputsExtractor.getFacematchProofInputs(commitments);
    bool isProduction = environment == Environment.PRODUCTION;
    bool isCorrectMode = retrievedFaceMatchMode == faceMatchMode;
    bool isCorrectRootKeyHash = (rootKeyHash == AppAttest.APPLE_ROOT_KEY_HASH && (os == OS.IOS || os == OS.ANY)) || (rootKeyHash == AppAttest.GOOGLE_RSA_ROOT_KEY_HASH && (os == OS.ANDROID || os == OS.ANY));
    bool isCorrectAppIdHash = (appId == AppAttest.IOS_APP_ID_HASH && (os == OS.IOS || os == OS.ANY)) || (appId == AppAttest.ANDROID_APP_ID_HASH && (os == OS.ANDROID || os == OS.ANY));
    return isProduction && isCorrectMode && isCorrectRootKeyHash && isCorrectAppIdHash;
  }

  /**
   * @notice Verifies that the proof was generated for the given domain and scope
   * @param publicInputs The public inputs of the proof
   * @param domain The domain to check against
   * @param scope The scope to check against
   * @return True if the proof was generated for the given domain and scope, false otherwise
   */
  function verifyScopes(
    bytes32[] calldata publicInputs,
    string calldata domain,
    string calldata scope
  ) public pure returns (bool) {
    // One byte is dropped at the end
    // What we call scope internally is derived from the domain
    bytes32 scopeHash = StringUtils.isEmpty(domain)
      ? bytes32(0)
      : sha256(abi.encodePacked(domain)) >> 8;
    // What we call the subscope internally is the scope specified
    // manually in the SDK
    bytes32 subscopeHash = StringUtils.isEmpty(scope)
      ? bytes32(0)
      : sha256(abi.encodePacked(scope)) >> 8;
    return publicInputs[PublicInput.SCOPE_INDEX] == scopeHash && publicInputs[PublicInput.SUBSCOPE_INDEX] == subscopeHash;
  }

  function verifyCommittedInputs(
    bytes32[] memory paramCommitments,
    Commitments calldata commitments
  ) internal pure {
    uint256 offset = 0;
    for (uint256 i = 0; i < commitments.committedInputCounts.length; i++) {
      // One byte is dropped inside the circuit as BN254 is limited to 254 bits
      bytes32 calculatedCommitment = sha256(
        abi.encodePacked(commitments.committedInputs[offset:offset + commitments.committedInputCounts[i]])
      ) >> 8;
      require(calculatedCommitment == paramCommitments[i], "Invalid commitment");
      offset += commitments.committedInputCounts[i];
    }
    // Check that all the committed inputs have been covered, otherwise something is wrong
    require(offset == commitments.committedInputs.length, "Invalid committed inputs length");
  }

  function _getVerifier(bytes32 vkeyHash) internal view returns (address) {
    address verifier = vkeyHashToVerifier[vkeyHash];
    require(verifier != address(0), "Verifier not found");
    return verifier;
  }

  function _validateCertificateRoot(bytes32 certificateRoot) internal view {
    require(
      rootRegistry.isRootValid(CERTIFICATE_REGISTRY_ID, certificateRoot),
      "Invalid certificate registry root"
    );
  }

  function _validateCircuitRoot(bytes32 circuitRoot) internal view {
    require(
      rootRegistry.isRootValid(CIRCUIT_REGISTRY_ID, circuitRoot),
      "Invalid circuit registry root"
    );
  }

  function _validateSanctionsRoot(bytes32 sanctionsRoot) internal view {
    require(
      rootRegistry.isRootValid(SANCTIONS_REGISTRY_ID, sanctionsRoot),
      "Invalid sanctions registry root"
    );
  }

  /**
   * @notice Verifies a proof from ZKPassport
   * @param params The proof verification parameters
   * @return isValid True if the proof is valid, false otherwise
   * @return uniqueIdentifier The unique identifier associated to the identity document that generated the proof
   */
  function verifyProof(
    ProofVerificationParams calldata params
  ) external view whenNotPaused returns (bool isValid, bytes32 uniqueIdentifier) {
    // Get the verifier for the Outer Circuit corresponding to the vkey hash
    address verifier = _getVerifier(params.proofVerificationData.vkeyHash);

    // Validate certificate registry root
    _validateCertificateRoot(params.proofVerificationData.publicInputs[PublicInput.CERTIFICATE_REGISTRY_ROOT_INDEX]);

    // Validate circuit registry root
    _validateCircuitRoot(params.proofVerificationData.publicInputs[PublicInput.CIRCUIT_REGISTRY_ROOT_INDEX]);

    // Checks the date of the proof
    require(
      checkDate(params.proofVerificationData.publicInputs, params.serviceConfig.validityPeriodInSeconds),
      "The proof was generated outside the validity period"
    );

    // Validate scopes if provided
    // It is recommended to verify this against static variables in your contract
    // by calling the verifyScopes function directly or setting domain and scope in the params
    // inside your smart contract function before calling verifyProof
    // Check SampleContract.sol for an example
    require(verifyScopes(params.proofVerificationData.publicInputs, params.serviceConfig.domain, params.serviceConfig.scope), "Invalid domain or scope");

    // Verifies the commitments against the committed inputs
    verifyCommittedInputs(
      // Extracts the commitments from the public inputs
      params.proofVerificationData.publicInputs[PublicInput.PARAM_COMMITMENTS_INDEX:params.proofVerificationData.publicInputs.length - 1],
      params.commitments
    );

    NullifierType nullifierType = NullifierType(uint256(params.proofVerificationData.publicInputs[params.proofVerificationData.publicInputs.length - 2]));

    // Allow mock proofs in dev mode
    // Note: On mainnets, this stage won't be reached as the ZKR certificates will not be part
    // of the mainnet registries and the verification will fail at _validateCertificateRoot
    require(
      (nullifierType != NullifierType.NON_SALTED_MOCK_NULLIFIER && nullifierType != NullifierType.SALTED_MOCK_NULLIFIER)
      || params.serviceConfig.devMode,
      "Mock proofs are only allowed in dev mode"
    );
    
    // For now, only non-salted nullifiers are supported
    // but salted nullifiers can be used in dev mode
    // They will be later once a proper registration mechanism is implemented
    require(
      nullifierType == NullifierType.NON_SALTED_NULLIFIER || params.serviceConfig.devMode,
      "Salted nullifiers are not supported for now"
    );

    // Make sure the committedInputCounts length matches the number of param commitments in the public inputs
    // to ensure all the param commitments are covered
    require(params.commitments.committedInputCounts.length == params.proofVerificationData.publicInputs.length - PublicInput.PUBLIC_INPUTS_EXCLUDING_PARAM_COMMITMENTS_LENGTH, "Invalid committed input counts length");

    // Call the UltraHonk verifier for the given Outer Circuit to verify if the actual proof is valid
    isValid = IVerifier(verifier).verify(params.proofVerificationData.proof, params.proofVerificationData.publicInputs);

    // Get the unique identifier from the public inputs
    uint256 uniqueIdentifierIndex = params.proofVerificationData.publicInputs.length - 1;
    uniqueIdentifier = params.proofVerificationData.publicInputs[uniqueIdentifierIndex];

    // Not actually needed but it makes it clearer what is returned
    return (isValid, uniqueIdentifier);
  }
}
