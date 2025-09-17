// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IVerifier} from "../src/ultra-honk-verifiers/OuterCount4.sol";
import {DateUtils} from "../src/DateUtils.sol";
import {StringUtils} from "../src/StringUtils.sol";
import {IRootRegistry} from "../src/IRootRegistry.sol";
import {InputsExtractor} from "../src/InputsExtractor.sol";
import {CommittedInputLen, MRZIndex, MRZLength, SECONDS_BETWEEN_1900_AND_1970, PublicInput} from "../src/Constants.sol";
import {ProofType, ProofVerificationParams, BoundDataIdentifier, DisclosedData, BoundData} from "../src/Types.sol";

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
   * @param params The proof verification parameters
   * @param isIDCard Whether the proof is an ID card
   * @return disclosedData The data disclosed by the proof
   */
  function getDisclosedData(    
    ProofVerificationParams calldata params,
    bool isIDCard
  ) public pure returns (DisclosedData memory disclosedData) {
    (, bytes memory discloseBytes) = InputsExtractor.getDiscloseProofInputs(params.committedInputs, params.committedInputCounts);
    disclosedData = InputsExtractor.getDisclosedData(discloseBytes, isIDCard);
  }

  /**
   * @notice Checks if the age is above or equal to the given age
   * @param minAge The age must be above or equal to this age
   * @param params The proof verification parameters
   * @return True if the age is above or equal to the given age, false otherwise
   */
  function isAgeAboveOrEqual(
    uint8 minAge,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    (uint256 currentDate, uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(params.committedInputs, params.committedInputCounts);
    require(DateUtils.isDateValid(currentDate, params.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(max == 0, "The proof upper bound must be 0, please use isAgeBetween instead");
    return minAge == min;
  }

  /**
   * @notice Checks if the age is above the given age
   * @param minAge The age must be above this age
   * @param params The proof verification parameters
   * @return True if the age is above the given age, false otherwise
   */
  function isAgeAbove(
    uint8 minAge,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isAgeAboveOrEqual(minAge + 1, params);
  }

  /**
   * @notice Checks if the age is in the given range
   * @param minAge The age must be greater than or equal to this age
   * @param maxAge The age must be less than or equal to this age
   * @param params The proof verification parameters
   * @return True if the age is in the given range, false otherwise
   */
  function isAgeBetween(
    uint8 minAge,
    uint8 maxAge,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    (uint256 currentDate, uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(params.committedInputs, params.committedInputCounts);
    require(DateUtils.isDateValid(currentDate, params.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(minAge <= maxAge, "Min age must be less than or equal to max age");
    require(min != 0, "The proof lower bound must be non-zero, please use isAgeBelowOrEqual instead");
    require(max != 0, "The proof upper bound must be non-zero, please use isAgeAboveOrEqual instead");
    return minAge == min && maxAge == max;
  }

  /**
   * @notice Checks if the age is below or equal to the given age
   * @param maxAge The age must be below or equal to this age
   * @param params The proof verification parameters
   * @return True if the age is below or equal to the given age, false otherwise
   */
  function isAgeBelowOrEqual(
    uint8 maxAge,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    (uint256 currentDate, uint8 min, uint8 max) = InputsExtractor.getAgeProofInputs(params.committedInputs, params.committedInputCounts);
    require(DateUtils.isDateValid(currentDate, params.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(min == 0, "The proof lower bound must be 0, please use isAgeBetween instead");
    return maxAge == max;
  }

  /**
   * @notice Checks if the age is below the given age
   * @param maxAge The age must be below this age
   * @param params The proof verification parameters
   * @return True if the age is below the given age, false otherwise
   */
  function isAgeBelow(
    uint8 maxAge,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    require(maxAge > 0, "Max age must be greater than 0");
    return isAgeBelowOrEqual(maxAge - 1, params);
  }

  /**
   * @notice Checks if the age is equal to the given age
   * @param age The age must be equal to this age
   * @param params The proof verification parameters
   * @return True if the age is equal to the given age, false otherwise
   */
  function isAgeEqual(
    uint8 age,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isAgeBetween(age, age, params);
  }

  function isDateAfterOrEqual(
    uint256 minDate,
    ProofType proofType,
    ProofVerificationParams calldata params
  ) private view returns (bool) {
    (uint256 currentDate, uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(params.committedInputs, params.committedInputCounts, proofType);
    require(DateUtils.isDateValid(currentDate, params.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(proofType == ProofType.BIRTHDATE || proofType == ProofType.EXPIRY_DATE, "Invalid proof type");
    if (proofType == ProofType.BIRTHDATE) {
      require(max == 0, "The proof upper bound must be 0, please use isBirthdateBetween instead");
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
    ProofVerificationParams calldata params
  ) private view returns (bool) {
    (uint256 currentDate, uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(params.committedInputs, params.committedInputCounts, proofType);
    require(DateUtils.isDateValid(currentDate, params.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(minDate <= maxDate, "Min date must be less than or equal to max date");
    require(proofType == ProofType.BIRTHDATE || proofType == ProofType.EXPIRY_DATE, "Invalid proof type");
    if (proofType == ProofType.BIRTHDATE) {
      require(min != 0, "The proof lower bound must be non-zero, please use isBirthdateBelowOrEqual instead");
      require(max != 0, "The proof upper bound must be non-zero, please use isBirthdateAboveOrEqual instead");
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
    ProofVerificationParams calldata params
  ) private view returns (bool) {
    (uint256 currentDate, uint256 min, uint256 max) = InputsExtractor.getDateProofInputs(params.committedInputs, params.committedInputCounts, proofType);
    require(DateUtils.isDateValid(currentDate, params.validityPeriodInSeconds), "The current date used in the proof does not fall within the validity period");
    require(min == 0, "The proof lower bound must be 0, please use isDateBetween instead");
    require(proofType == ProofType.BIRTHDATE || proofType == ProofType.EXPIRY_DATE, "Invalid proof type");
    if (proofType == ProofType.BIRTHDATE) {
      require(max != 0, "The proof upper bound must be non-zero, please use isBirthdateAboveOrEqual instead");
      return maxDate == max - SECONDS_BETWEEN_1900_AND_1970;
    } else {
      require(max != 0, "The proof upper bound must be non-zero, please use isExpiryDateAboveOrEqual instead");
      return maxDate == max;
    }
  }

  /**
   * @notice Checks if the birthdate is after or equal to the given date
   * @param minDate The birthdate must be after or equal to this date
   * @param params The proof verification parameters
   * @return True if the birthdate is after or equal to the given date, false otherwise
   */
  function isBirthdateAfterOrEqual(
    uint256 minDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateAfterOrEqual(minDate, ProofType.BIRTHDATE, params);
  }

  /**
   * @notice Checks if the birthdate is after the given date
   * @param minDate The birthdate must be after this date
   * @param params The proof verification parameters
   * @return True if the birthdate is after the given date, false otherwise
   */
  function isBirthdateAfter(
    uint256 minDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateAfterOrEqual(minDate + 1 days, ProofType.BIRTHDATE, params);
  }

  /**
   * @notice Checks if the birthdate is between the given dates
   * @param minDate The birthdate must be after or equal to this date
   * @param maxDate The birthdate must be before or equal to this date
   * @param params The proof verification parameters
   * @return True if the birthdate is between the given dates, false otherwise
   */
  function isBirthdateBetween(
    uint256 minDate,
    uint256 maxDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateBetween(minDate, maxDate, ProofType.BIRTHDATE, params);
  }

  /**
   * @notice Checks if the birthdate is before or equal to the given date
   * @param maxDate The birthdate must be before or equal to this date
   * @param params The proof verification parameters
   * @return True if the birthdate is before or equal to the given date, false otherwise
   */
  function isBirthdateBeforeOrEqual(
    uint256 maxDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateBeforeOrEqual(maxDate, ProofType.BIRTHDATE, params);
  }

  /**
   * @notice Checks if the birthdate is before the given date
   * @param maxDate The birthdate must be before this date
   * @param params The proof verification parameters
   * @return True if the birthdate is before the given date, false otherwise
   */
  function isBirthdateBefore(
    uint256 maxDate,
      ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateBeforeOrEqual(maxDate - 1 days, ProofType.BIRTHDATE, params);
  }

  /**
   * @notice Checks if the birthdate is equal to the given date
   * @param date The birthdate must be equal to this date
   * @param params The proof verification parameters
   * @return True if the birthdate is equal to the given date, false otherwise
   */
  function isBirthdateEqual(
    uint256 date,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateBetween(date, date, ProofType.BIRTHDATE, params);
  }

  /**
   * @notice Checks if the expiry date is after or equal to the given date
   * @param minDate The expiry date must be after or equal to this date
   * @param params The proof verification parameters
   * @return True if the expiry date is after or equal to the given date, false otherwise
   */
  function isExpiryDateAfterOrEqual(
    uint256 minDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateAfterOrEqual(minDate, ProofType.EXPIRY_DATE, params);
  }

  /**
   * @notice Checks if the expiry date is after the given date
   * @param minDate The expiry date must be after this date
   * @param params The proof verification parameters
   * @return True if the expiry date is after the given date, false otherwise
   */
  function isExpiryDateAfter(
    uint256 minDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateAfterOrEqual(minDate + 1 days, ProofType.EXPIRY_DATE, params);
  }

  /**
   * @notice Checks if the expiry date is between the given dates
   * @param minDate The expiry date must be after or equal to this date
   * @param maxDate The expiry date must be before or equal to this date
   * @param params The proof verification parameters
   * @return True if the expiry date is between the given dates, false otherwise
   */
  function isExpiryDateBetween(
    uint256 minDate,
    uint256 maxDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateBetween(minDate, maxDate, ProofType.EXPIRY_DATE, params);
  }

  /**
   * @notice Checks if the expiry date is before or equal to the given date
   * @param maxDate The expiry date must be before or equal to this date
   * @param params The proof verification parameters
   * @return True if the expiry date is before or equal to the given date, false otherwise
   */
  function isExpiryDateBeforeOrEqual(
    uint256 maxDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateBeforeOrEqual(maxDate, ProofType.EXPIRY_DATE, params);
  }

  /**
   * @notice Checks if the expiry date is before the given date
   * @param maxDate The expiry date must be before this date
   * @param params The proof verification parameters
   * @return True if the expiry date is before the given date, false otherwise
   */
  function isExpiryDateBefore(
    uint256 maxDate,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateBeforeOrEqual(maxDate - 1 days, ProofType.EXPIRY_DATE, params);
  }

  /**
   * @notice Checks if the expiry date is equal to the given date
   * @param date The expiry date must be equal to this date
   * @param params The proof verification parameters
   * @return True if the expiry date is equal to the given date, false otherwise
   */
  function isExpiryDateEqual(
    uint256 date,
    ProofVerificationParams calldata params
  ) public view returns (bool) {
    return isDateBetween(date, date, ProofType.EXPIRY_DATE, params);
  }

  function isCountryInOrOut(
    string[] memory countryList,
    ProofType proofType,
    ProofVerificationParams calldata params
  ) private pure returns (bool) {
    (string[] memory inputCountryList, uint256 inputCountryListLength) = InputsExtractor.getCountryProofInputs(params.committedInputs, params.committedInputCounts, proofType);
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
   * @param params The proof verification parameters
   * @return True if the nationality is in the list of countries, false otherwise
   */
  function isNationalityIn(
    string[] memory countryList,
    ProofVerificationParams calldata params
  ) public pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.NATIONALITY_INCLUSION, params);
  }

  /**
   * @notice Checks if the issuing country is in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * @param params The proof verification parameters
   * @return True if the issuing country is in the list of countries, false otherwise
   */
  function isIssuingCountryIn(
    string[] memory countryList,
    ProofVerificationParams calldata params
  ) public pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.ISSUING_COUNTRY_INCLUSION, params);
  }

  /**
   * @notice Checks if the nationality is not in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * Note: The list of countries must be sorted in alphabetical order
   * @param params The proof verification parameters
   * @return True if the nationality is not in the list of countries, false otherwise
   */
  function isNationalityOut(
    string[] memory countryList,
    ProofVerificationParams calldata params
  ) public pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.NATIONALITY_EXCLUSION, params);
  }

  /**
   * @notice Checks if the issuing country is not in the list of countries
   * @param countryList The list of countries (needs to match exactly the list of countries in the proof)
   * Note: The list of countries must be sorted in alphabetical order
   * @param params The proof verification parameters
   * @return True if the issuing country is not in the list of countries, false otherwise
   */
  function isIssuingCountryOut(
    string[] memory countryList,
    ProofVerificationParams calldata params
  ) public pure returns (bool) {
    return isCountryInOrOut(countryList, ProofType.ISSUING_COUNTRY_EXCLUSION, params);
  }

  /**
   * @notice Gets the data bound to the proof
   * @param params The proof verification parameters
   * @return boundData The data bound to the proof
   */
  function getBoundData(
    ProofVerificationParams calldata params
  ) public pure returns (BoundData memory boundData) {
    bytes memory data = InputsExtractor.getBindProofInputs(params.committedInputs, params.committedInputCounts);
    (boundData.senderAddress, boundData.chainId, boundData.customData) = InputsExtractor.getBoundData(data);
  }

  /**
   * @notice Enforces that the proof checks against the expected sanction list(s)
   * @param params The proof verification parameters
   */
  function enforceSanctionsRoot(
    ProofVerificationParams calldata params
  ) public view {
    bytes32 proofSanctionsRoot = InputsExtractor.getSanctionsProofInputs(params.committedInputs, params.committedInputCounts);
    _validateSanctionsRoot(proofSanctionsRoot);
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
    bytes calldata committedInputs,
    uint256[] memory committedInputCounts
  ) internal pure {
    uint256 offset = 0;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // One byte is dropped inside the circuit as BN254 is limited to 254 bits
      bytes32 calculatedCommitment = sha256(
        abi.encodePacked(committedInputs[offset:offset + committedInputCounts[i]])
      ) >> 8;
      require(calculatedCommitment == paramCommitments[i], "Invalid commitment");
      offset += committedInputCounts[i];
    }
    // Check that all the committed inputs have been covered, otherwise something is wrong
    require(offset == committedInputs.length, "Invalid committed inputs length");
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
    address verifier = _getVerifier(params.vkeyHash);

    // Validate certificate registry root
    _validateCertificateRoot(params.publicInputs[PublicInput.CERTIFICATE_REGISTRY_ROOT_INDEX]);

    // Validate circuit registry root
    _validateCircuitRoot(params.publicInputs[PublicInput.CIRCUIT_REGISTRY_ROOT_INDEX]);

    // Checks the date of the proof
    require(
      checkDate(params.publicInputs, params.validityPeriodInSeconds),
      "The proof was generated outside the validity period"
    );

    // Validate scopes if provided
    // It is recommended to verify this against static variables in your contract
    // by calling the verifyScopes function directly or setting domain and scope in the params
    // inside your smart contract function before calling verifyProof
    // Check SampleContract.sol for an example
    require(verifyScopes(params.publicInputs, params.domain, params.scope), "Invalid domain or scope");

    // Verifies the commitments against the committed inputs
    verifyCommittedInputs(
      // Extracts the commitments from the public inputs
      params.publicInputs[PublicInput.PARAM_COMMITMENTS_INDEX:params.publicInputs.length - 1],
      params.committedInputs,
      params.committedInputCounts
    );

    // Allow mock proofs in dev mode
    // Mock proofs are recognisable by their unique identifier set to 1
    // Note: On mainnets, this stage won't be reached as the ZKR certificates will not be part
    // of the mainnet registries and the verification will fail at _validateCertificateRoot
    require(
      params.publicInputs[params.publicInputs.length - 1] != bytes32(uint256(1)) || params.devMode,
      "Mock proofs are only allowed in dev mode"
    );

    // Make sure the committedInputCounts length matches the number of param commitments in the public inputs
    // to ensure all the param commitments are covered
    require(params.committedInputCounts.length == params.publicInputs.length - PublicInput.PUBLIC_INPUTS_BEFORE_PARAM_COMMITMENTS_LENGTH, "Invalid committed input counts length");

    // Call the UltraHonk verifier for the given Outer Circuit to verify if the actual proof is valid
    isValid = IVerifier(verifier).verify(params.proof, params.publicInputs);

    // Get the unique identifier from the public inputs
    uint256 uniqueIdentifierIndex = params.publicInputs.length - 1;
    uniqueIdentifier = params.publicInputs[uniqueIdentifierIndex];

    // Not actually needed but it makes it clearer what is returned
    return (isValid, uniqueIdentifier);
  }
}
