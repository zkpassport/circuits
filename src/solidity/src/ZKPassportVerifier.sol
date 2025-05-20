// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IVerifier} from "../src/OuterCount4.sol";
import {DateUtils} from "../src/DateUtils.sol";
import {StringUtils} from "../src/StringUtils.sol";
import {ArrayUtils} from "../src/ArrayUtils.sol";
import {IRootRegistry} from "../src/IRootRegistry.sol";

enum ProofType {
  DISCLOSE,
  AGE,
  BIRTHDATE,
  EXPIRY_DATE,
  NATIONALITY_INCLUSION,
  NATIONALITY_EXCLUSION,
  ISSUING_COUNTRY_INCLUSION,
  ISSUING_COUNTRY_EXCLUSION,
  BIND
}

enum BoundDataIdentifier {
  NONE,
  USER_ADDRESS,
  CUSTOM_DATA
}

// Add this struct to group parameters
struct ProofVerificationParams {
  bytes32 vkeyHash;
  bytes proof;
  bytes32[] publicInputs;
  bytes committedInputs;
  uint256[] committedInputCounts;
  uint256 validityPeriodInDays;
  string scope;
  string subscope;
  bool devMode;
}

contract ZKPassportVerifier {
  // Constants
  // Index for the country of issuance of the passport
  uint256 constant PASSPORT_MRZ_COUNTRY_INDEX = 2;
  // Index for the three letter code of the country of citizenship
  // Note that the first three letter code (index 2) in the MRZ is the country of issuance
  // not citizenship. It is important to keep in mind for residence permits
  // where the issuing country differs from the citizenship country
  uint256 constant PASSPORT_MRZ_NATIONALITY_INDEX = 54;
  // Index for the gender of the passport holder (M, F or < if unspecified)
  uint256 constant PASSPORT_MRZ_GENDER_INDEX = 64;
  // Index for the date of expiry (YYMMDD)
  uint256 constant PASSPORT_MRZ_EXPIRY_DATE_INDEX = 65;
  // Index for the date of birth (YYMMDD) in TD1 (i.e. passport) MRZ
  uint256 constant PASSPORT_MRZ_BIRTHDATE_INDEX = 57;
  // Index for the document number in the MRZ
  uint256 constant PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX = 44;
  // Index for the document type in the MRZ
  uint256 constant PASSPORT_MRZ_DOCUMENT_TYPE_INDEX = 0;
  // Index for the name of the passport holder
  uint256 constant PASSPORT_MRZ_NAME_INDEX = 5;
  // Length of the MRZ on a passport
  uint256 constant PASSPORT_MRZ_LENGTH = 88;

  // Index for the country of issuance of the ID card
  uint256 constant ID_CARD_MRZ_COUNTRY_INDEX = 2;
  // Note that the first three letter code (index 2) in the MRZ is the country of issuance
  // not citizenship. It is important to keep in mind for residence permits
  // where the issuing country differs from the citizenship country
  uint256 constant ID_CARD_MRZ_NATIONALITY_INDEX = 45;
  // Index for the gender of the passport holder (M, F or < if unspecified)
  uint256 constant ID_CARD_MRZ_GENDER_INDEX = 37;
  // Index for the date of expiry (YYMMDD)
  uint256 constant ID_CARD_MRZ_EXPIRY_DATE_INDEX = 38;
  // Index for the date of birth (YYMMDD) in TD3 (i.e. ID cards) MRZ
  uint256 constant ID_CARD_MRZ_BIRTHDATE_INDEX = 30;
  // Index for the document number in the MRZ
  uint256 constant ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX = 5;
  // Index for the document type in the MRZ
  uint256 constant ID_CARD_MRZ_DOCUMENT_TYPE_INDEX = 0;
  // Index for the name of the passport holder
  uint256 constant ID_CARD_MRZ_NAME_INDEX = 60;
  // Length of the MRZ on an ID card
  uint256 constant ID_CARD_MRZ_LENGTH = 90;

  bytes32 public constant CERTIFICATE_REGISTRY_ID = bytes32(uint256(1));
  bytes32 public constant CIRCUIT_REGISTRY_ID = bytes32(uint256(2));

  address public admin;
  bool public paused;

  mapping(bytes32 => address) public vkeyHashToVerifier;
  // TODO: remove this when proper local testing with the root registry is done
  mapping(bytes32 => bool) public isValidCertificateRegistryRoot;

  // Maybe make this immutable as this should most likely not change?
  IRootRegistry public rootRegistry;

  // Events
  event AdminUpdated(address indexed oldAdmin, address indexed newAdmin);
  event PausedStatusChanged(bool paused);
  event ZKPassportVerifierDeployed(address indexed admin, uint256 timestamp);
  event VerifierAdded(bytes32 indexed vkeyHash, address indexed verifier);
  event VerifierRemoved(bytes32 indexed vkeyHash);
  event CertificateRegistryRootAdded(bytes32 indexed certificateRegistryRoot);
  event CertificateRegistryRootRemoved(bytes32 indexed certificateRegistryRoot);

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

  // TODO: remove this when proper local testing with the root registry is done
  function addCertificateRegistryRoot(bytes32 certificateRegistryRoot) external onlyAdmin {
    isValidCertificateRegistryRoot[certificateRegistryRoot] = true;
    emit CertificateRegistryRootAdded(certificateRegistryRoot);
  }

  // TODO: remove this when proper local testing with the root registry is done
  function removeCertificateRegistryRoot(bytes32 certificateRegistryRoot) external onlyAdmin {
    isValidCertificateRegistryRoot[certificateRegistryRoot] = false;
    emit CertificateRegistryRootRemoved(certificateRegistryRoot);
  }

  function checkDate(
    bytes32[] memory publicInputs,
    uint256 validityPeriodInDays
  ) internal view returns (bool) {
    bytes memory currentDate = new bytes(8);
    for (uint256 i = 1; i < 9; i++) {
      currentDate[i - 1] = bytes1(publicInputs[i] << 248);
    }
    return DateUtils.isDateValid(currentDate, validityPeriodInDays);
  }

  function getDisclosedData(
    bytes calldata discloseBytes,
    bool isIDCard
  )
    public
    pure
    returns (
      string memory name,
      string memory issuingCountry,
      string memory nationality,
      string memory gender,
      string memory birthDate,
      string memory expiryDate,
      string memory documentNumber,
      string memory documentType
    )
  {
    if (!isIDCard) {
      name = string(discloseBytes[PASSPORT_MRZ_NAME_INDEX:PASSPORT_MRZ_NAME_INDEX + 39]);
      issuingCountry = string(
        discloseBytes[PASSPORT_MRZ_COUNTRY_INDEX:PASSPORT_MRZ_COUNTRY_INDEX + 3]
      );
      nationality = string(
        discloseBytes[PASSPORT_MRZ_NATIONALITY_INDEX:PASSPORT_MRZ_NATIONALITY_INDEX + 3]
      );
      gender = string(discloseBytes[PASSPORT_MRZ_GENDER_INDEX:PASSPORT_MRZ_GENDER_INDEX + 1]);
      birthDate = string(
        discloseBytes[PASSPORT_MRZ_BIRTHDATE_INDEX:PASSPORT_MRZ_BIRTHDATE_INDEX + 6]
      );
      expiryDate = string(
        discloseBytes[PASSPORT_MRZ_EXPIRY_DATE_INDEX:PASSPORT_MRZ_EXPIRY_DATE_INDEX + 6]
      );
      documentNumber = string(
        discloseBytes[PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX:PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + 9]
      );
      documentType = string(
        discloseBytes[PASSPORT_MRZ_DOCUMENT_TYPE_INDEX:PASSPORT_MRZ_DOCUMENT_TYPE_INDEX + 2]
      );
    } else {
      name = string(discloseBytes[ID_CARD_MRZ_NAME_INDEX:ID_CARD_MRZ_NAME_INDEX + 30]);
      issuingCountry = string(
        discloseBytes[ID_CARD_MRZ_COUNTRY_INDEX:ID_CARD_MRZ_COUNTRY_INDEX + 3]
      );
      nationality = string(
        discloseBytes[ID_CARD_MRZ_NATIONALITY_INDEX:ID_CARD_MRZ_NATIONALITY_INDEX + 3]
      );
      gender = string(discloseBytes[ID_CARD_MRZ_GENDER_INDEX:ID_CARD_MRZ_GENDER_INDEX + 1]);
      birthDate = string(
        discloseBytes[ID_CARD_MRZ_BIRTHDATE_INDEX:ID_CARD_MRZ_BIRTHDATE_INDEX + 6]
      );
      expiryDate = string(
        discloseBytes[ID_CARD_MRZ_EXPIRY_DATE_INDEX:ID_CARD_MRZ_EXPIRY_DATE_INDEX + 6]
      );
      documentNumber = string(
        discloseBytes[ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX:ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX + 9]
      );
      documentType = string(
        discloseBytes[ID_CARD_MRZ_DOCUMENT_TYPE_INDEX:ID_CARD_MRZ_DOCUMENT_TYPE_INDEX + 2]
      );
    }
  }

  function getDiscloseProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes memory discloseMask, bytes memory discloseBytes) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Disclose circuits have 181 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 181) {
        require(committedInputs[offset] == bytes1(uint8(ProofType.DISCLOSE)), "Invalid proof type");
        discloseMask = committedInputs[offset + 1:offset + 91];
        discloseBytes = committedInputs[offset + 91:offset + 181];
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Disclose proof inputs not found");
  }

  function getDateProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts,
    ProofType proofType
  ) public pure returns (uint256 currentDate, uint256 minDate, uint256 maxDate) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Date circuits have 25 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 25 && committedInputs[offset] == bytes1(uint8(proofType))) {
        currentDate = DateUtils.getTimestampFromDate(committedInputs[offset + 1:offset + 9]);
        minDate = DateUtils.getTimestampFromDate(committedInputs[offset + 9:offset + 17]);
        maxDate = DateUtils.getTimestampFromDate(committedInputs[offset + 17:offset + 25]);
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Date proof inputs not found");
  }

  function getAgeProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (uint256 currentDate, uint8 minAge, uint8 maxAge) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // The age circuit has 11 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 11) {
        require(committedInputs[offset] == bytes1(uint8(ProofType.AGE)), "Invalid proof type");
        currentDate = DateUtils.getTimestampFromDate(committedInputs[offset + 1:offset + 9]);
        minAge = uint8(committedInputs[offset + 9]);
        maxAge = uint8(committedInputs[offset + 10]);
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Age proof inputs not found");
  }

  function getCountryProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts,
    ProofType proofType
  ) public pure returns (string[] memory countryList) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Country (inclusion and exclusion) circuits have 601 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 601 && committedInputs[offset] == bytes1(uint8(proofType))) {
        countryList = new string[](200);
        for (uint256 j = 0; j < 200; j++) {
          if (committedInputs[offset + j * 3 + 1] == 0) {
            // We don't need to include the padding bytes
            break;
          }
          countryList[j] = string(committedInputs[offset + j * 3 + 1:offset + j * 3 + 3 + 1]);
        }
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Country proof inputs not found");
  }

  function getBindProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes memory data) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // The bind data circuit has 501 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 501) {
        require(committedInputs[offset] == bytes1(uint8(ProofType.BIND)), "Invalid proof type");
        // Get the length of the data from the tag length encoded in the data
        // The developer should check on their side the actual data returned before
        // the padding bytes by asserting the values returned from getBoundData meets
        // what they expect
        uint256 dataLength = 0;
        while (dataLength < 500) {
          if (
            committedInputs[offset + 1 + dataLength] ==
            bytes1(uint8(BoundDataIdentifier.USER_ADDRESS))
          ) {
            uint16 addressLength = uint16(
              bytes2(committedInputs[offset + 1 + dataLength + 1:offset + 1 + dataLength + 3])
            );
            dataLength += 2 + addressLength + 1;
          } else if (
            committedInputs[offset + 1 + dataLength] ==
            bytes1(uint8(BoundDataIdentifier.CUSTOM_DATA))
          ) {
            uint16 customDataLength = uint16(
              bytes2(committedInputs[offset + 1 + dataLength + 1:offset + 1 + dataLength + 3])
            );
            dataLength += 2 + customDataLength + 1;
          } else {
            break;
          }
        }
        require(dataLength > 0 && dataLength <= 500, "Invalid data length");

        // Verify all padding bytes are zeros
        for (uint256 j = dataLength; j < 500; j++) {
          require(committedInputs[offset + 1 + j] == 0, "Invalid padding");
        }

        data = committedInputs[offset + 1:offset + 501];
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Bind data proof inputs not found");
  }

  function getBoundData(
    bytes calldata data
  ) public pure returns (address senderAddress, string memory customData) {
    uint256 offset = 0;
    while (offset < 500) {
      if (data[offset] == bytes1(uint8(BoundDataIdentifier.USER_ADDRESS))) {
        uint16 addressLength = uint16(bytes2(data[offset + 1:offset + 3]));
        senderAddress = address(bytes20(data[offset + 3:offset + 3 + addressLength]));
        offset += 2 + addressLength + 1;
      } else if (data[offset] == bytes1(uint8(BoundDataIdentifier.CUSTOM_DATA))) {
        uint16 customDataLength = uint16(bytes2(data[offset + 1:offset + 3]));
        customData = string(data[offset + 3:offset + 3 + customDataLength]);
        offset += 2 + customDataLength + 1;
      } else {
        break;
      }
    }
  }

  function verifyScopes(
    bytes32[] calldata publicInputs,
    string calldata scope,
    string calldata subscope
  ) public view returns (bool) {
    // One byte is dropped at the end
    string memory chainId = StringUtils.toString(block.chainid);
    bytes32 scopeHash = StringUtils.isEmpty(scope)
      ? bytes32(0)
      : sha256(abi.encodePacked(scope, ":chain-", chainId)) >> 8;
    bytes32 subscopeHash = StringUtils.isEmpty(subscope)
      ? bytes32(0)
      : sha256(abi.encodePacked(subscope)) >> 8;
    return publicInputs[9] == scopeHash && publicInputs[10] == subscopeHash;
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
  }

  function _getVerifier(bytes32 vkeyHash) internal view returns (address) {
    address verifier = vkeyHashToVerifier[vkeyHash];
    require(verifier != address(0), "Verifier not found");
    return verifier;
  }

  function _validateCertificateRoot(bytes32 certificateRoot) internal view {
    require(
      // Keep the legacy check for testing purposes for now
      // Only in local testing will the mapping be populated
      isValidCertificateRegistryRoot[certificateRoot] ||
        rootRegistry.isRootValid(CERTIFICATE_REGISTRY_ID, certificateRoot),
      "Invalid certificate registry root"
    );
  }

  // TODO: use this function when the circuit registry inclusion is done
  // in the outer proofs
  function _validateCircuitRoot(bytes32 circuitRoot) internal view {
    require(
      rootRegistry.isRootValid(CIRCUIT_REGISTRY_ID, circuitRoot),
      "Invalid circuit registry root"
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
  ) external view whenNotPaused returns (bool, bytes32) {
    address verifier = _getVerifier(params.vkeyHash);

    // We remove the last 16 public inputs from the count cause they are part of the aggregation object
    // and not the actual public inputs of the circuit
    uint256 actualPublicInputCount = params.publicInputs.length - 16;

    // Validate certificate registry root
    _validateCertificateRoot(params.publicInputs[0]);

    // Checks the date of the proof
    require(
      checkDate(params.publicInputs, params.validityPeriodInDays),
      "Proof expired or date is invalid"
    );

    // Validate scopes if provided
    require(verifyScopes(params.publicInputs, params.scope, params.subscope), "Invalid scopes");

    // Verifies the commitments against the committed inputs
    verifyCommittedInputs(
      // Extracts the commitments from the public inputs
      params.publicInputs[11:actualPublicInputCount - 1],
      params.committedInputs,
      params.committedInputCounts
    );

    // Allow mock proofs in dev mode
    // Mock proofs are recognisable by their unique identifier set to 0
    require(
      params.publicInputs[actualPublicInputCount - 1] != bytes32(0) || params.devMode,
      "Mock proofs are only allowed in dev mode"
    );

    return (
      IVerifier(verifier).verify(params.proof, params.publicInputs),
      params.publicInputs[actualPublicInputCount - 1]
    );
  }
}
