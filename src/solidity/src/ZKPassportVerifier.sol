// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {IVerifier} from "../src/OuterCount4.sol";
import {DateUtils} from "../src/DateUtils.sol";

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

  uint8 constant PROOF_TYPE_DISCLOSE = 0;
  uint8 constant PROOF_TYPE_AGE = 1;
  uint8 constant PROOF_TYPE_BIRTHDATE = 2;
  uint8 constant PROOF_TYPE_EXPIRY_DATE = 3;
  uint8 constant PROOF_TYPE_NATIONALITY_INCLUSION = 4;
  uint8 constant PROOF_TYPE_NATIONALITY_EXCLUSION = 5;
  uint8 constant PROOF_TYPE_ISSUING_COUNTRY_INCLUSION = 6;
  uint8 constant PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION = 7;

  address public admin;
  bool public paused;

  mapping(bytes32 => address) public vkeyHashToVerifier;
  mapping(bytes32 => bool) public isValidCertificateRegistryRoot;

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

  function addVerifiers(
    bytes32[] calldata vkeyHashes,
    address[] calldata verifiers
  ) external onlyAdmin whenNotPaused {
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

  function addCertificateRegistryRoot(bytes32 certificateRegistryRoot) external onlyAdmin {
    isValidCertificateRegistryRoot[certificateRegistryRoot] = true;
    emit CertificateRegistryRootAdded(certificateRegistryRoot);
  }

  function removeCertificateRegistryRoot(bytes32 certificateRegistryRoot) external onlyAdmin {
    isValidCertificateRegistryRoot[certificateRegistryRoot] = false;
    emit CertificateRegistryRootRemoved(certificateRegistryRoot);
  }

  function proofTypeToName(uint8 proofType) public pure returns (string memory) {
    if (proofType == PROOF_TYPE_DISCLOSE) {
      return "disclose";
    } else if (proofType == PROOF_TYPE_AGE) {
      return "age";
    } else if (proofType == PROOF_TYPE_BIRTHDATE) {
      return "birthdate";
    } else if (proofType == PROOF_TYPE_EXPIRY_DATE) {
      return "expiry_date";
    } else if (proofType == PROOF_TYPE_NATIONALITY_INCLUSION) {
      return "nationality_inclusion";
    } else if (proofType == PROOF_TYPE_NATIONALITY_EXCLUSION) {
      return "nationality_exclusion";
    } else if (proofType == PROOF_TYPE_ISSUING_COUNTRY_INCLUSION) {
      return "issuing_country_inclusion";
    } else if (proofType == PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION) {
      return "issuing_country_exclusion";
    }
    revert("Invalid proof type");
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
  )
    public
    pure
    returns (bytes memory discloseMask, bytes memory discloseBytes, string memory proofType)
  {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Disclose circuits have 181 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 181) {
        require(committedInputs[offset] == bytes1(PROOF_TYPE_DISCLOSE), "Invalid proof type");
        proofType = proofTypeToName(PROOF_TYPE_DISCLOSE);
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
    uint256[] calldata committedInputCounts
  )
    public
    pure
    returns (uint256 currentDate, uint256 minDate, uint256 maxDate, string memory proofType)
  {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Date circuits have 25 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 25) {
        require(
          committedInputs[offset] == bytes1(PROOF_TYPE_EXPIRY_DATE) ||
            committedInputs[offset] == bytes1(PROOF_TYPE_BIRTHDATE),
          "Invalid proof type"
        );
        proofType = proofTypeToName(uint8(committedInputs[offset]));
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
  ) public pure returns (uint256 currentDate, uint8 minAge, uint8 maxAge, string memory proofType) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // The age circuit has 11 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 11) {
        require(committedInputs[offset] == bytes1(PROOF_TYPE_AGE), "Invalid proof type");
        proofType = proofTypeToName(PROOF_TYPE_AGE);
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
    uint256[] calldata committedInputCounts
  ) public pure returns (string[] memory countryList, string memory proofType) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Country (inclusion and exclusion) circuits have 601 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == 601) {
        require(
          committedInputs[offset] == bytes1(PROOF_TYPE_NATIONALITY_INCLUSION) ||
            committedInputs[offset] == bytes1(PROOF_TYPE_NATIONALITY_EXCLUSION) ||
            committedInputs[offset] == bytes1(PROOF_TYPE_ISSUING_COUNTRY_INCLUSION) ||
            committedInputs[offset] == bytes1(PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION),
          "Invalid proof type"
        );
        proofType = proofTypeToName(uint8(committedInputs[offset]));
        for (uint256 j = 1; j < 601; j++) {
          if (committedInputs[offset + j * 3] == 0) {
            // We don't need to include the padding bytes
            break;
          }
          countryList[j] = string(committedInputs[offset + j * 3:offset + j * 3 + 3]);
        }
        found = true;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Country proof inputs not found");
  }

  function verifyCommittedInputs(
    bytes32[] memory paramCommitments,
    bytes calldata committedInputs,
    uint256[] memory committedInputCounts
  ) internal pure returns (bool) {
    uint256 offset = 0;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // One byte is dropped inside the circuit as BN254 is limited to 254 bits
      bytes32 calculatedCommitment = sha256(
        abi.encodePacked(committedInputs[offset:offset + committedInputCounts[i]])
      ) >> 8;
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
    // TODO: Replace by a call to the actual certificate registry when it is ready
    require(isValidCertificateRegistryRoot[publicInputs[0]], "Invalid certificate registry root");
    // Checks the date of the proof
    require(checkDate(publicInputs, validityPeriodInDays), "Proof expired or date is invalid");
    // Verifies the commitments against the committed inputs
    require(
      verifyCommittedInputs(
        // Extracts the commitments from the public inputs
        publicInputs[11:actualPublicInputCount - 1],
        committedInputs,
        committedInputCounts
      ),
      "Invalid committed inputs"
    );
    // Verifies the proof
    return (
      IVerifier(verifier).verify(proof, publicInputs),
      publicInputs[actualPublicInputCount - 1]
    );
  }
}
