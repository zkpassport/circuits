// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {MRZIndex, MRZLength, CommittedInputLen, COUNTRY_LIST_LENGTH, BOUND_DATA_LENGTH, TIMESTAMP_LENGTH} from "../src/Constants.sol";
import {DisclosedData, ProofType} from "../src/Types.sol";
import {BoundDataIdentifier} from "../src/Types.sol";

library InputsExtractor {

  function getDisclosedData(
    bytes calldata discloseBytes,
    bool isIDCard
  )
    public
    pure
    returns (DisclosedData memory disclosedData)
  {
    if (!isIDCard) {
      disclosedData.name = string(discloseBytes[MRZIndex.PASSPORT_MRZ_NAME_INDEX:MRZIndex.PASSPORT_MRZ_NAME_INDEX + MRZLength.PASSPORT_MRZ_NAME_LENGTH]);
      disclosedData.issuingCountry = string(
        discloseBytes[MRZIndex.PASSPORT_MRZ_ISSUING_COUNTRY_INDEX:MRZIndex.PASSPORT_MRZ_ISSUING_COUNTRY_INDEX + MRZLength.PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH]
      );
      disclosedData.nationality = string(
        discloseBytes[MRZIndex.PASSPORT_MRZ_NATIONALITY_INDEX:MRZIndex.PASSPORT_MRZ_NATIONALITY_INDEX + MRZLength.PASSPORT_MRZ_NATIONALITY_LENGTH]
      );
      disclosedData.gender = string(discloseBytes[MRZIndex.PASSPORT_MRZ_GENDER_INDEX:MRZIndex.PASSPORT_MRZ_GENDER_INDEX + MRZLength.PASSPORT_MRZ_GENDER_LENGTH]);
      disclosedData.birthDate = string(
        discloseBytes[MRZIndex.PASSPORT_MRZ_BIRTHDATE_INDEX:MRZIndex.PASSPORT_MRZ_BIRTHDATE_INDEX + MRZLength.PASSPORT_MRZ_BIRTHDATE_LENGTH]
      );
      disclosedData.expiryDate = string(
        discloseBytes[MRZIndex.PASSPORT_MRZ_EXPIRY_DATE_INDEX:MRZIndex.PASSPORT_MRZ_EXPIRY_DATE_INDEX + MRZLength.PASSPORT_MRZ_EXPIRY_DATE_LENGTH]
      );
      disclosedData.documentNumber = string(
        discloseBytes[MRZIndex.PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX:MRZIndex.PASSPORT_MRZ_DOCUMENT_NUMBER_INDEX + MRZLength.PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH]
      );
      disclosedData.documentType = string(
        discloseBytes[MRZIndex.PASSPORT_MRZ_DOCUMENT_TYPE_INDEX:MRZIndex.PASSPORT_MRZ_DOCUMENT_TYPE_INDEX + MRZLength.PASSPORT_MRZ_DOCUMENT_TYPE_LENGTH]
      );
    } else {
      disclosedData.name = string(discloseBytes[MRZIndex.ID_CARD_MRZ_NAME_INDEX:MRZIndex.ID_CARD_MRZ_NAME_INDEX + MRZLength.ID_CARD_MRZ_NAME_LENGTH]);
      disclosedData.issuingCountry = string(
        discloseBytes[MRZIndex.ID_CARD_MRZ_ISSUING_COUNTRY_INDEX:MRZIndex.ID_CARD_MRZ_ISSUING_COUNTRY_INDEX + MRZLength.ID_CARD_MRZ_ISSUING_COUNTRY_LENGTH]
      );
      disclosedData.nationality = string(
        discloseBytes[MRZIndex.ID_CARD_MRZ_NATIONALITY_INDEX:MRZIndex.ID_CARD_MRZ_NATIONALITY_INDEX + MRZLength.ID_CARD_MRZ_NATIONALITY_LENGTH]
      );
      disclosedData.gender = string(discloseBytes[MRZIndex.ID_CARD_MRZ_GENDER_INDEX:MRZIndex.ID_CARD_MRZ_GENDER_INDEX + MRZLength.ID_CARD_MRZ_GENDER_LENGTH]);
      disclosedData.birthDate = string(
        discloseBytes[MRZIndex.ID_CARD_MRZ_BIRTHDATE_INDEX:MRZIndex.ID_CARD_MRZ_BIRTHDATE_INDEX + MRZLength.ID_CARD_MRZ_BIRTHDATE_LENGTH]
      );
      disclosedData.expiryDate = string(
        discloseBytes[MRZIndex.ID_CARD_MRZ_EXPIRY_DATE_INDEX:MRZIndex.ID_CARD_MRZ_EXPIRY_DATE_INDEX + MRZLength.ID_CARD_MRZ_EXPIRY_DATE_LENGTH]
      );
      disclosedData.documentNumber = string(
        discloseBytes[MRZIndex.ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX:MRZIndex.ID_CARD_MRZ_DOCUMENT_NUMBER_INDEX + MRZLength.ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH]
      );
      disclosedData.documentType = string(
        discloseBytes[MRZIndex.ID_CARD_MRZ_DOCUMENT_TYPE_INDEX:MRZIndex.ID_CARD_MRZ_DOCUMENT_TYPE_INDEX + MRZLength.ID_CARD_MRZ_DOCUMENT_TYPE_LENGTH]
      );
    }
  }

  function getDiscloseProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes memory discloseMask, bytes memory discloseBytes) {
    uint256 offset = 0;
    uint256 foundCount = 0;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Disclose circuits have 181 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == CommittedInputLen.DISCLOSE_BYTES && committedInputs[offset] == bytes1(uint8(ProofType.DISCLOSE))) {
        offset += 1;
        discloseMask = committedInputs[offset:offset + MRZLength.MRZ_MAX_LENGTH];
        discloseBytes = committedInputs[offset + MRZLength.MRZ_MAX_LENGTH:offset + MRZLength.MRZ_MAX_LENGTH * 2];
        foundCount++;
      }
      offset += committedInputCounts[i];
    }
    require(foundCount > 0, "Disclose proof inputs not found");
    require(foundCount == 1, "Found multiple disclose proofs, the proof should only have one");
  }

  function getDateProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts,
    ProofType proofType
  ) public pure returns (uint256 currentDate, uint256 minDate, uint256 maxDate) {
    uint256 offset = 0;
    uint256 foundCount = 0;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Date circuits have 25 bytes of committed inputs
      // The first byte is the proof type
      if (
        committedInputCounts[i] == CommittedInputLen.COMPARE_EXPIRY &&
        committedInputs[offset] == bytes1(uint8(proofType))
      ) {
        offset += 1;
        // Get rid of the padding 0s bytes as the timestamp is contained within the first 64 bits
        // i.e. 256 - 64 = 192
        currentDate = uint256(bytes32(committedInputs[offset:offset + TIMESTAMP_LENGTH])) >> 192;
        minDate = uint256(bytes32(committedInputs[offset + TIMESTAMP_LENGTH:offset + TIMESTAMP_LENGTH * 2])) >> 192;
        maxDate = uint256(bytes32(committedInputs[offset + TIMESTAMP_LENGTH * 2:offset + TIMESTAMP_LENGTH * 3])) >> 192;
        foundCount++;
      }
      offset += committedInputCounts[i];
    }
    if (proofType == ProofType.BIRTHDATE) {
      require(foundCount > 0, "Compare birthdate proof inputs not found");
      require(foundCount == 1, "Found multiple compare birthdate proofs, the proof should only have one");
    } else {
      require(foundCount > 0, "Compare expiry date proof inputs not found");
      require(foundCount == 1, "Found multiple compare expiry date proofs, the proof should only have one");
    }
  }

  function getAgeProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (uint256 currentDate, uint8 minAge, uint8 maxAge) {
    uint256 offset = 0;
    uint256 foundCount = 0;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // The age circuit has 11 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == CommittedInputLen.COMPARE_AGE && committedInputs[offset] == bytes1(uint8(ProofType.AGE))) {
        // Get rid of the padding 0s bytes as the timestamp is contained within the first 64 bits
        // i.e. 256 - 64 = 192
        currentDate = uint256(bytes32(committedInputs[offset + 1:offset + 9])) >> 192;
        minAge = uint8(committedInputs[offset + 9]);
        maxAge = uint8(committedInputs[offset + 10]);
        foundCount++;
      }
      offset += committedInputCounts[i];
    }
    require(foundCount > 0, "Compare age proof inputs not found");
    require(foundCount == 1, "Found multiple compare age proofs, the proof should only have one");
  }

  function getCountryProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts,
    ProofType proofType
  ) public pure returns (string[] memory countryList, uint256 length) {
    uint256 offset = 0;
    uint256 foundCount = 0;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Country (inclusion and exclusion) circuits have 601 bytes of committed inputs
      // The first byte is the proof type
      if (
        committedInputCounts[i] == CommittedInputLen.INCL_NATIONALITY &&
        committedInputs[offset] == bytes1(uint8(proofType))
      ) {
        countryList = new string[](COUNTRY_LIST_LENGTH);
        offset += 1;
        for (uint256 j = 0; j < COUNTRY_LIST_LENGTH; j++) {
          if (committedInputs[offset] == 0) {
            length = j;
            // The circuit constrains that once we've reached the first `0`,
            // we won't encounter any further nonzero values.
            // We don't need to include the padding bytes
            break;
          }
          countryList[j] = string(committedInputs[offset:offset + 3]);
          offset += 3;
        }
        foundCount++;
      }
      offset += committedInputCounts[i];
    }
    if (proofType == ProofType.ISSUING_COUNTRY_INCLUSION) {
      require(foundCount > 0, "Inclusion country proof inputs not found");
      require(foundCount == 1, "Found multiple inclusion country proofs, the proof should only have one");
    } else if (proofType == ProofType.ISSUING_COUNTRY_EXCLUSION) {
      require(foundCount > 0, "Exclusion country proof inputs not found");
      require(foundCount == 1, "Found multiple exclusion country proofs, the proof should only have one");
    } else if (proofType == ProofType.NATIONALITY_INCLUSION) {
      require(foundCount > 0, "Inclusion nationality proof inputs not found");
      require(foundCount == 1, "Found multiple inclusion nationality proofs, the proof should only have one");
    } else if (proofType == ProofType.NATIONALITY_EXCLUSION) {
      require(foundCount > 0, "Exclusion nationality proof inputs not found");
      require(foundCount == 1, "Found multiple exclusion nationality proofs, the proof should only have one");
    }
  }

  function getBindProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes memory data) {
    uint256 offset = 0;
    uint256 foundCount = 0;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // The bind data circuit has 501 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == CommittedInputLen.BIND && committedInputs[offset] == bytes1(uint8(ProofType.BIND))) {
        data = committedInputs[offset + 1:offset + BOUND_DATA_LENGTH + 1];
        foundCount++;
      }
      offset += committedInputCounts[i];
    }
    require(foundCount > 0, "Bind data proof inputs not found");
    require(foundCount == 1, "Found multiple bind data proofs, the proof should only have one");
  }

  function getSanctionsProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes32 sanctionsTreesCommitment) {
    uint256 offset = 0;
    uint256 foundCount = 0;
    for (uint256 i = 0; i < committedInputCounts.length; ++i) {
      if (committedInputCounts[i] == CommittedInputLen.SANCTIONS && committedInputs[offset] == bytes1(uint8(ProofType.SANCTIONS))) {
        sanctionsTreesCommitment = bytes32(committedInputs[offset + 1:offset + 33]);
        foundCount++;
      }
      offset += committedInputCounts[i];
    }
    require(foundCount > 0, "Sanctions proof inputs not found");
    require(foundCount == 1, "Found multiple sanctions proofs, the proof should only have one");
  }

  function getBoundData(
    bytes calldata data
  ) public pure returns (address senderAddress, uint256 chainId, string memory customData) {
    uint256 offset = 0;
    while (offset < BOUND_DATA_LENGTH) {
      if (data[offset] == bytes1(uint8(BoundDataIdentifier.USER_ADDRESS))) {
        uint16 addressLength = uint16(bytes2(data[offset + 1:offset + 3]));
        senderAddress = address(bytes20(data[offset + 3:offset + 3 + addressLength]));
        offset += 2 + addressLength + 1;
      } else if (data[offset] == bytes1(uint8(BoundDataIdentifier.CHAIN_ID))) {
        uint16 chainIdLength = uint16(bytes2(data[offset + 1:offset + 3]));
        require(chainIdLength <= 32, "Chain id length too long");
        // bytes32 right pads while we want to left pad
        // so we shift the bytes to the right by 256 - (chainIdLength * 8)
        chainId = uint256(
          bytes32(data[offset + 3:offset + 3 + chainIdLength]) >> (256 - (chainIdLength * 8))
        );
        offset += 2 + chainIdLength + 1;
      } else if (data[offset] == bytes1(uint8(BoundDataIdentifier.CUSTOM_DATA))) {
        uint16 customDataLength = uint16(bytes2(data[offset + 1:offset + 3]));
        customData = string(data[offset + 3:offset + 3 + customDataLength]);
        offset += 2 + customDataLength + 1;
      } else {
        // Check that the data length is valid
        require(offset > 0 && offset <= BOUND_DATA_LENGTH, "Invalid data length");
        // Check that the padding is valid
        for (uint256 i = offset; i < BOUND_DATA_LENGTH; i++) {
          require(data[i] == 0, "Invalid padding");
        }
        break;
      }
    }
  }
}