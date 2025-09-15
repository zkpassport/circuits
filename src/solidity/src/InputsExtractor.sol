// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

import {MRZIndex, MRZLength, CommittedInputLen} from "../src/Constants.sol";
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
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Disclose circuits have 181 bytes of committed inputs
      // The first byte is the proof type
      if (committedInputCounts[i] == CommittedInputLen.DISCLOSE_BYTES && committedInputs[offset] == bytes1(uint8(ProofType.DISCLOSE))) {
        discloseMask = committedInputs[offset + 1:offset + 91];
        discloseBytes = committedInputs[offset + 91:offset + 181];
        found = true;
        break;
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
      if (
        committedInputCounts[i] == CommittedInputLen.COMPARE_EXPIRY &&
        committedInputs[offset] == bytes1(uint8(proofType))
      ) {
        // Get rid of the padding 0s bytes as the timestamp is contained within the first 64 bits
        // i.e. 256 - 64 = 192
        currentDate = uint256(bytes32(committedInputs[offset + 1:offset + 9])) >> 192;
        minDate = uint256(bytes32(committedInputs[offset + 9:offset + 17])) >> 192;
        maxDate = uint256(bytes32(committedInputs[offset + 17:offset + 25])) >> 192;
        found = true;
        break;
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
      if (committedInputCounts[i] == CommittedInputLen.COMPARE_AGE && committedInputs[offset] == bytes1(uint8(ProofType.AGE))) {
        // Get rid of the padding 0s bytes as the timestamp is contained within the first 64 bits
        // i.e. 256 - 64 = 192
        currentDate = uint256(bytes32(committedInputs[offset + 1:offset + 9])) >> 192;
        minAge = uint8(committedInputs[offset + 9]);
        maxAge = uint8(committedInputs[offset + 10]);
        found = true;
        break;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Age proof inputs not found");
  }

  function getCountryProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts,
    ProofType proofType
  ) public pure returns (string[] memory countryList, uint256 length) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; i++) {
      // Country (inclusion and exclusion) circuits have 601 bytes of committed inputs
      // The first byte is the proof type
      if (
        committedInputCounts[i] == CommittedInputLen.INCL_NATIONALITY &&
        committedInputs[offset] == bytes1(uint8(proofType))
      ) {
        countryList = new string[](200);
        for (uint256 j = 0; j < 200; j++) {
          if (committedInputs[offset + j * 3 + 1] == 0) {
            length = j;
            // We don't need to include the padding bytes
            break;
          }
          countryList[j] = string(committedInputs[offset + j * 3 + 1:offset + j * 3 + 3 + 1]);
        }
        found = true;
        break;
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
      if (committedInputCounts[i] == CommittedInputLen.BIND && committedInputs[offset] == bytes1(uint8(ProofType.BIND))) {
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
            committedInputs[offset + 1 + dataLength] == bytes1(uint8(BoundDataIdentifier.CHAIN_ID))
          ) {
            uint16 chainIdLength = uint16(
              bytes2(committedInputs[offset + 1 + dataLength + 1:offset + 1 + dataLength + 3])
            );
            dataLength += 2 + chainIdLength + 1;
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
        break;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Bind data proof inputs not found");
  }

  function getSanctionsProofInputs(
    bytes calldata committedInputs,
    uint256[] calldata committedInputCounts
  ) public pure returns (bytes32 sanctionsTreesCommitment) {
    uint256 offset = 0;
    bool found = false;
    for (uint256 i = 0; i < committedInputCounts.length; ++i) {
      if (committedInputCounts[i] == CommittedInputLen.SANCTIONS && committedInputs[offset] == bytes1(uint8(ProofType.SANCTIONS))) {
        sanctionsTreesCommitment = bytes32(committedInputs[offset + 1:offset + 33]);
        found = true;
        break;
      }
      offset += committedInputCounts[i];
    }
    require(found, "Sanctions proof inputs not found");
  }

  function getBoundData(
    bytes calldata data
  ) public pure returns (address senderAddress, uint256 chainId, string memory customData) {
    uint256 offset = 0;
    while (offset < 500) {
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
        break;
      }
    }
  }
}