// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 ZKPassport
pragma solidity >=0.8.21;

bytes32 constant SANCTIONS_TREES_ROOT = 0x27cea23b989f5246d6577568d11cff22537f10fb47729dc004d1bf464ce37bd3;
uint256 constant SECONDS_BETWEEN_1900_AND_1970 = 2208988800;

// The lengths of the preimages of the `param_commitments` of the various disclosure circuits.
library CommittedInputLen {
  uint256 constant COMPARE_AGE = 11;
  uint256 constant COMPARE_BIRTHDATE = 25;
  uint256 constant COMPARE_EXPIRY = 25;
  uint256 constant DISCLOSE_BYTES = 181;
  uint256 constant INCL_ISSUING_COUNTRY = 601;
  uint256 constant EXCL_ISSUING_COUNTRY = 601;
  uint256 constant INCL_NATIONALITY = 601;
  uint256 constant EXCL_NATIONALITY = 601;
  uint256 constant BIND = 501;
  uint256 constant SANCTIONS = 33;
}

library MRZIndex {
  // Index for the country of issuance of the passport
  uint256 constant PASSPORT_MRZ_ISSUING_COUNTRY_INDEX = 2;
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

  // Index for the country of issuance of the ID card
  uint256 constant ID_CARD_MRZ_ISSUING_COUNTRY_INDEX = 2;
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
}

library MRZLength {
  uint256 constant PASSPORT_MRZ_LENGTH = 88;
  uint256 constant ID_CARD_MRZ_LENGTH = 90;
  uint256 constant PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH = 3;
  uint256 constant ID_CARD_MRZ_ISSUING_COUNTRY_LENGTH = 3;
  uint256 constant PASSPORT_MRZ_NATIONALITY_LENGTH = 3;
  uint256 constant ID_CARD_MRZ_NATIONALITY_LENGTH = 3;
  uint256 constant PASSPORT_MRZ_GENDER_LENGTH = 1;
  uint256 constant ID_CARD_MRZ_GENDER_LENGTH = 1;
  uint256 constant PASSPORT_MRZ_BIRTHDATE_LENGTH = 6;
  uint256 constant ID_CARD_MRZ_BIRTHDATE_LENGTH = 6;
  uint256 constant PASSPORT_MRZ_EXPIRY_DATE_LENGTH = 6;
  uint256 constant ID_CARD_MRZ_EXPIRY_DATE_LENGTH = 6;
  uint256 constant PASSPORT_MRZ_DOCUMENT_NUMBER_LENGTH = 9;
  uint256 constant ID_CARD_MRZ_DOCUMENT_NUMBER_LENGTH = 9;
  uint256 constant PASSPORT_MRZ_DOCUMENT_TYPE_LENGTH = 2;
  uint256 constant ID_CARD_MRZ_DOCUMENT_TYPE_LENGTH = 2;
  uint256 constant PASSPORT_MRZ_NAME_LENGTH = 39;
  uint256 constant ID_CARD_MRZ_NAME_LENGTH = 30;
  uint256 constant PASSPORT_MRZ_YEAR_OF_BIRTH_LENGTH = 2;
  uint256 constant ID_CARD_MRZ_YEAR_OF_BIRTH_LENGTH = 2;
}