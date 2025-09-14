use super::constants::{
    DG1_LENGTH, ECONTENT_LENGTH, MAX_MRZ_LENGTH, PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH,
    PASSPORT_MRZ_NATIONALITY_LENGTH, SHA1_DIGEST_LENGTH, SHA224_DIGEST_LENGTH, SHA256_DIGEST_LENGTH,
    SHA384_DIGEST_LENGTH, SHA512_DIGEST_LENGTH, SIGNED_ATTRS_LENGTH, YYMMDD_DATE_LENGTH,
};

// DG1 types
pub type DG1Data = [u8; DG1_LENGTH];
pub type MRZData = [u8; MAX_MRZ_LENGTH];

// MRZ types
pub type MRZName = [u8; 39];
pub type MRZNameIdCard = [u8; 30];
pub type MRZDOB = [u8; YYMMDD_DATE_LENGTH];
pub type MRZYOB = [u8; 2];
pub type MRZExpiryDate = [u8; YYMMDD_DATE_LENGTH];
pub type MRZDocumentNumber = [u8; 9];
pub type MRZNationality = [u8; PASSPORT_MRZ_NATIONALITY_LENGTH];
pub type MRZIssuingCountry = [u8; PASSPORT_MRZ_ISSUING_COUNTRY_LENGTH];

pub type EContentData = [u8; ECONTENT_LENGTH];
pub type SignedAttrsData = [u8; SIGNED_ATTRS_LENGTH];

pub type Alpha3CountryCode = str<3>;
pub type Alpha2CountryCode = str<2>;

pub type DiscloseMask = [u1; MAX_MRZ_LENGTH];

pub type SHA1Digest = [u8; SHA1_DIGEST_LENGTH];
pub type SHA224Digest = [u8; SHA224_DIGEST_LENGTH];
pub type SHA256Digest = [u8; SHA256_DIGEST_LENGTH];
pub type SHA384Digest = [u8; SHA384_DIGEST_LENGTH];
pub type SHA512Digest = [u8; SHA512_DIGEST_LENGTH];
