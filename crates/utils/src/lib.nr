/**
* The standards for passports and any other travel documents, electronic or not,
* are defined in the ICAO (International Civil Aviation Organization) 9303 document available here: 
* https://www.icao.int/publications/pages/publication.aspx?docnum=9303
*/

/**
* The structure of the MRZ is well defined and standardized by the ICAO
* so the index will always be the same for every passport
* c.f. ICAO 9303-4, Appendix B
*/

// The following constants define the indices of the information
// we need to generate various proofs of identity from the MRZ
// The structure of the MRZ is slightly different between passports
// and ID cards so we need to define indices for both types

// Index for the three letter code of the country of citizenship
// Note that the first three letter code (index 2) in the MRZ is the country of issuance
// not citizenship. It is important to keep in mind for residence permits 
// where the issuing country differs from the citizenship country
global PASSPORT_MRZ_COUNTRY_INDEX: u32 = 54;
// Index for the sex of the passport holder (M, F or < if unspecified)
global PASSPORT_MRZ_SEX_INDEX: u32 = 64;
// Index for the date of expiry (YYMMDD)
global PASSPORT_MRZ_EXPIRY_DATE_INDEX: u32 = 65;
// Index for the date of birth (YYMMDD) in TD1 (i.e. passport) MRZ
global PASSPORT_MRZ_BIRTHDATE_INDEX: u32 = 57;
// Length of the MRZ on a passport
global PASSPORT_MRZ_LENGTH: u32 = 88;

// Note that the first three letter code (index 2) in the MRZ is the country of issuance
// not citizenship. It is important to keep in mind for residence permits 
// where the issuing country differs from the citizenship country
global ID_CARD_MRZ_COUNTRY_INDEX: u32 = 45;
// Index for the sex of the passport holder (M, F or < if unspecified)
global ID_CARD_MRZ_SEX_INDEX: u32 = 37;
// Index for the date of expiry (YYMMDD)
global ID_CARD_MRZ_EXPIRY_DATE_INDEX: u32 = 38;
// Index for the date of birth (YYMMDD) in TD3 (i.e. ID cards) MRZ
global ID_CARD_MRZ_BIRTHDATE_INDEX: u32 = 30;
// Length of the MRZ on an ID card
global ID_CARD_MRZ_LENGTH: u32 = 90;

struct IDData {
    // Last 32 bytes: result of the hash of all the hashes of the data groups
    // Rest of the bytes: padding data + signature date
    e_content: [u8; 104],
    // The signature of the ID data, essentially the signature by the private
    // key of the Document Signing Certificate (DSC) of the ID over e_content
    encrypted_digest: [u8; 256],
    // The Machine Readable Zone (MRZ) of the document
    // The two lines at the bottom of the passport data page
    // or the three bottom lines on the rear of an ID card
    mrz: str<90>,

    // The hashes of each data group
    // While the hashing algorithm could be any SHA, we assume it's SHA-256
    // for now as is the case for French passports
    // Only DG1 and DG2 are mandatory
    // The others are optional (or conditional under certain circumstances)
    // If not present in the ID, the array shall be filled with 0s

    // Data Group 1 -> Contains the MRZ (Machine Readable Zone)
    dg1_hash: [u8; 32],
    // Data Group 2 -> Contains the photo of the ID holder
    dg2_hash: [u8; 32],
    // Data Group 3 -> Contains the fingerprints of the ID holder (access likely restricted)
    dg3_hash: [u8; 32],
    // Data Group 4 -> Contains the iris scan of the ID holder (access likely restricted)
    dg4_hash: [u8; 32],
    // Data Group 5 -> Contains the displayed portrait
    dg5_hash: [u8; 32],
    // Data Group 6 -> Reserved for future use (so not used as of today)
    dg6_hash: [u8; 32],
    // Data Group 7 -> Contains the displayed signature
    dg7_hash: [u8; 32],
    // Data Group 8 -> Yet to be defined, can be used for temporary proprietary usage
    dg8_hash: [u8; 32],
    // Data Group 9 -> Yet to be defined, can be used for temporary proprietary usage
    dg9_hash: [u8; 32],
    // Data Group 10 -> Yet to be defined, can be used for temporary proprietary usage
    dg10_hash: [u8; 32],
    // Data Group 11 -> Contains additional personal details (such as the address, full date of birth, etc.)
    dg11_hash: [u8; 32],
    // Data Group 12 -> Contains additional document details (such as date of issue, issuing authority, etc.)
    dg12_hash: [u8; 32],
    // Data Group 13 -> Freeform data group where each State can fully decide of the data in it and how to encode them
    dg13_hash: [u8; 32],
    // Data Group 14 -> Contains security options for authentication with the chip of the ID
    dg14_hash: [u8; 32],
    // Data Group 15 -> Contains the Active Authentication Public Key Info
    dg15_hash: [u8; 32],
    // Data Group 16 -> Contains the details of the persons to notify (i.e. emergency contacts)
    dg16_hash: [u8; 32],
}

struct DSCData {
    // The public key of the Document Signing Certificate (DSC)
    // Most likely a 2048-bit RSA key, so that's the size we set here
    // 256 bytes = 2048 bits
    pubkey: [u8; 256],
    // The signature of the DSC TBS certificate by the CSCA certificate
    // 512 bytes = 4096 bits
    signature: [u8; 512],
    // The TBS certificate of the DSC
    // TBS stands for To Be Signed
    tbs_certificate: [u8; 888],
    // Data used to verify the signature
    // Generated by the pre-compute function in Rust
    // c.f. main.rs
    redc_param: [u8; 257],
}

struct CSCACertData {
    // The public key of the Country Signing Certificate Authority (CSCA)
    // Most likely a 4096-bit RSA key, so that's the size we set here
    // 512 bytes = 4096 bits
    pubkey: [u8; 512],
    // Data used to verify the signature
    // Generated by the pre-compute function in Rust
    // c.f. main.rs
    redc_param: [Field; 35],
}

pub fn get_array_slice<let N: u32, let M: u32>(arr: [u8; N], start: u32, end: u32) -> [u8; M] {
    let mut slice = [0 as u8; M];
    for i in start..end {
        slice[i - start] = arr[i];
    }
    slice
}

// Reverse the bytes of an array so you can switch from
// big endian to little endian order and vice versa
pub fn reverse_bytes_array<let N: u32>(arr: [u8; N]) -> [u8; N] {
    let mut reversed_arr = [0 as u8; N];
    for i in 0..N {
        // Reverse
        reversed_arr[i] = arr[N - 1 - i];
    }
    reversed_arr
}

pub fn insert_into_array<let N: u32, let M: u32>(
    mut arr: [u8; N],
    sub_arr: [u8; M],
    index: u32
) -> [u8; N] {
    for i in index..index + M {
        arr[i] = sub_arr[i - index];
    }
    arr
}

/**
* Rather hacky but in some cases we cannot use a for loop as the compiler 
* won't be able to determine its bounds at compile time
*/
pub fn insert_32_bytes_into_array<let N: u32>(mut arr: [u8; N], sub_arr: [u8; 32], index: u32) -> [u8; N] {
    arr[index] = sub_arr[0];
    arr[index + 1] = sub_arr[1];
    arr[index + 2] = sub_arr[2];
    arr[index + 3] = sub_arr[3];
    arr[index + 4] = sub_arr[4];
    arr[index + 5] = sub_arr[5];
    arr[index + 6] = sub_arr[6];
    arr[index + 7] = sub_arr[7];
    arr[index + 8] = sub_arr[8];
    arr[index + 9] = sub_arr[9];
    arr[index + 10] = sub_arr[10];

    arr[index + 11] = sub_arr[11];
    arr[index + 12] = sub_arr[12];
    arr[index + 13] = sub_arr[13];
    arr[index + 14] = sub_arr[14];
    arr[index + 15] = sub_arr[15];
    arr[index + 16] = sub_arr[16];
    arr[index + 17] = sub_arr[17];
    arr[index + 18] = sub_arr[18];
    arr[index + 19] = sub_arr[19];
    arr[index + 20] = sub_arr[20];

    arr[index + 21] = sub_arr[21];
    arr[index + 22] = sub_arr[22];
    arr[index + 23] = sub_arr[23];
    arr[index + 24] = sub_arr[24];
    arr[index + 25] = sub_arr[25];
    arr[index + 26] = sub_arr[26];
    arr[index + 27] = sub_arr[27];
    arr[index + 28] = sub_arr[28];
    arr[index + 29] = sub_arr[29];
    arr[index + 30] = sub_arr[30];

    arr[index + 31] = sub_arr[31];

    arr
}

pub fn insert_7_bytes_into_array<let N: u32>(mut arr: [u8; N], sub_arr: [u8; 7], index: u32) -> [u8; N] {
    arr[index] = sub_arr[0];
    arr[index + 1] = sub_arr[1];
    arr[index + 2] = sub_arr[2];
    arr[index + 3] = sub_arr[3];
    arr[index + 4] = sub_arr[4];
    arr[index + 5] = sub_arr[5];
    arr[index + 6] = sub_arr[6];
    arr
}

pub fn is_id_card(id_data: IDData) -> bool {
    let mrz_bytes = id_data.mrz.as_bytes();
    // 95 encodes the _ character
    // This is our padding character to support both the 
    // MRZ of the passports and ID cards
    (mrz_bytes[88] != 95) & (mrz_bytes[89] != 95)
}

pub fn from_byte_be_to_fields<let NBytes: u32, let N: u32>(x: [u8; NBytes]) -> [Field; N] {
    let mut result = [0 as Field; N];

    let excess_bytes = N * 15 - NBytes;
    let final_limb_bytes = 15 - excess_bytes;
    let mut limb: Field = 0;
    let mut k = 0;
    for _j in 0..final_limb_bytes {
        limb *= 256;
        limb += x[k] as Field;
        k += 1;
    }
    result[N - 1] = limb;

    for i in 1..N {
        let mut limb: Field = 0;
        for _j in 0..15 {
            limb *= 256;
            limb += x[k] as Field;
            k += 1;
        }
        result[N - i - 1] = limb;
    }

    result
}

unconstrained pub fn __from_byte_be_to_fields<let NBytes: u32, let N: u32>(x: [u8; NBytes]) -> [Field; N] {
    from_byte_be_to_fields(x)
}
