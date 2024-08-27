use dep::utils::{
    IDData, insert_7_bytes_into_array, ID_CARD_MRZ_LENGTH, insert_32_bytes_into_array,
    insert_into_array, is_id_card, dynamic_insert_into_array
};
use dep::std::sha256;

/**
* To form the whole Data Group 1, the MRZ is padded with some tags and lengths 
* as specified in the ICAO specifications
* c.f. see ICAO 9303-11, 4.7.1, Table 39
*/
fn get_dg1_from_mrz(mrz: str<ID_CARD_MRZ_LENGTH>) -> [u8; 95] {
    let mut dg1 = [0 as u8; 95];

    // Tag for Data Group 1 (which contains the MRZ)
    dg1[0] = 97;
    // Length of the array 88 + 2 bytes for the following tag + 1 byte for the length of the MRZ
    dg1[1] = 91;
    // 5F1F is the tag for the MRZ data within Data Group 1
    // First byte is 5F = 95 in decimals
    dg1[2] = 95;
    // Second byte is 1F = 31 in decimals
    dg1[3] = 31;
    // Length of the MRZ
    dg1[4] = 88;

    let mrz_bytes = mrz.as_bytes();

    // The MRZ itself
    for i in 5..95 {
        // We need to ignore the zero since the MRZ is potentially
        // zero padded at the end to account for the different size of
        // the MRZ between ID cards and passports
        if mrz_bytes[i - 5] != 0 {
            dg1[i] = mrz_bytes[i - 5];
        }
    }

    dg1
}

/**
* Computes the hash of the MRZ (Data Group 1) and checks it is the same as the one
* provided in the SOD file of the ID and then use it along with the rest of the
* hashes of the remaining data groups to compute the final hash contained in the last 32 bytes of
* eContent that is then signed by the Document Signing Certificate (DSC)
* This lets us make sure the data is authentic and has not been tampered with, so we can use the data 
* of the MRZ to build subsequent proofs (age, citizenship, etc.)
*/
pub fn check_integrity_of_data(id_data: IDData) {
    let computed_dg1 = get_dg1_from_mrz(id_data.mrz);

    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(id_data) {
        dg1_size = 95;
    }

    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let computed_dg1_hash = sha256::sha256_var(computed_dg1, dg1_size as u64);

    // Check the computed hash of Data Group 1 (i.e. MRZ) is the same 
    // as the one from the SOD file of the ID
    // c.f. ICAO 9303-11, 4.6.2 for more information
    assert(computed_dg1_hash == id_data.dg1_hash);

    // We group all the hashes of the data groups into an array
    // so we can iterate over it for the final hash computation
    let data_groups = [
        computed_dg1_hash,
        id_data.dg2_hash,
        id_data.dg3_hash,
        id_data.dg4_hash,
        id_data.dg5_hash,
        id_data.dg6_hash,
        id_data.dg7_hash,
        id_data.dg8_hash,
        id_data.dg9_hash,
        id_data.dg10_hash,
        id_data.dg11_hash,
        id_data.dg12_hash,
        id_data.dg13_hash,
        id_data.dg14_hash,
        id_data.dg15_hash,
        id_data.dg16_hash
    ];

    // The max size of the array is 648 bytes with all 16 data groups present
    // i.e. 16 * (7 bytes of padding data + 32 bytes of hash data) + 24 bytes of padding data = 648 bytes
    // Just to be safe, we set it to 700 bytes as the actual size doesn't matter
    // as long as it's big enough for the maximum size
    let mut content_to_hash = [0 as u8; 700];
    let mut current_index = 0;

    // The first 24 bytes are padding data
    content_to_hash = insert_into_array(content_to_hash, [48, 130, 1, 37, 2, 1, 0, 48, 11, 6, 9, 96, 134, 72, 1, 101, 3, 4, 2, 1, 48, 130, 1, 17], current_index);
    current_index += 24;

    for i in 0..16 {
        if data_groups[i] != [0 as u8; 32] {
            // 7 bytes of padding data + 32 bytes of hash data
            content_to_hash = insert_7_bytes_into_array(content_to_hash, [48, 37, 2, 1, i + 1, 4, 32], current_index);
            content_to_hash = insert_32_bytes_into_array(content_to_hash, data_groups[i], current_index + 7);
            current_index += 39;
        }
    }

    let computed_final_hash = sha256::sha256_var(content_to_hash, current_index as u64);

    let e_content_length = id_data.e_content.len();
    for i in 0..32 {
        // The last 32 bytes of the e_content are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(computed_final_hash[i] == id_data.e_content[e_content_length - 32 + i]);
    }
}