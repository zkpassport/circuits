use sha1::sha1;
use sha256::{sha224_var, sha256_var};
use sha512::{sha384, sha512};
use utils::{_find_subarray_index, is_id_card};

/**
* Computes the hash (using SHA1) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha1(dg1: [u8; 95], e_content: [u8; 700], dg1_offset_in_e_content: u32) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        dg1_size = 95;
    }

    let dg1_bounded_vec = BoundedVec::from_parts(dg1, dg1_size as u32);
    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha1::sha1_var(dg1_bounded_vec);

    for i in 0..20 {
        // Check the hash of dg1 is indeed in the e_content
        assert(
            dg1_hash[i] == e_content[dg1_offset_in_e_content + i],
            "Hash of dg1 not found in eContent",
        );
    }
}

/**
* Computes the hash (using SHA1) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha1<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: [u8; 700],
    e_content_size: u32,
) {
    let e_content_bounded_vec = BoundedVec::from_parts(e_content, e_content_size as u32);

    let computed_final_hash = sha1::sha1_var(e_content_bounded_vec);
    // Safety: get the index of the computed final hash in the signed attributes
    // Then check if at that position the hash is the same as the computed final hash
    let index = unsafe { _find_subarray_index(signed_attributes, computed_final_hash) };

    for i in 0..20 {
        // The last 20 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(
            computed_final_hash[i] == signed_attributes[index + i],
            "Computed final hash not found in signed attributes",
        );
    }
}

/**
* Computes the hash (using SHA2-224) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha224(dg1: [u8; 95], e_content: [u8; 700], dg1_offset_in_e_content: u32) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        dg1_size = 95;
    }

    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha224_var(dg1, dg1_size as u64);

    for i in 0..28 {
        // Check the hash of dg1 is indeed in the e_content
        assert(
            dg1_hash[i] == e_content[dg1_offset_in_e_content + i],
            "Hash of dg1 not found in eContent",
        );
    }
}

/**
* Computes the hash (using SHA2-224) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha224<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: [u8; 700],
    e_content_size: u32,
) {
    let computed_final_hash = sha224_var(e_content, e_content_size as u64);
    // Safety: get the index of the computed final hash in the signed attributes
    // Then check if at that position the hash is the same as the computed final hash
    let index = unsafe { _find_subarray_index(signed_attributes, computed_final_hash) };
    for i in 0..28 {
        // The last 28 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(
            computed_final_hash[i] == signed_attributes[index + i],
            "Computed final hash not found in signed attributes",
        );
    }
}

/**
* Computes the hash (using SHA2-256) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha256(dg1: [u8; 95], e_content: [u8; 700], dg1_offset_in_e_content: u32) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        dg1_size = 95;
    }

    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha256_var(dg1, dg1_size as u64);

    for i in 0..32 {
        // Check the hash of dg1 is indeed in the e_content
        assert(
            dg1_hash[i] == e_content[dg1_offset_in_e_content + i],
            "Hash of dg1 not found in eContent",
        );
    }
}

/**
* Computes the hash (using SHA2-256) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha256<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: [u8; 700],
    e_content_size: u32,
) {
    let computed_final_hash = sha256_var(e_content, e_content_size as u64);
    // Safety: get the index of the computed final hash in the signed attributes
    // Then check if at that position the hash is the same as the computed final hash
    let index = unsafe { _find_subarray_index(signed_attributes, computed_final_hash) };
    for i in 0..32 {
        // The last 32 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(
            computed_final_hash[i] == signed_attributes[index + i],
            "Computed final hash not found in signed attributes",
        );
    }
}

/**
* Computes the hash (using SHA2-384) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha384(dg1: [u8; 95], e_content: [u8; 700], dg1_offset_in_e_content: u32) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        dg1_size = 95;
    }

    let dg1_bounded_vec = BoundedVec::from_parts(dg1, dg1_size as u32);
    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha384::sha384_var(dg1_bounded_vec);

    for i in 0..48 {
        // Check the hash of dg1 is indeed in the e_content
        assert(
            dg1_hash[i] == e_content[dg1_offset_in_e_content + i],
            "Hash of dg1 not found in eContent",
        );
    }
}

/**
* Computes the hash (using SHA2-384) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha384<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: [u8; 700],
    e_content_size: u32,
) {
    let e_content_bounded_vec = BoundedVec::from_parts(e_content, e_content_size as u32);

    let computed_final_hash = sha384::sha384_var(e_content_bounded_vec);
    // Safety: get the index of the computed final hash in the signed attributes
    // Then check if at that position the hash is the same as the computed final hash
    let index = unsafe { _find_subarray_index(signed_attributes, computed_final_hash) };

    for i in 0..48 {
        // The last 48 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(
            computed_final_hash[i] == signed_attributes[index + i],
            "Computed final hash not found in signed attributes",
        );
    }
}

/**
* Computes the hash (using SHA2-512) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha512(dg1: [u8; 95], e_content: [u8; 700], dg1_offset_in_e_content: u32) {
    // For passports we ignore the last padding characters
    let mut dg1_size: u64 = 93;

    // If it's an ID card then the array should not have any padding
    // character
    if is_id_card(dg1) {
        dg1_size = 95;
    }

    let dg1_bounded_vec = BoundedVec::from_parts(dg1, dg1_size as u32);
    // We only need to recompute the hash of the MRZ (or more accurately that of Data Group 1)
    // within the circuit as this is the only data group we use to build the proof (age, country, etc.)
    let dg1_hash = sha512::sha512_var(dg1_bounded_vec);

    for i in 0..64 {
        // Check the hash of dg1 is indeed in the e_content
        assert(
            dg1_hash[i] == e_content[dg1_offset_in_e_content + i],
            "Hash of dg1 not found in eContent",
        );
    }
}

/**
* Computes the hash (using SHA2-512) of eContent (containing the hashes of the data groups) and checks it is the same as the one
* included in the signed_attributes, which is the message signed by the Document Signing Certificate (DSC)
*/
pub fn check_signed_attributes_sha512<let SA_SIZE: u32>(
    signed_attributes: [u8; SA_SIZE],
    e_content: [u8; 700],
    e_content_size: u32,
) {
    let e_content_bounded_vec = BoundedVec::from_parts(e_content, e_content_size as u32);

    let computed_final_hash = sha512::sha512_var(e_content_bounded_vec);
    // Safety: get the index of the computed final hash in the signed attributes
    // Then check if at that position the hash is the same as the computed final hash
    let index = unsafe { _find_subarray_index(signed_attributes, computed_final_hash) };

    for i in 0..64 {
        // The last 64 bytes of the signed_attributes are the hash of the data groups
        // The rest is padding and the signature date, not important to check
        assert(
            computed_final_hash[i] == signed_attributes[index + i],
            "Computed final hash not found in signed attributes",
        );
    }
}
