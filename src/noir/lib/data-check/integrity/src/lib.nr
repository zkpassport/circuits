use sha1::sha1;
use sha256::{sha224_var, sha256_var};
use sha512::{sha384, sha512};
use utils::{find_subarray_index, is_id_card, is_subarray_in_array};

/**
* Computes the hash (using SHA1) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha1(dg1: [u8; 95], e_content: [u8; 700], e_content_size: u32) {
    assert(e_content_size <= 700, "eContent size is too large");

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

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(dg1_offset_in_e_content + 20 <= e_content_size, "Hash of dg1 not found in eContent");
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

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}

/**
* Computes the hash (using SHA2-224) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha224(dg1: [u8; 95], e_content: [u8; 700], e_content_size: u32) {
    assert(e_content_size <= 700, "eContent size is too large");

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

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(dg1_offset_in_e_content + 28 <= e_content_size, "Hash of dg1 not found in eContent");
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

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}

/**
* Computes the hash (using SHA2-256) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha256(dg1: [u8; 95], e_content: [u8; 700], e_content_size: u32) {
    assert(e_content_size <= 700, "eContent size is too large");

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

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(dg1_offset_in_e_content + 32 <= e_content_size, "Hash of dg1 not found in eContent");
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

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}

/**
* Computes the hash (using SHA2-384) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha384(dg1: [u8; 95], e_content: [u8; 700], e_content_size: u32) {
    assert(e_content_size <= 700, "eContent size is too large");

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

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(dg1_offset_in_e_content + 48 <= e_content_size, "Hash of dg1 not found in eContent");
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

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}

/**
* Computes the hash (using SHA2-512) of the first data group (containing the MRZ) and checks it is the same as the one
* included in eContent at the offset provided (along with the rest of the data group hashes)
*/
pub fn check_dg1_sha512(dg1: [u8; 95], e_content: [u8; 700], e_content_size: u32) {
    assert(e_content_size <= 700, "eContent size is too large");

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

    // Find the offset of the hash of dg1 in e_content
    let dg1_offset_in_e_content = find_subarray_index(dg1_hash, e_content);
    // Check that the hash of dg1 is in the e_content, we use the actual size rather than generic size
    // of econtent to ignore the padding bytes at the end
    assert(dg1_offset_in_e_content + 64 <= e_content_size, "Hash of dg1 not found in eContent");
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

    // Check that the computed final hash is in the signed attributes
    assert(
        is_subarray_in_array(computed_final_hash, signed_attributes),
        "Computed final hash not found in signed attributes",
    );
}
