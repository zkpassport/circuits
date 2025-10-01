// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::nullify;
use data_check_tbs_pubkey::{verify_ecdsa_pubkey_in_tbs, verify_rsa_pubkey_in_tbs};
use facematch::{
    android::get_app_id_from_credential_tbs, calculate_attestation_registry_leaf,
    get_client_data_hash_for_signature, get_facematch_mode_from_client_data, get_tbs_hash_sha256,
    get_tbs_hash_sha384, verify_credential_certificate, verify_dg2_hash_in_client_data,
    verify_intermediate_certificate,
};
use facematch::constants::{
    APP_ID_MAX_LEN, ATTESTATION_KEY_TYPE_GOOGLE, CLIENT_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN,
};
use facematch::param_commit::{calculate_param_commitment, calculate_param_commitment_sha2};
use sig_check_ecdsa::{verify_nist_p256_blackbox as verify_nist_p256, verify_nist_p384};
use sig_check_rsa::verify_signature;
use utils::{poseidon2_hash_packed, split_array, types::DG1Data, unsafe_get_asn1_element_length};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    dg2_hash_normalized: Field,
    dg2_hash_type: u32,
    // @committed
    // Hash of root_key (the attestation registry leaf) is commitment to (via parameter commitment) and can be verified outside the circuit
    // There are only two possible root keys, right now the RSA one is the only one used
    // but the new one to be rolled out in February 2026 will be ECDSA P384 so both should be supported
    // c.f. https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
    root_key: [u8; 512],
    root_key_redc_param: [u8; 513],
    // Intermediate certificates from up (root) to bottom (leaf/credential) of the chain
    intermediate_1_key: [u8; 96],
    intermediate_1_tbs: [u8; 500],
    // RSA signature from the root over the intermediate certificate #1 TBS
    intermediate_1_sig: [u8; 512],
    intermediate_2_key: [u8; 512],
    intermediate_2_key_redc_param: [u8; 513],
    intermediate_2_tbs: [u8; 1000],
    // ecdsa signature from the intermediate certificate #1 over the intermediate certificate #2 TBS
    intermediate_2_sig: [u8; 96],
    intermediate_3_key: [u8; 512],
    intermediate_3_key_redc_param: [u8; 513],
    intermediate_3_tbs: [u8; 1000],
    // rsa signature from the intermediate certificate #2 over the intermediate certificate #3 TBS
    intermediate_3_sig: [u8; 512],
    // This is the leaf certificate derived from the private key in the KeyStore
    // so we have control over the signature algorithm used (i.e P-256 with SHA256)
    // so client_data_sig will always be P-256 with SHA256
    credential_key: [u8; 64],
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    // P-256 signature from the third intermediate certificate over the credential certificate TBS
    credential_sig: [u8; 512],
    client_data: [u8; CLIENT_DATA_MAX_LEN],
    // P-256 signature from the credential (i.e. leaf) certificate over the client data TBS
    client_data_sig: [u8; 64],
    // @committed
    // environment is commitment to (via parameter commitment) and can be verified outside the circuit
    environment: u8, // APP_ATTEST_ENV_DEVELOPMENT (0) or APP_ATTEST_ENV_PRODUCTION (1)
    // @committed
    // Hash of app_id is commitment to (via parameter commitment) and can be verified outside the circuit
    app_id: [u8; APP_ID_MAX_LEN],
    // @committed
    // facematch_mode is commitment to (via parameter commitment) and can be verified outside the circuit
    facematch_mode: u8, // FACEMATCH_MODE_REGULAR (1) or FACEMATCH_MODE_STRICT (2)
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    let (intermediate_1_key_x, intermediate_1_key_y) = split_array(intermediate_1_key);

    let root_key_leaf = calculate_attestation_registry_leaf(ATTESTATION_KEY_TYPE_GOOGLE, root_key);

    // Verify the intermediate certificate was signed by the root key
    // and the intermediate public key is in the intermediate certificate TBS

    verify_ecdsa_pubkey_in_tbs(
        intermediate_1_key_x,
        intermediate_1_key_y,
        intermediate_1_tbs,
    );

    let intermediate_1_tbs_len = unsafe { unsafe_get_asn1_element_length(intermediate_1_tbs) };

    assert(
        verify_signature::<_, 0, _, 32>(
            root_key,
            intermediate_1_sig,
            root_key_redc_param,
            65537,
            intermediate_1_tbs,
            intermediate_1_tbs_len,
        ),
        "Failed to verify intermediate certificate",
    );

    verify_rsa_pubkey_in_tbs(intermediate_2_key, intermediate_2_tbs);
    let (intermediate_2_sig_r, intermediate_2_sig_s) = split_array(intermediate_2_sig);
    let intermediate_2_tbs_hash = get_tbs_hash_sha384(intermediate_2_tbs);

    assert(
        verify_nist_p384(
            intermediate_1_key_x,
            intermediate_1_key_y,
            intermediate_2_sig_r,
            intermediate_2_sig_s,
            intermediate_2_tbs_hash,
        ),
        "Failed to verify intermediate certificate",
    );

    verify_rsa_pubkey_in_tbs(intermediate_3_key, intermediate_3_tbs);
    let (intermediate_3_sig_r, intermediate_3_sig_s) = split_array(intermediate_3_sig);
    let intermediate_3_tbs_hash = get_tbs_hash_sha256(intermediate_3_tbs);

    let intermediate_3_tbs_len = unsafe { unsafe_get_asn1_element_length(intermediate_3_tbs) };
    assert(
        verify_signature::<_, 0, _, 32>(
            intermediate_2_key,
            intermediate_3_sig,
            intermediate_2_key_redc_param,
            65537,
            intermediate_3_tbs,
            intermediate_3_tbs_len,
        ),
        "Failed to verify intermediate certificate",
    );

    let (credential_key_x, credential_key_y) = split_array(credential_key);
    verify_ecdsa_pubkey_in_tbs(credential_key_x, credential_key_y, credential_tbs);

    let credential_tbs_hash = get_tbs_hash_sha256(credential_tbs);

    let credential_tbs_len = unsafe { unsafe_get_asn1_element_length(credential_tbs) };
    assert(
        verify_signature::<_, 0, _, 32>(
            intermediate_3_key,
            credential_sig,
            intermediate_3_key_redc_param,
            65537,
            credential_tbs,
            credential_tbs_len,
        ),
        "Failed to verify credential certificate",
    );

    let (client_data_sig_r, client_data_sig_s) = split_array(client_data_sig);
    let client_data_len = unsafe { unsafe_get_asn1_element_length(client_data) };
    let client_data_hash = get_client_data_hash_for_signature(client_data, client_data_len);
    assert(
        verify_nist_p256(
            credential_key_x,
            credential_key_y,
            client_data_sig_r,
            client_data_sig_s,
            client_data_hash,
        ),
        "Failed to verify client data hash",
    );

    // Verify the app ID in the credential certificate TBS matches the expected app ID
    let (tbs_app_id, app_id_length): ([u8; APP_ID_MAX_LEN], u32) =
        get_app_id_from_credential_tbs(credential_tbs);
    assert(tbs_app_id == app_id, "Failed to verify app_id");

    // Verify the facematch mode in client_data matches the expected facematch mode
    assert(
        get_facematch_mode_from_client_data(client_data) == facematch_mode,
        "Failed to verify facematch_mode in client_data",
    );

    // Verify the normalized dg2_hash in client_data matches the expected normalized dg2_hash
    assert(
        verify_dg2_hash_in_client_data(dg2_hash_normalized, client_data),
        "Failed to verify dg2_hash in client_data",
    );

    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salt,
        dg1,
        dg2_hash_normalized,
        dg2_hash_type,
        private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );

    let app_id_hash = poseidon2_hash_packed(app_id, app_id_length);
    let param_commitment =
        calculate_param_commitment(root_key_leaf, environment, app_id_hash, facematch_mode);

    (param_commitment, nullifier_type, nullifier)
}
