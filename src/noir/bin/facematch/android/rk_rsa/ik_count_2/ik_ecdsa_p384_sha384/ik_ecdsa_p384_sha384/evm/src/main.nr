// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
use commitment::nullify;
use data_check_expiry::check_expiry;
use data_check_tbs_pubkey::{verify_ecdsa_pubkey_in_tbs, verify_rsa_pubkey_in_tbs};
use facematch::{
    android::{
        constants::INTEGRITY_TOKEN_MAX_LENGTH,
        get_app_id_from_credential_tbs,
        token::{
            parse_integrity_token, verify_integrity_token, verify_integrity_token_signature,
            verify_nonce,
        },
    },
    calculate_attestation_registry_leaf,
    get_client_data_hash,
    get_facematch_mode_from_client_data,
    get_tbs_hash_sha256,
    get_tbs_hash_sha384,
    prepare_client_data_hash_for_signature,
    verify_dg2_hash_in_client_data,
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
    current_date: pub u64,
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
    intermediate_2_key: [u8; 96],
    intermediate_2_tbs: [u8; 500],
    // ecdsa signature from the intermediate certificate #1 over the intermediate certificate #2 TBS
    intermediate_2_sig: [u8; 96],
    // This is the leaf certificate derived from the private key in the KeyStore
    // so we have control over the signature algorithm used (i.e P-256 with SHA256)
    // so client_data_sig will always be P-256 with SHA256
    credential_key: [u8; 64],
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    // ecdsa signature from the third intermediate certificate over the credential certificate TBS
    credential_sig: [u8; 96],
    client_data: [u8; CLIENT_DATA_MAX_LEN],
    // P-256 signature from the credential (i.e. leaf) certificate over the client data TBS
    client_data_sig: [u8; 64],
    // @committed
    // environment is committed to (via parameter commitment) and can be verified outside the circuit
    environment: u8, // APP_ATTEST_ENV_DEVELOPMENT (0) or APP_ATTEST_ENV_PRODUCTION (1)
    // @committed
    // Hash of app_id is committed to (via parameter commitment) and can be verified outside the circuit
    app_id: [u8; APP_ID_MAX_LEN],
    // @committed
    // facematch_mode is commitment to (via parameter commitment) and can be verified outside the circuit
    facematch_mode: u8, // FACEMATCH_MODE_REGULAR (1) or FACEMATCH_MODE_STRICT (2)
    // The bytes of the JSON integrity token from Play Integrity API
    integrity_token: [u8; INTEGRITY_TOKEN_MAX_LENGTH],
    // The signature over the integrity token (ECDSA P-256 with SHA-256)
    integrity_token_signature: [u8; 64],
    // @committed
    // Hash of play_integrity_public_key is committed to (via parameter commitment) and can be verified outside the circuit
    // Play Integrity's public key behind the signature over the integrity token
    play_integrity_public_key: [u8; 64],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(dg1, current_date);

    let (intermediate_1_key_x, intermediate_1_key_y) = split_array(intermediate_1_key);

    let (intermediate_2_key_x, intermediate_2_key_y) = split_array(intermediate_2_key);

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

    let (intermediate_2_key_x, intermediate_2_key_y) = split_array(intermediate_2_key);
    verify_ecdsa_pubkey_in_tbs(
        intermediate_2_key_x,
        intermediate_2_key_y,
        intermediate_2_tbs,
    );
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

    let (credential_key_x, credential_key_y) = split_array(credential_key);
    verify_ecdsa_pubkey_in_tbs(credential_key_x, credential_key_y, credential_tbs);

    let (credential_sig_r, credential_sig_s) = split_array(credential_sig);

    let credential_tbs_hash = get_tbs_hash_sha384(credential_tbs);

    assert(
        verify_nist_p384(
            intermediate_2_key_x,
            intermediate_2_key_y,
            credential_sig_r,
            credential_sig_s,
            credential_tbs_hash,
        ),
        "Failed to verify credential certificate",
    );

    let (client_data_sig_r, client_data_sig_s) = split_array(client_data_sig);
    let client_data_len = unsafe { unsafe_get_asn1_element_length(client_data) };
    let client_data_hash = get_client_data_hash(client_data, client_data_len);
    assert(
        verify_nist_p256(
            credential_key_x,
            credential_key_y,
            client_data_sig_r,
            client_data_sig_s,
            prepare_client_data_hash_for_signature(client_data_hash),
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

    // Verify the integrity token
    let parsed_integrity_token = parse_integrity_token(integrity_token);
    let integrity_token_response =
        verify_integrity_token(parsed_integrity_token, app_id, app_id_length);
    assert(
        integrity_token_response.environment == environment,
        "Failed to verify integrity token environment",
    );

    // Verify the signature over the integrity token
    let (play_integrity_public_key_x, play_integrity_public_key_y) =
        split_array(play_integrity_public_key);
    assert(
        verify_integrity_token_signature(
            integrity_token,
            play_integrity_public_key_x,
            play_integrity_public_key_y,
            integrity_token_signature,
        ),
        "Failed to verify integrity token signature",
    );

    // Verify the nonce
    assert(
        verify_nonce(
            integrity_token_response.nonce,
            client_data_hash,
            client_data_sig,
        ),
        "Failed to verify nonce from integrity token",
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
    let play_integrity_public_key_hash =
        poseidon2_hash_packed(play_integrity_public_key, play_integrity_public_key.len());
    let param_commitment = calculate_param_commitment_sha2(
        root_key_leaf,
        environment,
        app_id_hash,
        play_integrity_public_key_hash,
        facematch_mode,
    );

    (param_commitment, nullifier_type, nullifier)
}
