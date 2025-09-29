use commitment::nullify;
use facematch::{
    calculate_attestation_registry_leaf, android::{get_app_id_from_credential_tbs},
    get_facematch_mode_from_client_data,
    verify_credential_certificate, verify_dg2_hash_in_client_data,
    verify_intermediate_certificate,
};
use facematch::constants::{
    ATTESTATION_KEY_TYPE_GOOGLE, APP_ID_MAX_LEN, AUTH_DATA_MAX_LEN, CLIENT_DATA_MAX_LEN,
    CREDENTIAL_TBS_MAX_LEN,
};
use facematch::param_commit::calculate_param_commitment_sha2;
use utils::{poseidon2_hash_packed, split_array, types::DG1Data};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    dg2_hash_normalized: Field,
    dg2_hash_type: u32,
    // @committed
    // Hash of root_key (the attestation registry leaf) is commitment to (via parameter commitment) and can be verified outside the circuit
    root_key: [u8; 512],
    intermediate_key: [u8; 96],
    intermediate_tbs: [u8; 500],
    intermediate_sig: [u8; 96],
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    credential_sig: [u8; 96],
    auth_data: [u8; AUTH_DATA_MAX_LEN],
    client_data: [u8; CLIENT_DATA_MAX_LEN],
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
    // Split the root and intermediate key into x and y coordinates
    let (root_key_x, root_key_y) = split_array(root_key);
    let (intermediate_key_x, intermediate_key_y) = split_array(intermediate_key);

    let root_key_leaf = calculate_attestation_registry_leaf(ATTESTATION_KEY_TYPE_GOOGLE, root_key);
    // Verify the intermediate certificate was signed by the root key
    // and the intermediate public key is in the intermediate certificate TBS
    /*assert(
        verify_intermediate_certificate(
            root_key_x,
            root_key_y,
            intermediate_key_x,
            intermediate_key_y,
            intermediate_tbs,
            intermediate_sig,
        ),
        "Failed to verify intermediate certificate",
    );

    // Verify the credential certificate was signed by the intermediate key
    let (intermediate_key_x, intermediate_key_y) = split_array(intermediate_key);
    assert(
        verify_credential_certificate(
            intermediate_key_x,
            intermediate_key_y,
            credential_tbs,
            credential_sig,
        ),
        "Failed to verify credential certificate",
    );*/

    // Verify the integrity of auth_data and client_data using the credential certificate TBS nonce
    /*assert(
        verify_auth_data_and_client_data(credential_tbs, auth_data, client_data),
        "Failed to verify auth_data and client_data",
    );

    // Verify the environment in auth_data matches the expected environment
    assert(
        verify_environment(environment, auth_data),
        "Failed to verify environment: AAGUID mismatch",
    );*/

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
        calculate_param_commitment_sha2(root_key_leaf, environment, app_id_hash, facematch_mode);

    (param_commitment, nullifier_type, nullifier)
}
