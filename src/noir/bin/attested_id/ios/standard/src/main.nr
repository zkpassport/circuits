/*
############################################################
# Attested ID (iOS)
############################################################
# The base proof of a Tier 2 verification: an ID read by camera, with no chip whose signed
# data could be verified. In place of the three chip base proofs, it verifies that a genuine
# device running the unmodified app attested, through Apple App Attest, the DG1 it read
# together with the portrait it matched against a live face in strict mode.
#
# It outputs the same commitment as the integrity check circuit, so the disclosure circuits
# (and a later facematch proof) take it as `comm_in` unchanged.
#
# Outputs
############################################################
# comm_out -> commitment over the salted DG1, expiry date, attested digest and private nullifier
# param_commitment -> commitment over the attestation root key, environment, app ID and mode,
#                     checked outside the circuit as for the facematch circuit
*/

use commitment::{calculate_attested_digest, commit_to_disclosure_attested};
use facematch::{
    calculate_attestation_registry_leaf,
    get_dg2_hash_from_client_data,
    get_facematch_mode_from_client_data,
    ios::{get_app_id_from_credential_tbs, verify_auth_data_and_client_data, verify_environment},
    verify_credential_certificate,
    verify_intermediate_certificate,
};
use facematch::constants::{
    APP_ID_MAX_LEN, ATTESTATION_KEY_TYPE_APPLE, AUTH_DATA_MAX_LEN, CLIENT_DATA_MAX_LEN,
    CREDENTIAL_TBS_MAX_LEN, FACEMATCH_MODE_STRICT,
};
use facematch::param_commit::calculate_param_commitment;
use utils::{
    constants::SHA256_IDENTIFIER,
    poseidon2_hash_packed,
    split_array,
    types::{DG1Data, SaltedValue},
};

fn main(
    salted_dg1: SaltedValue<DG1Data>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    private_nullifier_salt: Field,
    // SHA-256 of the portrait the face was matched against
    portrait_hash: [u8; 32],
    // @committed
    // Hash of root_key (the attestation registry leaf) is committed to (via parameter commitment) and can be verified outside the circuit
    root_key: [u8; 96],
    intermediate_key: [u8; 96],
    intermediate_tbs: [u8; 500],
    intermediate_sig: [u8; 96],
    credential_tbs: [u8; CREDENTIAL_TBS_MAX_LEN],
    credential_sig: [u8; 96],
    auth_data: [u8; AUTH_DATA_MAX_LEN],
    client_data: [u8; CLIENT_DATA_MAX_LEN],
    // @committed
    // environment is committed to (via parameter commitment) and can be verified outside the circuit
    environment: u8, // APP_ATTEST_ENV_DEVELOPMENT (0) or APP_ATTEST_ENV_PRODUCTION (1)
    // @committed
    // Hash of app_id is committed to (via parameter commitment) and can be verified outside the circuit
    app_id: [u8; APP_ID_MAX_LEN],
) -> pub (Field, Field) {
    // Split the root and intermediate key into x and y coordinates
    let (root_key_x, root_key_y) = split_array(root_key);
    let (intermediate_key_x, intermediate_key_y) = split_array(intermediate_key);

    let root_key_leaf = calculate_attestation_registry_leaf(ATTESTATION_KEY_TYPE_APPLE, root_key);
    // Verify the intermediate certificate was signed by the root key
    // and the intermediate public key is in the intermediate certificate TBS
    assert(
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
    assert(
        verify_credential_certificate(
            intermediate_key_x,
            intermediate_key_y,
            credential_tbs,
            credential_sig,
        ),
        "Failed to verify credential certificate",
    );

    // Verify the integrity of auth_data and client_data using the credential certificate TBS nonce
    assert(
        verify_auth_data_and_client_data(credential_tbs, auth_data, client_data),
        "Failed to verify auth_data and client_data",
    );

    // Verify the environment in auth_data matches the expected environment
    assert(
        verify_environment(environment, auth_data),
        "Failed to verify environment: AAGUID mismatch",
    );

    // Verify the app ID in the credential certificate TBS matches the expected app ID
    let (tbs_app_id, app_id_length): ([u8; APP_ID_MAX_LEN], u32) =
        get_app_id_from_credential_tbs(credential_tbs);
    assert(tbs_app_id == app_id, "Failed to verify app_id");

    // The face match is the only thing binding a camera-read ID to a person, so it must be strict
    assert(
        get_facematch_mode_from_client_data(client_data) == FACEMATCH_MODE_STRICT,
        "Tier 2 requires a strict face match",
    );

    // The device attests one digest in the DG2 hash slot: SHA-256 over the DG1 it read and
    // the hash of the portrait it matched. Recomputing it binds both to this proof.
    let (attested_digest, attested_digest_len) = get_dg2_hash_from_client_data(client_data);
    assert(attested_digest_len == 32, "Attested digest must be a SHA-256 digest");
    let expected_digest = calculate_attested_digest(salted_dg1.value, portrait_hash);
    for i in 0..32 {
        assert(
            attested_digest[i] == expected_digest[i],
            "Attested digest does not match DG1 and portrait",
        );
    }

    let (comm_out, _private_nullifier) = commit_to_disclosure_attested(
        salted_dg1,
        expiry_date_salt,
        dg2_hash_salt,
        SaltedValue::from_value(dg2_hash_salt, SHA256_IDENTIFIER),
        private_nullifier_salt,
        expected_digest,
    );

    let app_id_hash = poseidon2_hash_packed(app_id, app_id_length);
    // Since the integrity public key hash is only for Android, we set it to 0 for iOS
    let param_commitment = calculate_param_commitment(
        root_key_leaf,
        environment,
        app_id_hash,
        0,
        FACEMATCH_MODE_STRICT,
    );

    (comm_out, param_commitment)
}
