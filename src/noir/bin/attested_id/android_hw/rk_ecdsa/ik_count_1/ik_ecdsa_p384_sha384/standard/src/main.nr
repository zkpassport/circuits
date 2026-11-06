// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
// Attested ID (Android): the base proof of a Tier 2 verification on Android. In place of the
// three chip base proofs, it verifies that a genuine device running the unmodified app attested,
// through Android key attestation, the DG1 it read together with the portrait it matched against
// a live face in strict mode. It outputs the same commitment as the integrity check circuit.
// Hardware attestation variant: the device and app are vouched for by Android key attestation
// alone (locked bootloader, verified boot with the OEM key or an allowlisted one, recent
// security patch, APK signing digest), with no Play Integrity verdict. Only chains under
// Google's ECDSA root are accepted, which remote key provisioning issues per device.
use commitment::{calculate_attested_digest, commit_to_disclosure_attested};
use data_check_tbs_pubkey::{verify_ecdsa_pubkey_in_tbs, verify_rsa_pubkey_in_tbs};
use facematch::{
    android::{
        constants::ANDROID_BOOT_KEY_ALLOWLIST_DEPTH,
        get_key_description,
        get_tbs_serial_number,
        hardware::{
            assert_serial_not_revoked, calculate_hardware_integrity_anchor, RevocationProof,
            verify_hardware_device_state,
        },
    },
    calculate_attestation_registry_leaf,
    get_client_data_hash,
    get_dg2_hash_from_client_data,
    get_facematch_mode_from_client_data,
    get_tbs_hash_sha256,
    get_tbs_hash_sha384,
    prepare_client_data_hash_for_signature,
};
use facematch::constants::{
    APP_ID_MAX_LEN, ATTESTATION_KEY_TYPE_GOOGLE, CLIENT_DATA_MAX_LEN, CREDENTIAL_TBS_MAX_LEN,
    FACEMATCH_MODE_STRICT,
};
use facematch::param_commit::{calculate_param_commitment, calculate_param_commitment_sha2};
use sig_check_ecdsa::{verify_nist_p256_blackbox as verify_nist_p256, verify_nist_p384};
use sig_check_rsa::verify_signature;
use utils::{
    constants::{CREDENTIAL_SCHEME_ATTESTED_CAPTURE_ANDROID, SHA256_IDENTIFIER},
    poseidon2_hash_packed,
    split_array,
    types::{DG1Data, SaltedValue},
    unsafe_get_asn1_element_length,
};

fn main(
    // The device state and attestation freshness are checked against it, so the verifier
    // checks it is recent
    current_date: pub u64,
    salted_dg1: SaltedValue<DG1Data>,
    expiry_date_salt: Field,
    dg2_hash_salt: Field,
    private_nullifier_salt: Field,
    // SHA-256 of the portrait the face was matched against
    portrait_hash: [u8; 32],
    // @committed
    // Hash of root_key (the attestation registry leaf) is commitment to (via parameter commitment) and can be verified outside the circuit
    // There are only two possible root keys, one RSA (old) and one ECDSA P384 (new)
    // c.f. https://developer.android.com/privacy-and-security/security-key-attestation#root_certificate
    root_key: [u8; 96],
    // Intermediate certificates from up (root) to bottom (leaf/credential) of the chain
    intermediate_1_key: [u8; 96],
    intermediate_1_tbs: [u8; 700],
    // RSA signature from the root over the intermediate certificate #1 TBS
    intermediate_1_sig: [u8; 96],
    // Shows the serial number of intermediate certificate #1 is not in the revocation tree
    intermediate_1_revocation_proof: RevocationProof,
    // @committed
    // The root of the tree of revoked attestation certificate serial numbers is committed to
    // (via parameter commitment) and can be verified outside the circuit
    revocation_root: Field,
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
    // The root of the allowlist of user-installed verified boot keys (e.g. GrapheneOS, per device)
    // is committed to (via parameter commitment) and can be verified outside the circuit
    boot_key_allowlist_root: Field,
    // Position of the device's verified boot key in the allowlist, only checked when the OS
    // booted with a user-installed key
    boot_key_index: Field,
    boot_key_path: [Field; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
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

    let (root_key_x, root_key_y) = split_array(root_key);
    let intermediate_1_tbs_hash = get_tbs_hash_sha384(intermediate_1_tbs);
    let (intermediate_1_sig_r, intermediate_1_sig_s) = split_array(intermediate_1_sig);
    assert(
        verify_nist_p384(
            root_key_x,
            root_key_y,
            intermediate_1_sig_r,
            intermediate_1_sig_s,
            intermediate_1_tbs_hash,
        ),
        "Failed to verify intermediate certificate",
    );

    let (credential_key_x, credential_key_y) = split_array(credential_key);
    verify_ecdsa_pubkey_in_tbs(credential_key_x, credential_key_y, credential_tbs);

    let (credential_sig_r, credential_sig_s) = split_array(credential_sig);

    let credential_tbs_hash = get_tbs_hash_sha384(credential_tbs);

    assert(
        verify_nist_p384(
            intermediate_1_key_x,
            intermediate_1_key_y,
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

    assert_serial_not_revoked(
        revocation_root,
        get_tbs_serial_number(intermediate_1_tbs),
        intermediate_1_revocation_proof,
    );

    // Verify the app ID in the credential certificate TBS matches the expected app ID
    let key_description = get_key_description::<_, APP_ID_MAX_LEN>(credential_tbs);
    let tbs_app_id = key_description.app_id;
    let app_id_length = key_description.app_id_length;
    assert(tbs_app_id == app_id, "Failed to verify app_id");

    // The face match is the only thing binding a camera-read ID to a person, so it must be strict
    let facematch_mode = FACEMATCH_MODE_STRICT;
    assert(
        get_facematch_mode_from_client_data(client_data) == facematch_mode,
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

    verify_hardware_device_state(
        key_description,
        boot_key_allowlist_root,
        boot_key_index,
        boot_key_path,
        current_date,
    );

    let (comm_out, _private_nullifier) = commit_to_disclosure_attested(
        salted_dg1,
        expiry_date_salt,
        dg2_hash_salt,
        SaltedValue::from_value(dg2_hash_salt, SHA256_IDENTIFIER),
        private_nullifier_salt,
        expected_digest,
    );

    let app_id_hash = poseidon2_hash_packed(app_id, app_id_length);
    let integrity_anchor = calculate_hardware_integrity_anchor(
        boot_key_allowlist_root,
        key_description.app_signing_digest,
    );
    let param_commitment = calculate_param_commitment(
        root_key_leaf,
        environment,
        app_id_hash,
        integrity_anchor,
        facematch_mode,
        revocation_root,
    );

    (comm_out, param_commitment, CREDENTIAL_SCHEME_ATTESTED_CAPTURE_ANDROID)
}
