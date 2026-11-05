// This is an auto-generated file, to change the code please edit: src/ts/scripts/circuit-builder.ts
// Hardware attestation variant: the device and app are vouched for by Android key attestation
// alone (locked bootloader, verified boot with the OEM key or an allowlisted one, recent
// security patch, APK signing digest), with no Play Integrity verdict. Only chains under
// Google's ECDSA root are accepted, which remote key provisioning issues per device.
use commitment::nullify;
use data_check_expiry::check_expiry_from_date;
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
use utils::{
    poseidon2_hash_packed,
    split_array,
    types::{DG1Data, MRZExpiryDate, SaltedValue},
    unsafe_get_asn1_element_length,
};

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
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
    intermediate_2_key: [u8; 64],
    intermediate_2_tbs: [u8; 700],
    // ecdsa signature from the intermediate certificate #1 over the intermediate certificate #2 TBS
    intermediate_2_sig: [u8; 96],
    // Shows the serial number of intermediate certificate #2 is not in the revocation tree
    intermediate_2_revocation_proof: RevocationProof,
    intermediate_3_key: [u8; 96],
    intermediate_3_tbs: [u8; 700],
    // ecdsa signature from the intermediate certificate #2 over the intermediate certificate #3 TBS
    intermediate_3_sig: [u8; 64],
    // Shows the serial number of intermediate certificate #3 is not in the revocation tree
    intermediate_3_revocation_proof: RevocationProof,
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
    // facematch_mode is commitment to (via parameter commitment) and can be verified outside the circuit
    facematch_mode: u8, // FACEMATCH_MODE_REGULAR (1) or FACEMATCH_MODE_STRICT (2)
    // @committed
    // The root of the allowlist of user-installed verified boot keys (e.g. GrapheneOS, per device)
    // is committed to (via parameter commitment) and can be verified outside the circuit
    boot_key_allowlist_root: Field,
    // Position of the device's verified boot key in the allowlist, only checked when the OS
    // booted with a user-installed key
    boot_key_index: Field,
    boot_key_path: [Field; ANDROID_BOOT_KEY_ALLOWLIST_DEPTH],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field, Field) {
    // Check the ID is not expired
    check_expiry_from_date(salted_expiry_date.value, current_date);

    let (intermediate_1_key_x, intermediate_1_key_y) = split_array(intermediate_1_key);

    let (intermediate_2_key_x, intermediate_2_key_y) = split_array(intermediate_2_key);

    let (intermediate_3_key_x, intermediate_3_key_y) = split_array(intermediate_3_key);

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

    let (intermediate_2_key_x, intermediate_2_key_y) = split_array(intermediate_2_key);
    verify_ecdsa_pubkey_in_tbs(
        intermediate_2_key_x,
        intermediate_2_key_y,
        intermediate_2_tbs,
    );
    let (intermediate_2_sig_r, intermediate_2_sig_s) = split_array(intermediate_2_sig);
    let intermediate_2_tbs_hash = get_tbs_hash_sha256(intermediate_2_tbs);

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

    let (intermediate_3_key_x, intermediate_3_key_y) = split_array(intermediate_3_key);
    verify_ecdsa_pubkey_in_tbs(
        intermediate_3_key_x,
        intermediate_3_key_y,
        intermediate_3_tbs,
    );
    let (intermediate_3_sig_r, intermediate_3_sig_s) = split_array(intermediate_3_sig);
    let intermediate_3_tbs_hash = get_tbs_hash_sha256(intermediate_3_tbs);

    assert(
        verify_nist_p256(
            intermediate_2_key_x,
            intermediate_2_key_y,
            intermediate_3_sig_r,
            intermediate_3_sig_s,
            intermediate_3_tbs_hash,
        ),
        "Failed to verify intermediate certificate",
    );

    let (credential_key_x, credential_key_y) = split_array(credential_key);
    verify_ecdsa_pubkey_in_tbs(credential_key_x, credential_key_y, credential_tbs);

    let (credential_sig_r, credential_sig_s) = split_array(credential_sig);

    let credential_tbs_hash = get_tbs_hash_sha256(credential_tbs);

    assert(
        verify_nist_p384(
            intermediate_3_key_x,
            intermediate_3_key_y,
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

    assert_serial_not_revoked(
        revocation_root,
        get_tbs_serial_number(intermediate_2_tbs),
        intermediate_2_revocation_proof,
    );

    assert_serial_not_revoked(
        revocation_root,
        get_tbs_serial_number(intermediate_3_tbs),
        intermediate_3_revocation_proof,
    );

    // Verify the app ID in the credential certificate TBS matches the expected app ID
    let key_description = get_key_description::<_, APP_ID_MAX_LEN>(credential_tbs);
    let tbs_app_id = key_description.app_id;
    let app_id_length = key_description.app_id_length;
    assert(tbs_app_id == app_id, "Failed to verify app_id");

    // Verify the facematch mode in client_data matches the expected facematch mode
    assert(
        get_facematch_mode_from_client_data(client_data) == facematch_mode,
        "Failed to verify facematch_mode in client_data",
    );

    // Verify the normalized dg2_hash in client_data matches the expected normalized dg2_hash
    assert(
        verify_dg2_hash_in_client_data(salted_dg2_hash.value, client_data),
        "Failed to verify dg2_hash in client_data",
    );

    verify_hardware_device_state(
        key_description,
        boot_key_allowlist_root,
        boot_key_index,
        boot_key_path,
        current_date,
    );

    // Facematch circuit does not use OPRF proof. Pass a zero OPRF proof so nullify skips OPRF verification.
    let zero_oprf_proof = commitment::OPRFProof {
        pk: commitment::BabyJubJubPoint { x: 0, y: 0 },
        dlog_e: 0,
        dlog_s: 0,
        response_blinded: commitment::BabyJubJubPoint { x: 0, y: 0 },
        response: commitment::BabyJubJubPoint { x: 0, y: 0 },
        beta: 0,
    };
    let (nullifier, nullifier_type, oprf_pk_hash) = nullify(
        comm_in,
        salted_dg1,
        salted_expiry_date,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
        zero_oprf_proof,
    );

    let app_id_hash = poseidon2_hash_packed(app_id, app_id_length);
    let integrity_anchor = calculate_hardware_integrity_anchor(
        boot_key_allowlist_root,
        key_description.app_signing_digest,
    );
    let param_commitment = calculate_param_commitment_sha2(
        root_key_leaf,
        environment,
        app_id_hash,
        integrity_anchor,
        facematch_mode,
        revocation_root,
    );

    (param_commitment, nullifier_type, nullifier, oprf_pk_hash)
}
