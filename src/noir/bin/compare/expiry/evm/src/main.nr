use commitment::nullify;
use compare_date_lib::{calculate_param_commitment_sha2, compare_date, get_expiry_date};
use data_check_expiry::check_expiry;
use utils::{constants::PROOF_TYPE_EXPIRY_DATE, types::{DG1Data, SaltedValue}};
use utils::types::MRZExpiryDate;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    // The minimum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the minimum date timestamp is 0, it is not checked
    min_date: u64,
    // @committed
    // The maximum date required is public so verifiers can check
    // the date provided to the proof is correct
    // If the maximum date timestamp is 0, it is not checked
    max_date: u64,
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(salted_dg1.value, current_date);

    let expiry_date = get_expiry_date(salted_dg1.value, current_date);
    // Verify the expiry date of the ID holder
    // Uses the usual unix epoch year of 1970 as the epoch year as expiry dates are in the future
    // and for expired documents, the expiry date is still way after 1970
    compare_date(expiry_date, min_date, max_date, 1970);
    // Use SHA2-256 to calculate the parameter commitment so the parameter commitment can be
    // reconstructed by verifiers on EVM chains
    let param_commitment =
        calculate_param_commitment_sha2(PROOF_TYPE_EXPIRY_DATE, min_date, max_date);
    let (nullifier, nullifier_type) = nullify(
        comm_in,
        salted_dg1,
        salted_expiry_date,
        salted_dg2_hash,
        salted_dg2_hash_type,
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    (param_commitment, nullifier_type, nullifier)
}
