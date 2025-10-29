use commitment::nullify;
use data_check_expiry::check_expiry;
use exclusion_check_country::{calculate_param_commitment_sha2, check_issuing_country_exclusion};
use utils::{constants::PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION, types::{DG1Data, SaltedValue}};
use utils::types::MRZExpiryDate;

fn main(
    comm_in: pub Field,
    current_date: pub u64,
    salted_private_nullifier: SaltedValue<Field>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg1: SaltedValue<DG1Data>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    // @committed
    // There are roughly 200 countries in the world
    // so we can safely pad it to 200
    // The list must be sorted in ascending order
    // For efficiency, the list is not sorted in the circuit
    // but it is checked to be sorted.
    // So it is up to the prover to properly sort the list before passing it to the circuit
    // or the proof will fail to generate
    country_list: [u32; 200],
    nullifier_secret: Field,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (Field, Field, Field) {
    // Check the ID is not expired
    check_expiry(salted_dg1.value, current_date);

    // Check that the issuing country of the passport is not in the list of countries
    check_issuing_country_exclusion(salted_dg1.value, country_list);
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
    // Use SHA2-256 to calculate the parameter commitment so the parameter commitment can be
    // reconstructed by verifiers on EVM chains
    let param_commitment =
        calculate_param_commitment_sha2(PROOF_TYPE_ISSUING_COUNTRY_EXCLUSION, country_list);
    (param_commitment, nullifier_type, nullifier)
}
