use common::{calculate_scoped_nullifier, hash_salt_dg1_dg2_hash_private_nullifier};
use oprf::oprf_output::verified_oprf;
use poseidon::poseidon2::Poseidon2;
pub use babyjubjub::BabyJubJubPoint;
pub use utils::types::OPRFProof;
use utils::{
    constants::{
        NON_SALTED_MOCK_NULLIFIER, NON_SALTED_NULLIFIER, SALTED_MOCK_NULLIFIER, SALTED_NULLIFIER,
    },
    get_issuing_country_from_mrz,
    types::{DG1Data, MRZExpiryDate, SaltedValue},
};

pub mod tests;

// The ZKR (or Zero Knowledge Republic) is a mock country used for testing purposes
global ZKR_COUNTRY_CODE_BYTES: [u8; 3] = [90, 75, 82];

// Domain separator for the OPRF output
global DS_OPRF: Field = 1330664006;
// Domain separator for the DLOG equality proof
global DS_DLOG: Field = 1523098184080632582082867317389990410064981862;

/*
# Sub-circuit D: Disclosure Circuit
*/

pub fn nullify(
    comm_in: Field,
    salted_dg1: SaltedValue<DG1Data>,
    salted_expiry_date: SaltedValue<MRZExpiryDate>,
    salted_dg2_hash: SaltedValue<Field>,
    salted_dg2_hash_type: SaltedValue<u32>,
    salted_private_nullifier: SaltedValue<Field>,
    service_scope: Field,
    service_subscope: Field,
    nullifier_secret: Field,
    oprf_proof: OPRFProof,
) -> (Field, Field, Field) {
    assert(
        comm_in
            == hash_salt_dg1_dg2_hash_private_nullifier(
                salted_dg1,
                salted_expiry_date,
                salted_dg2_hash,
                salted_dg2_hash_type,
                salted_private_nullifier,
            ),
        "Commitment from 3rd subproof doesn't match in disclosure proof",
    );

    let mut oprf_pk_hash: Field = 0;

    if nullifier_secret != 0 {
        // Salted nullifier mode requires a valid OPRF proof
        assert(oprf_proof.beta != 0, "OPRF proof required when nullifier_secret is non-zero");

        let oprf_output = verified_oprf(
            oprf_proof.beta,
            oprf_proof.pk,
            oprf_proof.dlog_e,
            oprf_proof.dlog_s,
            oprf_proof.response_blinded,
            oprf_proof.response,
            salted_private_nullifier.value,
            DS_DLOG,
            DS_OPRF,
        );

        assert(oprf_output == nullifier_secret, "OPRF output must match nullifier_secret");
        oprf_pk_hash = Poseidon2::hash([oprf_proof.pk.x, oprf_proof.pk.y], 2);
    }

    let scoped_nullifier = calculate_scoped_nullifier(
        salted_private_nullifier,
        service_scope,
        service_subscope,
        nullifier_secret,
    );
    // Determine the nullifier type based on the secret
    let mut nullifier_type = if nullifier_secret != 0 {
        // Set the nullifier type to the salted nullifier type
        // as the secret was used to salt the nullifier
        SALTED_NULLIFIER
    } else {
        // Set the nullifier type to the non-salted nullifier type
        // as the secret was not used to salt the nullifier
        NON_SALTED_NULLIFIER
    };
    let issuing_country = get_issuing_country_from_mrz(salted_dg1.value);
    // Doesn't matter if we already calculated the scoped nullifier above
    // cause it's ZK all branches will be evaluated anyway
    if issuing_country == ZKR_COUNTRY_CODE_BYTES {
        // Set the nullifier type to one of the mock nullifier types
        // to indicate the issuing country is not a real one
        // and prevent the use of these proofs in production
        // Note: ZKPassport's registries on mainnet blockchains will not include
        // the ZKR certificates but still this distinction can be useful for testnets/devnets
        if nullifier_secret != 0 {
            // Set the nullifier type to the salted mock nullifier type
            // as the secret was used to salt the nullifier
            nullifier_type = SALTED_MOCK_NULLIFIER;
        } else {
            // Set the nullifier type to the non-salted mock nullifier type
            // as the secret was not used to salt the nullifier
            nullifier_type = NON_SALTED_MOCK_NULLIFIER;
        }
    }
    (scoped_nullifier, nullifier_type, oprf_pk_hash)
}
