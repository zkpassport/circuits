use utils::IDData;
use disclose::get_disclosed_bytes;
use subcircuits::subcircuit_d_verification;

#[recursive]
fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    id_data: IDData,
    disclose_mask: pub [u8; 90],
    service_scope: pub Field,
    service_subscope: pub Field,
    scoped_nullifier: pub Field,
) -> pub [u8; 90] {
    subcircuit_d_verification(
        comm_in,
        salt,
        id_data,
        private_nullifier,
        service_scope,
        service_subscope,
        scoped_nullifier,
    );
    get_disclosed_bytes(id_data, disclose_mask)
}
