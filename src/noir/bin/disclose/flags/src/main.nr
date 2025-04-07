use commitment::nullify;
use disclose::get_disclosed_data;
use utils::{DisclosedData, DiscloseFlags};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: [u8; 95],
    disclose_flags: DiscloseFlags,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (DisclosedData, Field) {
    let disclosed_data = get_disclosed_data(dg1, disclose_flags);
    let scoped_nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    (disclosed_data, scoped_nullifier)
}
