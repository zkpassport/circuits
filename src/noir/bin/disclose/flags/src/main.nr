use commitment::nullify;
use disclose::get_disclosed_data;
use utils::dg1::DG1;
use utils::{DisclosedData, DiscloseFlags, types::DG1Data};

fn main(
    comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,
    dg1: DG1Data,
    disclose_flags: DiscloseFlags,
    service_scope: pub Field,
    service_subscope: pub Field,
) -> pub (DisclosedData, Field) {
    let dg1_data = DG1::new(dg1);
    let disclosed_data = get_disclosed_data(dg1_data, disclose_flags);
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
