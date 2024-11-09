use disclose::get_disclosed_bytes;
//use commitment::nullify;

//#[recursive]
fn main(
    /*comm_in: pub Field,
    salt: Field,
    private_nullifier: Field,*/
    dg1: [u8; 95],
    disclose_mask: pub [u8; 90],
    /*service_scope: pub Field,
    service_subscope: pub Field,*/
) /*-> pub ([u8; 90], Field)*/ -> pub [u8; 90] {
    let disclosed_bytes = get_disclosed_bytes(dg1, disclose_mask);
    /*let nullifier = nullify(
        comm_in,
        salt,
        dg1,
        private_nullifier,
        service_scope,
        service_subscope,
    );
    (disclosed_bytes, nullifier)*/
    disclosed_bytes
}
