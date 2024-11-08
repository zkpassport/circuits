use utils::{CSCData, DSCData};
use subcircuits::{CertificateRegistry, subcircuit_a_verification};
use sig_check_ecdsa::verify_dsc_signature;

#[recursive]
fn main(
    certificate_registry_root: Field,
    certificate_registry: CertificateRegistry,
    salt: Field,
    country: str<3>,
    dsc_data: DSCData,
    csc_data: CSCData,
    comm_out: Field,
) {
    subcircuit_a_verification(
        certificate_registry_root,
        certificate_registry,
        country,
        dsc_data,
        salt,
        csc_data,
        comm_out,
    );
    assert(verify_dsc_signature(dsc_data, csc_data));
}
