use utils::{CSCData, DSCData};
use sig_check_rsa::verify_dsc_signature;
use subcircuits::{CertificateRegistry, subcircuit_a_verification};

#[recursive]
fn main(
    // Certificate registry merkle root
    certificate_registry_root: pub Field,
    certificate_registry: CertificateRegistry,
    salt: Field,
    country: str<3>,
    dsc_data: DSCData,
    csc_data: CSCData,
    comm_out: pub Field,
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
    assert(verify_dsc_signature::<2048, 0>(dsc_data, csc_data));
}
