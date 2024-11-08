use utils::{CSCData, DSCData};
use sig_check_rsa::verify_dsc_signature_2048;
use subcircuits::{CertificateRegistry, subcircuit_a_verification};

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
    verify_dsc_signature_2048::<1>(dsc_data, csc_data);
}
