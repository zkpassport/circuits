use dep::utils::IDData;
use dep::disclose::get_disclosed_data_bytes;

fn main(id_data: IDData, disclose_mask: [u8; 90]) -> pub [u8; 90] {
    get_disclosed_data_bytes(id_data, disclose_mask)
}
