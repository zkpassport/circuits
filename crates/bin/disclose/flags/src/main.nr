use utils::{IDData, DiscloseFlags, DisclosedData};
use disclose::get_disclosed_data;

fn main(id_data: IDData, disclose_flags: DiscloseFlags) -> pub DisclosedData {
    get_disclosed_data(id_data, disclose_flags)
}
