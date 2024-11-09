use utils::{DiscloseFlags, DisclosedData};
use disclose::get_disclosed_data;

fn main(dg1: [u8; 95], disclose_flags: DiscloseFlags) -> pub DisclosedData {
    get_disclosed_data(dg1, disclose_flags)
}
