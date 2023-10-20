pub mod adss;
pub mod vss;
mod shamir;
mod utils;

#[allow(non_upper_case_globals)]
const λ_bits: usize = 128;

#[allow(non_upper_case_globals)]
const λ: usize = λ_bits / 8;