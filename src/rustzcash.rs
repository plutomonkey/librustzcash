#[macro_use]
extern crate log;

extern crate byteorder;
extern crate env_logger;
extern crate generic_array;
extern crate libsodium_sys;
extern crate rustc_serialize;
extern crate typenum;

extern crate libc;
use libc::uint32_t;
use libc::uint64_t;
use libc::c_uchar;
use libc::size_t;

use std::slice;

pub mod equihash;

/// XOR two uint64_t values and return the result, used
/// as a temporary mechanism for introducing Rust into
/// Zcash.
#[no_mangle]
pub extern "system" fn librustzcash_xor(a: uint64_t, b: uint64_t) -> uint64_t {
    a ^ b
}

#[no_mangle]
pub extern "system" fn librustzcash_eh_isvalid(n: uint32_t,
                                               k: uint32_t,
                                               input: *const c_uchar,
                                               input_len: size_t,
                                               nonce: *const c_uchar,
                                               nonce_len: size_t,
                                               indices: *mut uint32_t,
                                               indices_len: size_t)
                                               -> bool {
    if (nonce_len != (n as usize) / 8) || (indices_len != 1 << k) {
        return false;
    }
    let rs_input = unsafe { slice::from_raw_parts(input, input_len) };
    let rs_nonce = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let rs_indices = unsafe { slice::from_raw_parts(indices, indices_len) };
    equihash::is_valid_solution(n, k, rs_input, rs_nonce, rs_indices)
}

#[test]
fn test_xor() {
    assert_eq!(librustzcash_xor(0x0f0f0f0f0f0f0f0f, 0x1111111111111111),
               0x1e1e1e1e1e1e1e1e);
}
