// Documentation can be found in `../interface.h`
#![allow(clippy::missing_safety_doc)]

#[cfg(test)]
mod tests;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use digest::{Input, VariableOutput};
use rand::rngs::OsRng;
use std::collections::{BTreeSet, HashSet};
use std::mem;
use std::ptr;
use std::slice;

type Hasher = blake2::VarBlake2b;

#[macro_export]
macro_rules! quick_hash {
    (__internal $hasher:expr) => {{
        let mut out = [0u8; 64];
        $hasher.variable_result(|b| out.copy_from_slice(b));
        out
    }};
    (__internal $hasher:expr, $first:expr $(, $item:expr)*) => {{
        ::digest::Input::input(&mut $hasher, $first as &[u8]);
        quick_hash!(__internal $hasher $(, $item)*)
    }};
    ($($item:expr $(,)*)*) => {{
        let mut hasher = crate::Hasher::new(64)
            .expect("Hasher doesn't support a 64 byte output");
        quick_hash!(__internal hasher $(, $item)*)
    }};
}

#[macro_export]
macro_rules! quick_hash_scalar {
    ($($item:expr $(,)*)*) => {{
        let bytes = quick_hash!($($item,)*);
        ::curve25519_dalek::scalar::Scalar::from_bytes_mod_order_wide(&bytes)
    }};
}

fn secret_bytes_to_scalar(secret: &[u8]) -> Scalar {
    assert_eq!(secret.len(), 32);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&quick_hash!(secret)[..32]);
    digest[0] &= 248;
    digest[31] &= 127;
    digest[31] |= 64;
    Scalar::from_bits(digest)
}

pub const INTERNAL_ERROR: u8 = 1;
pub const PARAMS_ERROR: u8 = 2;
pub const PEER_ERROR: u8 = 3;

#[allow(clippy::identity_op)]
pub const FLAG_SCALAR_KEY: u32 = 1 << 0;

macro_rules! catch_panic {
    ($err_out:ident $(,$err_ret:expr)*; $code:block) => {{
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || $code));
        match res {
            Ok(x) => x,
            Err(e) => {
                match e.downcast_ref::<&'static str>() {
                    Some(s) => eprintln!("INTERNAL MUSIG-BANANO ERROR: {}", s),
                    None => eprintln!("UNKNOWN INTERNAL MUSIG-BANANO ERROR!"),
                }
                *$err_out = INTERNAL_ERROR;
                $($err_ret)*
            }
        }
    }};
}

#[cfg(feature = "wasm")]
#[no_mangle]
pub unsafe extern "C" fn musig_malloc(size: usize) -> *mut u8 {
    let mut vec: Vec<u8> = Vec::with_capacity(size + mem::size_of::<usize>());
    let true_size = vec.capacity();
    let ptr = vec.as_mut_ptr();
    *(ptr as *mut usize) = true_size;
    mem::forget(vec);
    ptr.offset(mem::size_of::<usize>() as isize)
}

#[cfg(feature = "wasm")]
#[no_mangle]
pub unsafe extern "C" fn musig_free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }
    let ptr = ptr.offset(-(mem::size_of::<usize>() as isize));
    let size = *(ptr as *mut usize);
    let _: Vec<u8> = Vec::from_raw_parts(ptr, 0, size);
}

#[no_mangle]
pub unsafe extern "C" fn musig_aggregate_public_keys(
    pubkeys: *const *const u8,
    count: usize,
    error_out: *mut u8,
    aggregated_pubkey_out: *mut u8,
) {
    catch_panic!(error_out; {
    // Sort the pubkeys and remove duplicates
    let pubkeys: BTreeSet<[u8; 32]> = slice::from_raw_parts(pubkeys, count)
        .iter()
        .map(|&pointer| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(slice::from_raw_parts(pointer, 32));
            bytes
        })
        .collect();
    let pubkeys: Option<Vec<EdwardsPoint>> = pubkeys
        .into_iter()
        .map(|bytes| CompressedEdwardsY(bytes).decompress())
        .collect();
    let pubkeys = match pubkeys {
        Some(x) => x,
        None => {
            *error_out = PEER_ERROR;
            return;
        }
    };
    let mut l_hasher = crate::Hasher::new(64).expect("Hasher doesn't support a 64 byte output");
    for pkey in &pubkeys {
        l_hasher.input(pkey.compress().as_bytes());
    }
    let mut l_value = [0u8; 64];
    l_hasher.variable_result(|b| l_value.copy_from_slice(b));
    let aggregated_pubkey = pubkeys
        .iter()
        .map(|pkey| {
            let a_value =
                quick_hash_scalar!(b"agg", &l_value, pkey.compress().as_bytes());
            pkey * a_value
        })
        .fold(None, |sum, new| match sum {
            None => Some(new),
            Some(sum) => Some(sum + new),
        });
    let aggregated_pubkey = match aggregated_pubkey {
        Some(x) => x,
        None => {
            *error_out = PEER_ERROR;
            return;
        }
    };
    slice::from_raw_parts_mut(aggregated_pubkey_out, 32)
        .copy_from_slice(aggregated_pubkey.compress().as_bytes());
    })
}

pub struct Stage0 {
    our_r: Scalar,
}

#[no_mangle]
pub unsafe extern "C" fn musig_stage0(error_out: *mut u8, publish_out: *mut u8) -> *mut Stage0 {
    catch_panic!(error_out, ptr::null_mut(); {
    let our_r = Scalar::random(&mut OsRng);
    let our_rb = &our_r * &ED25519_BASEPOINT_TABLE;
    let mut our_t_hasher = Hasher::new(32).expect("Invalid blake2b length");
    our_t_hasher.input(b"com");
    our_t_hasher.input(our_rb.compress().as_bytes());
    our_t_hasher.variable_result(|b| slice::from_raw_parts_mut(publish_out, 32).copy_from_slice(b));
    Box::into_raw(Box::new(Stage0 {
        our_r,
    }))
    })
}

pub struct Stage1 {
    our_new_sec_key: Scalar,
    aggregated_pubkey: EdwardsPoint,
    our_r: Scalar,
    t_values: HashSet<[u8; 32]>,
    message: Vec<u8>,
}

#[no_mangle]
pub unsafe extern "C" fn musig_stage1(
    stage0: *mut Stage0,
    our_sec_key: *const u8,
    all_pub_keys: *const *const u8,
    all_pub_keys_count: usize,
    flags: u32,
    message: *const u8,
    message_len: usize,
    responses: *const *const u8,
    responses_count: usize,
    error_out: *mut u8,
    aggregated_pubkey_out: *mut u8,
    publish_out: *mut u8,
) -> *mut Stage1 {
    catch_panic!(error_out, ptr::null_mut(); {
    let stage0 = Box::from_raw(stage0);
    let our_sec_key = slice::from_raw_parts(our_sec_key, 32);
    let our_sec_key = if flags & FLAG_SCALAR_KEY != 0 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&our_sec_key);
        Scalar::from_bytes_mod_order(bytes)
    } else {
        secret_bytes_to_scalar(our_sec_key)
    };
    // Sort the pubkeys and remove duplicates
    let mut all_pub_keys: BTreeSet<[u8; 32]> =
        slice::from_raw_parts(all_pub_keys, all_pub_keys_count)
            .iter()
            .map(|&pointer| {
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(slice::from_raw_parts(pointer, 32));
                bytes
            })
            .collect();
    all_pub_keys.insert(
        (&our_sec_key * &ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes(),
    );
    let all_pub_keys: Option<Vec<EdwardsPoint>> = all_pub_keys
        .into_iter()
        .map(|bytes| CompressedEdwardsY(bytes).decompress())
        .collect();
    let all_pub_keys = match all_pub_keys {
        Some(x) => x,
        None => {
            *error_out = PEER_ERROR;
            return ptr::null_mut();
        }
    };
    let mut l_hasher = crate::Hasher::new(64).expect("Hasher doesn't support a 64 byte output");
    for pkey in &all_pub_keys {
        l_hasher.input(pkey.compress().as_bytes());
    }
    let mut l_value = [0u8; 64];
    l_hasher.variable_result(|b| l_value.copy_from_slice(b));
    let our_pub_key = &our_sec_key * &ED25519_BASEPOINT_TABLE;
    let mut our_new_sec_key = None;
    let aggregated_pubkey = all_pub_keys
        .iter()
        .map(|pkey| {
            let a_value =
                quick_hash_scalar!(b"agg", &l_value, pkey.compress().as_bytes());
            if pkey == &our_pub_key {
                our_new_sec_key = Some(our_sec_key * a_value);
            }
            pkey * a_value
        })
        .fold(None, |sum, new| match sum {
            None => Some(new),
            Some(sum) => Some(sum + new),
        });
    let (our_new_sec_key, aggregated_pubkey) = match (our_new_sec_key, aggregated_pubkey) {
        (Some(x), Some(y)) => (x, y),
        _ => {
            *error_out = PARAMS_ERROR;
            return ptr::null_mut();
        }
    };
    if !aggregated_pubkey_out.is_null() {
        slice::from_raw_parts_mut(aggregated_pubkey_out, 32)
            .copy_from_slice(aggregated_pubkey.compress().as_bytes());
    }
    let mut t_values: HashSet<[u8; 32]> = slice::from_raw_parts(responses, responses_count)
        .iter()
        .map(|&pointer| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(slice::from_raw_parts(pointer, 32));
            bytes
        })
        .collect();
    let our_rb = &stage0.our_r * &ED25519_BASEPOINT_TABLE;
    slice::from_raw_parts_mut(publish_out, 32).copy_from_slice(our_rb.compress().as_bytes());
    let mut our_t = [0u8; 32];
    let mut our_t_hasher = Hasher::new(32).expect("Invalid blake2b length");
    our_t_hasher.input(b"com");
    our_t_hasher.input(our_rb.compress().as_bytes());
    our_t_hasher.variable_result(|b| our_t.copy_from_slice(b));
    t_values.insert(our_t);
    Box::into_raw(Box::new(Stage1 {
        our_new_sec_key,
        our_r: stage0.our_r,
        aggregated_pubkey,
        t_values,
        message: slice::from_raw_parts(message, message_len).to_vec(),
    }))
    })
}

pub struct Stage2 {
    our_s_part: Scalar,
    total_rb: EdwardsPoint,
    c_value: Scalar,
    aggregated_pubkey: EdwardsPoint,
}

#[no_mangle]
pub unsafe extern "C" fn musig_stage2(
    stage1: *mut Stage1,
    responses: *const *const u8,
    responses_count: usize,
    error_out: *mut u8,
    publish_out: *mut u8,
) -> *mut Stage2 {
    catch_panic!(error_out, ptr::null_mut(); {
    let stage1 = Box::from_raw(stage1);
    let mut total_rb = None;
    let mut rb_values: HashSet<[u8; 32]> = slice::from_raw_parts(responses, responses_count)
        .iter()
        .map(|&pointer| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(slice::from_raw_parts(pointer, 32));
            bytes
        })
        .collect();
    rb_values.insert(
        (&stage1.our_r * &ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes(),
    );
    let mut t_values = stage1.t_values.clone();
    for rb_bytes in rb_values {
        let mut expected_t = [0u8; 32];
        let mut t_hasher = Hasher::new(32).expect("Invalid blake2b length");
        t_hasher.input(b"com");
        t_hasher.input(&rb_bytes);
        t_hasher.variable_result(|b| expected_t.copy_from_slice(b));
        if !t_values.remove(&expected_t) {
            *error_out = PEER_ERROR;
            mem::forget(stage1);
            return ptr::null_mut();
        }
        if let Some(rb) = CompressedEdwardsY(rb_bytes).decompress() {
            total_rb = Some(match total_rb {
                Some(prev) => prev + rb,
                None => rb,
            });
        } else {
            *error_out = PEER_ERROR;
            mem::forget(stage1);
            return ptr::null_mut();
        }
    }
    if !t_values.is_empty() {
        *error_out = PEER_ERROR;
        mem::forget(stage1);
        return ptr::null_mut();
    }
    let total_rb = match total_rb {
        Some(x) => x,
        None => {
            *error_out = PARAMS_ERROR;
            mem::forget(stage1);
            return ptr::null_mut();
        }
    };
    let c_value = quick_hash_scalar!(
        total_rb.compress().as_bytes(),
        stage1.aggregated_pubkey.compress().as_bytes(),
        &stage1.message
    );
    let our_s_part = stage1.our_r + (c_value * stage1.our_new_sec_key);
    slice::from_raw_parts_mut(publish_out, 32).copy_from_slice(our_s_part.as_bytes());
    Box::into_raw(Box::new(Stage2 {
        our_s_part,
        total_rb,
        c_value,
        aggregated_pubkey: stage1.aggregated_pubkey,
    }))
    })
}

#[no_mangle]
pub unsafe extern "C" fn musig_stage3(
    stage2: *mut Stage2,
    responses: *const *const u8,
    responses_count: usize,
    error_out: *mut u8,
    signature_out: *mut u8,
) {
    catch_panic!(error_out; {
    let stage2 = Box::from_raw(stage2);
    let mut s_parts: HashSet<[u8; 32]> = slice::from_raw_parts(responses, responses_count)
        .iter()
        .map(|&ptr| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(slice::from_raw_parts(ptr, 32));
            bytes
        })
        .collect();
    s_parts.insert(stage2.our_s_part.to_bytes());
    let total_s = s_parts.into_iter().map(Scalar::from_bytes_mod_order).sum();
    let expected_sb = stage2.total_rb + (stage2.c_value * stage2.aggregated_pubkey);
    if &total_s * &ED25519_BASEPOINT_TABLE != expected_sb {
        *error_out = PEER_ERROR;
        mem::forget(stage2);
        return;
    }
    let signature_out = slice::from_raw_parts_mut(signature_out, 64);
    signature_out[..32].copy_from_slice(stage2.total_rb.compress().as_bytes());
    signature_out[32..].copy_from_slice(total_s.as_bytes());
    })
}

#[no_mangle]
pub unsafe extern "C" fn musig_free_stage0(stage0: *mut Stage0) {
    Box::from_raw(stage0);
}

#[no_mangle]
pub unsafe extern "C" fn musig_free_stage1(stage1: *mut Stage1) {
    Box::from_raw(stage1);
}

#[no_mangle]
pub unsafe extern "C" fn musig_free_stage2(stage2: *mut Stage2) {
    Box::from_raw(stage2);
}

#[no_mangle]
pub unsafe extern "C" fn musig_observe(
    aggregated_pubkey: *const u8,
    message: *const u8,
    message_len: usize,
    stage1_messages: *const *const u8,
    stage1_messages_count: usize,
    stage2_messages: *const *const u8,
    stage2_messages_count: usize,
    error_out: *mut u8,
    signature_out: *mut u8,
) {
    catch_panic!(error_out; {
    let mut aggregated_pubkey_bytes = [0u8; 32];
    aggregated_pubkey_bytes.copy_from_slice(slice::from_raw_parts(aggregated_pubkey, 32));
    let aggregated_pubkey = match CompressedEdwardsY(aggregated_pubkey_bytes).decompress() {
        Some(x) => x,
        None => {
            *error_out = PEER_ERROR;
            return;
        }
    };
    let message = slice::from_raw_parts(message, message_len);
    let stage1_messages = slice::from_raw_parts(stage1_messages, stage1_messages_count);
    let mut seen_rb_values = HashSet::new();
    let mut total_rb = None;
    for &rb_pointer in stage1_messages {
        let mut rb_bytes = [0u8; 32];
        rb_bytes.copy_from_slice(slice::from_raw_parts(rb_pointer, 32));
        if !seen_rb_values.insert(rb_bytes.clone()) {
            continue;
        }
        let rb = match CompressedEdwardsY(rb_bytes).decompress() {
            Some(x) => x,
            None => {
                *error_out = PEER_ERROR;
                return;
            }
        };
        total_rb = Some(match total_rb {
            Some(prev) => prev + rb,
            None => rb,
        });
    }
    let total_rb = match total_rb {
        Some(x) => x,
        None => {
            *error_out = PARAMS_ERROR;
            return;
        }
    };
    let stage2_messages = slice::from_raw_parts(stage2_messages, stage2_messages_count);
    let total_s: Scalar = stage2_messages
        .iter()
        .map(|&p| {
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(slice::from_raw_parts(p, 32));
            bytes
        })
        .collect::<HashSet<_>>() // remove duplicates
        .into_iter()
        .map(Scalar::from_bytes_mod_order)
        .sum();
    let c_value = quick_hash_scalar!(
        total_rb.compress().as_bytes(),
        &aggregated_pubkey_bytes,
        message,
    );
    let expected_sb = total_rb + (c_value * aggregated_pubkey);
    if &total_s * &ED25519_BASEPOINT_TABLE != expected_sb {
        *error_out = PEER_ERROR;
        return;
    }
    let signature_out = slice::from_raw_parts_mut(signature_out, 64);
    signature_out[..32].copy_from_slice(total_rb.compress().as_bytes());
    signature_out[32..].copy_from_slice(total_s.as_bytes());
    })
}

#[cfg(test)]
#[no_mangle]
pub(crate) unsafe extern "C" fn test_catch_panic(error_out: *mut u8) -> u16 {
    catch_panic!(error_out, 42; {
    panic!("test_catch_panic");
    })
}
