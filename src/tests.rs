use crate::*;
use digest::{generic_array, Input, VariableOutput};
use ed25519_dalek::{PublicKey, SecretKey, Signature};
use rand::prelude::*;

/// A fixed size hasher for ed25519_dalek
#[derive(Clone)]
struct Blake2b512(blake2::VarBlake2b);

impl Default for Blake2b512 {
    fn default() -> Blake2b512 {
        Blake2b512(
            blake2::VarBlake2b::new(512 / 8).expect("Blake2b doesn't support 512 bit output"),
        )
    }
}

impl Input for Blake2b512 {
    fn input<B: std::convert::AsRef<[u8]>>(&mut self, data: B) {
        self.0.input(data)
    }
}

impl digest::FixedOutput for Blake2b512 {
    type OutputSize = generic_array::typenum::consts::U64;

    fn fixed_result(self) -> generic_array::GenericArray<u8, Self::OutputSize> {
        let mut out = generic_array::GenericArray::default();
        self.0
            .variable_result(|b| out.as_mut_slice().copy_from_slice(b));
        out
    }
}

impl digest::Reset for Blake2b512 {
    fn reset(&mut self) {
        self.0.reset();
    }
}

type Hasher = Blake2b512;

#[test]
fn basic_test() {
    const PARTICIPANTS: usize = 5;
    const MESSAGE: &[u8] = b"Hello world!";
    let mut rng = OsRng;
    let mut skeys = [[0u8; 32]; PARTICIPANTS];
    for skey in &mut skeys {
        rng.fill(skey);
    }
    let pkeys: Vec<_> = skeys
        .iter()
        .map(|skey| {
            PublicKey::from_secret::<Hasher>(&SecretKey::from_bytes(skey).unwrap()).to_bytes()
        })
        .collect();
    let mut pkey_ptrs: Vec<_> = pkeys.iter().map(|x| x.as_ptr()).collect();
    let mut err = 0u8;
    let mut agg_pkey = [0u8; 32];
    unsafe {
        musig_aggregate_public_keys(
            pkey_ptrs.as_ptr(),
            pkey_ptrs.len(),
            &mut err as *mut _,
            agg_pkey.as_mut_ptr(),
        );
    }
    assert_eq!(err, 0);
    assert!(agg_pkey.iter().any(|&x| x != 0));
    for pkey in &pkeys {
        assert!(&agg_pkey != pkey);
    }
    let mut agg_pkey2 = [0u8; 32];
    let mut publish0s = [[0u8; 32]; PARTICIPANTS];
    let mut stage0s = Vec::new();
    for (i, skey) in skeys.iter().enumerate() {
        pkey_ptrs.shuffle(&mut rng);
        stage0s.push(unsafe {
            musig_stage0(
                skey.as_ptr(),
                pkey_ptrs.as_ptr(),
                pkey_ptrs.len(),
                0,
                &mut err as *mut _,
                agg_pkey2.as_mut_ptr(),
                publish0s[i].as_mut_ptr(),
            )
        });
        assert_eq!(err, 0);
        assert_eq!(agg_pkey2, agg_pkey);
    }
    let mut publish0_ptrs: Vec<_> = publish0s.iter().map(|x| x.as_ptr()).collect();
    let mut publish1s = [[0u8; 32]; PARTICIPANTS];
    let mut stage1s = Vec::new();
    for (i, stage0) in stage0s.into_iter().enumerate() {
        publish0_ptrs.shuffle(&mut rng);
        let rand_publish = *publish0_ptrs.choose(&mut rng).unwrap();
        publish0_ptrs.push(rand_publish);
        stage1s.push(unsafe {
            musig_stage1(
                stage0,
                publish0_ptrs.as_ptr(),
                publish0_ptrs.len(),
                &mut err as *mut _,
                publish1s[i].as_mut_ptr(),
            )
        });
        assert_eq!(err, 0);
    }
    let mut publish1_ptrs: Vec<_> = publish1s.iter().map(|x| x.as_ptr()).collect();
    let mut publish2s = [[0u8; 32]; PARTICIPANTS];
    let mut stage2s = Vec::new();
    for (i, stage1) in stage1s.into_iter().enumerate() {
        publish1_ptrs.shuffle(&mut rng);
        let rand_publish = *publish1_ptrs.choose(&mut rng).unwrap();
        publish1_ptrs.push(rand_publish);
        stage2s.push(unsafe {
            musig_stage2(
                stage1,
                MESSAGE.as_ptr(),
                MESSAGE.len(),
                publish1_ptrs.as_ptr(),
                publish1_ptrs.len(),
                &mut err as *mut _,
                publish2s[i].as_mut_ptr(),
            )
        });
        assert_eq!(err, 0);
    }
    let mut publish2_ptrs: Vec<_> = publish2s.iter().map(|x| x.as_ptr()).collect();
    let agg_pkey = PublicKey::from_bytes(&agg_pkey).unwrap();
    let mut signature = [0u8; 64];
    for stage2 in stage2s {
        publish2_ptrs.shuffle(&mut rng);
        let rand_publish = *publish2_ptrs.choose(&mut rng).unwrap();
        publish2_ptrs.push(rand_publish);
        unsafe {
            musig_stage3(
                stage2,
                publish2_ptrs.as_ptr(),
                publish2_ptrs.len(),
                &mut err as *mut _,
                signature.as_mut_ptr(),
            );
        }
        assert_eq!(err, 0);
        assert!(agg_pkey
            .verify::<Hasher>(
                MESSAGE,
                &Signature::from_bytes(&signature as &[u8]).unwrap()
            )
            .is_ok());
        signature = [0u8; 64];
    }
    let agg_pkey_bytes = agg_pkey.as_bytes();
    unsafe {
        musig_observe(
            agg_pkey_bytes.as_ptr(),
            MESSAGE.as_ptr(),
            MESSAGE.len(),
            publish1_ptrs.as_ptr(),
            publish1_ptrs.len(),
            publish2_ptrs.as_ptr(),
            publish2_ptrs.len(),
            &mut err as *mut u8,
            signature.as_mut_ptr(),
        );
    }
    assert_eq!(err, 0);
    assert!(agg_pkey
        .verify::<Hasher>(
            MESSAGE,
            &Signature::from_bytes(&signature as &[u8]).unwrap()
        )
        .is_ok());
}

#[test]
fn incorrect_commit_reveal() {
    const PARTICIPANTS: usize = 5;
    const MESSAGE: &[u8] = b"Hello world!";
    let mut rng = OsRng;
    let mut skeys = [[0u8; 32]; PARTICIPANTS];
    for skey in &mut skeys {
        rng.fill(skey);
    }
    let pkeys: Vec<_> = skeys
        .iter()
        .map(|skey| {
            PublicKey::from_secret::<Hasher>(&SecretKey::from_bytes(skey).unwrap()).to_bytes()
        })
        .collect();
    let pkey_ptrs: Vec<_> = pkeys.iter().map(|x| x.as_ptr()).collect();
    let mut buf = [0u8; 32];
    let mut err = 0u8;
    let stage0 = unsafe {
        musig_stage0(
            skeys[0].as_ptr(),
            pkey_ptrs.as_ptr(),
            pkey_ptrs.len(),
            0,
            &mut err as *mut _,
            ptr::null_mut(),
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(err, 0);
    let mut commitments = [[0u8; 32]];
    rng.fill(&mut commitments[0]);
    let commitment_ptrs: Vec<_> = commitments.iter().map(|x| x.as_ptr()).collect();
    let stage1 = unsafe {
        musig_stage1(
            stage0,
            commitment_ptrs.as_ptr(),
            commitment_ptrs.len(),
            &mut err as *mut _,
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(err, 0);
    // Random but a valid edwards point
    let reveal = (&Scalar::from_bytes_mod_order(commitments[0]) * &ED25519_BASEPOINT_TABLE)
        .compress()
        .to_bytes();
    let reveal_ptrs: Vec<_> = vec![reveal.as_ptr()];
    let stage2 = unsafe {
        musig_stage2(
            stage1,
            MESSAGE.as_ptr(),
            MESSAGE.len(),
            reveal_ptrs.as_ptr(),
            reveal_ptrs.len(),
            &mut err as *mut _,
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(err, PEER_ERROR);
    assert!(stage2.is_null());
    err = 0;
    let stage2_again = unsafe {
        musig_stage2(
            stage1,
            MESSAGE.as_ptr(),
            MESSAGE.len(),
            reveal_ptrs.as_ptr(),
            reveal_ptrs.len(),
            &mut err as *mut _,
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(err, PEER_ERROR);
    assert!(stage2_again.is_null());
}

#[test]
fn commit_missing_participant() {
    const PARTICIPANTS: usize = 5;
    const MESSAGE: &[u8] = b"Hello world!";
    let mut rng = OsRng;
    let mut skeys = [[0u8; 32]; PARTICIPANTS];
    for skey in &mut skeys {
        rng.fill(skey);
    }
    let pkeys: Vec<_> = skeys
        .iter()
        .map(|skey| {
            PublicKey::from_secret::<Hasher>(&SecretKey::from_bytes(skey).unwrap()).to_bytes()
        })
        .collect();
    let pkey_ptrs: Vec<_> = pkeys.iter().map(|x| x.as_ptr()).collect();
    let mut buf = [0u8; 32];
    let mut err = 0u8;
    let stage0 = unsafe {
        musig_stage0(
            skeys[0].as_ptr(),
            pkey_ptrs.as_ptr(),
            pkey_ptrs.len(),
            0,
            &mut err as *mut _,
            ptr::null_mut(),
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(err, 0);
    let mut commitments = [[0u8; 32]];
    rng.fill(&mut commitments[0]);
    let commitment_ptrs: Vec<_> = commitments.iter().map(|x| x.as_ptr()).collect();
    let stage1 = unsafe {
        musig_stage1(
            stage0,
            commitment_ptrs.as_ptr(),
            commitment_ptrs.len(),
            &mut err as *mut _,
            buf.as_mut_ptr(),
        )
    };
    assert_eq!(err, 0);
    let buf_ptr = vec![buf.as_ptr()];
    let mut buf2 = [0u8; 32];
    let stage2 = unsafe {
        musig_stage2(
            stage1,
            MESSAGE.as_ptr(),
            MESSAGE.len(),
            buf_ptr.as_ptr(),
            buf_ptr.len(),
            &mut err as *mut _,
            buf2.as_mut_ptr(),
        )
    };
    assert_eq!(err, PEER_ERROR);
    assert!(stage2.is_null());
}

#[test]
fn test_catch_panic() {
    let mut err = 0;
    let ret = unsafe { crate::test_catch_panic(&mut err as _) };
    assert_eq!(err, INTERNAL_ERROR);
    assert_eq!(ret, 42);
}

#[test]
fn test_scalar_key() {
    let mut rng = OsRng;
    let scalar = Scalar::random(&mut rng);
    let scalar_bytes = scalar.to_bytes();
    let pkey = &scalar * &ED25519_BASEPOINT_TABLE;
    let pkey_bytes = pkey.compress().to_bytes();
    let pkey_ptrs = [pkey_bytes.as_ptr()];
    let mut agg_pkey = [0u8; 32];
    let mut err = 0u8;
    unsafe {
        musig_aggregate_public_keys(
            pkey_ptrs.as_ptr(),
            pkey_ptrs.len(),
            &mut err as *mut _,
            agg_pkey.as_mut_ptr(),
        );
    }
    assert_eq!(err, 0);
    assert!(agg_pkey.iter().any(|&b| b != 0));
    let mut agg_pkey2 = [0u8; 32];
    let mut out = [0u8; 32];
    let stage0 = unsafe {
        musig_stage0(
            scalar_bytes.as_ptr(),
            ptr::null(),
            0,
            FLAG_SCALAR_KEY,
            &mut err as *mut _,
            agg_pkey2.as_mut_ptr(),
            out.as_mut_ptr(),
        )
    };
    assert_eq!(err, 0);
    assert!(!stage0.is_null());
    assert_eq!(agg_pkey2, agg_pkey);
    assert!(out.iter().any(|&b| b != 0));
    unsafe {
        musig_free_stage0(stage0);
    }
}
