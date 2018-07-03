extern crate ed25519_dalek;

use self::ed25519_dalek::{PublicKey, SecretKey, Signature};
use rand::{OsRng, Rng};
use *;

#[test]
fn basic_test() {
    const PARTICIPANTS: usize = 5;
    const MESSAGE: &[u8] = b"Hello world!";
    let mut rng = OsRng::new().unwrap();
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
        rng.shuffle(&mut pkey_ptrs);
        stage0s.push(unsafe {
            musig_stage0(
                skey.as_ptr(),
                pkey_ptrs.as_ptr(),
                pkey_ptrs.len(),
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
        rng.shuffle(&mut publish0_ptrs);
        let rand_publish = *rng.choose(&publish0_ptrs).unwrap();
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
        rng.shuffle(&mut publish1_ptrs);
        let rand_publish = *rng.choose(&publish1_ptrs).unwrap();
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
        rng.shuffle(&mut publish2_ptrs);
        let rand_publish = *rng.choose(&publish2_ptrs).unwrap();
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
        assert!(agg_pkey.verify::<Hasher>(
            MESSAGE,
            &Signature::from_bytes(&signature as &[u8]).unwrap()
        ));
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
    assert!(agg_pkey.verify::<Hasher>(
        MESSAGE,
        &Signature::from_bytes(&signature as &[u8]).unwrap()
    ));
}
