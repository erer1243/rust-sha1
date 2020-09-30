use super::*;
use std::convert::TryInto;
use std::iter::repeat;

#[test]
fn reset_test() {
    // Test that reset Sha1 structs act the same as new Sha1 structs
    let mut s = Sha1::new();
    s.update(b"hello, world :^)");
    s.finish();
    s.reset();
    assert!(s.h0 == 0x67452301);
    assert!(s.h1 == 0xEFCDAB89);
    assert!(s.h2 == 0x98BADCFE);
    assert!(s.h3 == 0x10325476);
    assert!(s.h4 == 0xC3D2E1F0);
    assert!(s.finish() == known_good_hash(b""));
}

#[test]
fn update_test() {
    // Test that update does not leave a chunk full without processing it
    let mut s = Sha1::new();
    let data: Vec<u8> = repeat(b'a').take(64).collect();
    s.update(&data);
    assert!(s.used == 0);
    assert!(s.chunks_processed == 1);
}

#[test]
fn general_test() {
    // Test 0..300 x 'a' hash
    let mut data: Vec<u8> = Vec::with_capacity(1000);

    for n in 0..300 {
        assert!(
            Sha1::digest(&data) == known_good_hash(&data),
            format!("{} x a", n)
        );
        data.push(b'a');
    }
}

fn known_good_hash(data: &[u8]) -> Hash {
    let bytes: [u8; 20] = mitsuhiko::Sha1::from(data).digest().bytes();

    [
        u32::from_be_bytes(bytes[0..4].try_into().unwrap()),
        u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
        u32::from_be_bytes(bytes[12..16].try_into().unwrap()),
        u32::from_be_bytes(bytes[16..20].try_into().unwrap()),
    ]
}
