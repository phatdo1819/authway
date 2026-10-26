// X25519 of RFC 7748, only to show the public key of a configuration: the service has the private key, the window
// of details shows the public one, which the administrator of the server knows. The ladder is the constant-time
// one of the RFC, on numbers of five limbs of 51 bits.

use crate::conf::Key;

type Field = [u64; 5];

const MASK: u64 = (1 << 51) - 1;
// (A - 2) / 4 of the curve
const A24: u64 = 121_665;

fn load(bytes: &Key) -> Field {
    let read = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
    // the top bit of the u-coordinate is ignored
    [read(0) & MASK, (read(6) >> 3) & MASK, (read(12) >> 6) & MASK, (read(19) >> 1) & MASK, (read(24) >> 12) & MASK]
}

fn add(a: &Field, b: &Field) -> Field {
    [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]]
}

// a + 2p - b: never below zero for the reduced numbers of the ladder
fn sub(a: &Field, b: &Field) -> Field {
    const TWO_P0: u64 = 0xf_ffff_ffff_ffda;
    const TWO_P: u64 = 0xf_ffff_ffff_fffe;
    [a[0] + TWO_P0 - b[0], a[1] + TWO_P - b[1], a[2] + TWO_P - b[2], a[3] + TWO_P - b[3], a[4] + TWO_P - b[4]]
}

fn carry(r: [u128; 5]) -> Field {
    let mut out = [0u64; 5];
    let mut next = r[0];
    for i in 0..4 {
        out[i] = next as u64 & MASK;
        next = r[i + 1] + (next >> 51);
    }
    out[4] = next as u64 & MASK;
    // 2^255 = 19
    let low = out[0] as u128 + (next >> 51) * 19;
    out[0] = low as u64 & MASK;
    out[1] += (low >> 51) as u64;
    out
}

fn mul(a: &Field, b: &Field) -> Field {
    let m = |x: u64, y: u64| x as u128 * y as u128;
    let (b1, b2, b3, b4) = (b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19);
    carry([
        m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1),
        m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2),
        m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3),
        m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4),
        m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
    ])
}

fn square(a: &Field) -> Field {
    mul(a, a)
}

fn mul_small(a: &Field, small: u64) -> Field {
    carry([
        a[0] as u128 * small as u128,
        a[1] as u128 * small as u128,
        a[2] as u128 * small as u128,
        a[3] as u128 * small as u128,
        a[4] as u128 * small as u128,
    ])
}

// a^(p - 2) = 1 / a, with p - 2 = 2^255 - 21: every bit set but 2 and 4
fn invert(a: &Field) -> Field {
    let mut result: Field = [1, 0, 0, 0, 0];
    for bit in (0..255).rev() {
        result = square(&result);
        if bit >= 5 || (0b01011 >> bit) & 1 == 1 {
            result = mul(&result, a);
        }
    }
    result
}

fn store(a: &Field) -> Key {
    let mut t = *a;
    for _ in 0..2 {
        for i in 0..4 {
            t[i + 1] += t[i] >> 51;
            t[i] &= MASK;
        }
        t[0] += 19 * (t[4] >> 51);
        t[4] &= MASK;
    }
    // below 2^255 now: minus p once if it's p or more
    let mut q = (t[0] + 19) >> 51;
    for limb in &t[1..] {
        q = (limb + q) >> 51;
    }
    t[0] += 19 * q;
    for i in 0..4 {
        t[i + 1] += t[i] >> 51;
        t[i] &= MASK;
    }
    t[4] &= MASK;
    let mut out = [0u8; 32];
    let (mut acc, mut bits, mut at) = (0u128, 0, 0);
    for limb in t {
        acc |= (limb as u128) << bits;
        bits += 51;
        while bits >= 8 {
            out[at] = acc as u8;
            acc >>= 8;
            bits -= 8;
            at += 1;
        }
    }
    out[at] = acc as u8;
    out
}

fn swap(condition: u64, a: &mut Field, b: &mut Field) {
    let mask = 0u64.wrapping_sub(condition);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

pub fn x25519(scalar: &Key, u: &Key) -> Key {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = load(u);
    let (mut x2, mut z2, mut x3, mut z3): (Field, Field, Field, Field) = ([1, 0, 0, 0, 0], [0; 5], x1, [1, 0, 0, 0, 0]);
    let mut swapped = 0u64;
    for t in (0..255).rev() {
        let bit = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swapped ^= bit;
        swap(swapped, &mut x2, &mut x3);
        swap(swapped, &mut z2, &mut z3);
        swapped = bit;
        let a = add(&x2, &z2);
        let aa = square(&a);
        let b = sub(&x2, &z2);
        let bb = square(&b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        x3 = square(&add(&da, &cb));
        z3 = mul(&x1, &square(&sub(&da, &cb)));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &add(&aa, &mul_small(&e, A24)));
    }
    swap(swapped, &mut x2, &mut x3);
    swap(swapped, &mut z2, &mut z3);
    store(&mul(&x2, &invert(&z2)))
}

pub fn public_key(private_key: &Key) -> Key {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(private_key, &base)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(hex: &str) -> Key {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        key
    }

    // RFC 7748, 5.2 and 6.1
    #[test]
    fn the_vectors_of_the_rfc() {
        assert_eq!(
            x25519(
                &key("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                &key("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
            ),
            key("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
        let alice = key("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let bob = key("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assert_eq!(public_key(&alice), key("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"));
        assert_eq!(public_key(&bob), key("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"));
        let shared = key("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(x25519(&alice, &public_key(&bob)), shared);
        assert_eq!(x25519(&bob, &public_key(&alice)), shared);
    }

    // after 1000 rounds of k, u = X25519(k, u), k
    #[test]
    fn iterated() {
        let mut k = key("0900000000000000000000000000000000000000000000000000000000000000");
        let mut u = k;
        for _ in 0..1000 {
            let next = x25519(&k, &u);
            u = k;
            k = next;
        }
        assert_eq!(k, key("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"));
    }
}
