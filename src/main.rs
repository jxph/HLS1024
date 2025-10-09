#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]

/* =========================================================
   HLS-1024 : Post-Quantum Hash Function
   ---------------------------------------------------------
   Version : v0.2 (Rust Port Base)
   Author  : JXPH
   Language: Rust (num-bigint-dig + SHAKE256)
   Purpose : Core hash primitive for HMS-1024 and PQ systems
   Build   : cargo run --release -- --message "test"
   ---------------------------------------------------------
   Notes:
   - Optimized clean Rust translation of the HLS-1024 v0.1 algorithm.
   - Uses arbitrary-precision arithmetic (BigUint).
   - Deterministic domain separation and SHAKE-based extraction.
   - Designed for PQ signature, proof-of-work, and cryptographic systems.
   ========================================================= */

use std::io::{self, Read};
use std::fs;
use std::sync::OnceLock;

use num_bigint_dig::BigUint;
use num_traits::{One, Zero};

use sha3::{Shake128, Shake256};
use sha3::digest::{Update, ExtendableOutput, XofReader};

use hex;

// =========================================================
//   GLOBAL PARAMETERS
// =========================================================

static PRIME_MODULUS: OnceLock<BigUint> = OnceLock::new();
static WORD_BITS: OnceLock<usize> = OnceLock::new();
static BYTES_PER_ELEM: OnceLock<usize> = OnceLock::new();

pub const StateSize: usize = 512;
pub const RoundCount: usize = 16;
pub const OutputBitLength: usize = 1024;
pub const BlockBytes: usize = 64;
pub const SeedString: &[u8] = b"HLS-1024-v0.2";

// =========================================================
//   PARAMETER INITIALIZATION
// =========================================================

pub fn InitializeParameters() {
    if PRIME_MODULUS.get().is_none() {
        let hex_str = concat!(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
            "E485B576625E7EC6F44C42E9A63A36210000000000090563"
        );
        let prime = BigUint::parse_bytes(hex_str.as_bytes(), 16).unwrap();
        let bits = prime.bits() as usize;
        let bytes = (bits + 7) / 8;

        PRIME_MODULUS.set(prime).ok();
        WORD_BITS.set(bits).ok();
        BYTES_PER_ELEM.set(bytes).ok();
    }
}

pub fn WordBitsValue() -> usize {
    *WORD_BITS.get_or_init(|| {
        InitializeParameters();
        *WORD_BITS.get().unwrap()
    })
}

pub fn BytesPerElemValue() -> usize {
    *BYTES_PER_ELEM.get_or_init(|| {
        InitializeParameters();
        *BYTES_PER_ELEM.get().unwrap()
    })
}

// =========================================================
//   INTERNAL UTILITIES
// =========================================================

pub fn ShakeInts(seed: &[u8], count: usize, bytes_per_int: Option<usize>) -> Vec<BigUint> {
    InitializeParameters();
    let bytes_per_int = bytes_per_int.unwrap_or_else(BytesPerElemValue);

    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();

    let mut raw = vec![0u8; count * bytes_per_int];
    XofReader::read(&mut reader, &mut raw);

    (0..count)
        .map(|i| {
            let start = i * bytes_per_int;
            let end = start + bytes_per_int;
            BigUint::from_bytes_be(&raw[start..end])
        })
        .collect()
}

pub fn DeriveConst(label: &[u8], n: usize) -> Vec<BigUint> {
    InitializeParameters();

    let mut seed = Vec::new();
    seed.extend_from_slice(SeedString);
    seed.extend_from_slice(b"::const::");
    seed.extend_from_slice(label);

    let prime = PRIME_MODULUS.get().unwrap();

    ShakeInts(&seed, n, None)
        .into_iter()
        .map(|x| x % prime)
        .collect()
}

pub fn InitializeState() -> Vec<BigUint> {
    DeriveConst(b"init", StateSize)
}

// =========================================================
//   CORE TRANSFORMS
// =========================================================

pub fn Rol(x: &BigUint, r: usize, bits: usize) -> BigUint {
    let r = r % bits;
    let mask = (BigUint::one() << bits) - BigUint::one();
    ((x << r) | (x >> (bits - r))) & mask
}

pub fn AbsorbMessageBlock(state: &Vec<BigUint>, block: &[u8]) -> Vec<BigUint> {
    let mut s = state.clone();
    let wb = WordBitsValue();
    let word_bytes = 8;

    let mut padded = block.to_vec();
    if padded.len() % word_bytes != 0 {
        let pad_len = word_bytes - (padded.len() % word_bytes);
        padded.extend(vec![0u8; pad_len]);
    }

    let words: Vec<BigUint> = padded
        .chunks(word_bytes)
        .map(|chunk| BigUint::from_bytes_be(chunk))
        .collect();

    let prime = PRIME_MODULUS.get().unwrap();

    for (i, w) in words.iter().enumerate() {
        let idx = i % s.len();
        let curr = s[idx].clone();
        s[idx] = (curr + w) % prime;

        let next_idx = (idx + 1) % s.len();
        let next_curr = s[next_idx].clone();
        let shift = w >> 16usize;
        let mask = (BigUint::one() << wb) - BigUint::one();
        let updated_next = next_curr ^ (&shift & &mask);
        s[next_idx] = updated_next;
    }

    s
}

pub fn ApplyLinearDiffusion(state: &Vec<BigUint>) -> Vec<BigUint> {
    let n = state.len();
    let wb = WordBitsValue();
    let prime = PRIME_MODULUS.get().unwrap();
    let mut out = vec![BigUint::zero(); n];

    for i in 0..n {
        let a = &state[i];
        let b = &state[(i + 1) % n];
        let c = &state[(i + 7) % n];
        let mix = (a + &(b ^ &(c >> 3usize))) % prime;
        out[i] = Rol(&mix, (i * 3) % wb, wb);
    }
    out
}

pub fn ApplyNonLinearConfusion(state: &Vec<BigUint>) -> Vec<BigUint> {
    let prime = PRIME_MODULUS.get().unwrap();
    state
        .iter()
        .map(|x| {
            let x3 = x.modpow(&BigUint::from(3u32), prime);
            let x5 = x.modpow(&BigUint::from(5u32), prime);
            (x3 + x5 + BigUint::from(17u32)) % prime
        })
        .collect()
}

pub fn PerformRound(state: &Vec<BigUint>) -> Vec<BigUint> {
    let s = ApplyLinearDiffusion(state);
    ApplyNonLinearConfusion(&s)
}

// =========================================================
//   FINALIZATION
// =========================================================

pub fn FinalizeState(state: &Vec<BigUint>) -> Vec<BigUint> {
    let mut s = state.clone();
    for _ in 0..4 {
        s = ApplyLinearDiffusion(&s);
        s = ApplyNonLinearConfusion(&s);
    }
    s
}

pub fn ExtractDigest(state: &Vec<BigUint>) -> Vec<u8> {
    InitializeParameters();

    let mut hasher = Shake256::default();
    hasher.update(SeedString);
    hasher.update(b"::extract");

    for v in state {
        let bytes = v.to_bytes_be();
        let full_bytes = if bytes.len() < BytesPerElemValue() {
            let mut padded = vec![0u8; BytesPerElemValue() - bytes.len()];
            padded.extend_from_slice(&bytes);
            padded
        } else {
            bytes
        };
        hasher.update(&full_bytes);
    }

    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; OutputBitLength / 8];
    XofReader::read(&mut reader, &mut out);
    out
}

// =========================================================
//   TOP-LEVEL HASH
// =========================================================

pub fn SplitIntoBlocks(message: &[u8]) -> Vec<Vec<u8>> {
    let l = message.len();
    let rate = BlockBytes;
    let padlen = ((-(l as isize) - 2).rem_euclid(rate as isize)) as usize;

    let mut padded = Vec::from(message);
    padded.push(0x01);
    padded.extend(vec![0x00; padlen]);
    padded.push(0x80);

    padded.chunks(rate).map(|chunk| chunk.to_vec()).collect()
}

pub fn Hls1024Hash(message: &[u8]) -> Vec<u8> {
    let mut state = InitializeState();

    for blk in SplitIntoBlocks(message) {
        state = AbsorbMessageBlock(&state, &blk);
        for _ in 0..RoundCount {
            state = PerformRound(&state);
        }
    }

    state = FinalizeState(&state);
    ExtractDigest(&state)
}

// =========================================================
//   SELF-TEST & CLI
// =========================================================

fn RunSelfTest() {
    println!("Running HLS-1024 v0.2 self-test...");
    let msg = b"selftest";
    let d1 = Hls1024Hash(msg);
    let d2 = Hls1024Hash(msg);
    if d1 != d2 {
        println!("FAIL: Non-deterministic output");
    } else {
        println!("PASS: Deterministic");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut message: Option<String> = None;
    let mut file_path: Option<String> = None;
    let mut selftest = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--message" => {
                if i + 1 < args.len() {
                    message = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-f" | "--file" => {
                if i + 1 < args.len() {
                    file_path = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--selftest" => {
                selftest = true;
            }
            _ => {}
        }
        i += 1;
    }

    if selftest {
        RunSelfTest();
        return;
    }

    let data: Vec<u8> = if let Some(path) = file_path {
        fs::read(path).expect("Failed to read file")
    } else if let Some(msg) = message {
        msg.into_bytes()
    } else {
        let mut buffer = Vec::new();
        io::stdin().read_to_end(&mut buffer).unwrap();
        buffer
    };

    let digest = Hls1024Hash(&data);
    println!("{}", hex::encode(digest));
}
