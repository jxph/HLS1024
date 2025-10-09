# HLS-1024 v0.2 — Post-Quantum Hash Function (Rust Port)

Ultra-fast, deterministic, and cryptographically hardened hash function for post-quantum systems.

## Overview

**HLS-1024** is a post-quantum hash function designed for secure systems — including signatures, proof-of-work, and PQ cryptographic primitives.

This Rust version (**v0.2**) is a complete rewrite of the original Python prototype, optimized for **speed and determinism** using **SHAKE256** and **arbitrary-precision math** (`num-bigint-dig`).

## Highlights

- Pure Rust implementation (no unsafe)
- Post-quantum resistant (non-lattice, SHAKE-based)
- BigInteger state model via `num-bigint-dig`
- Dual diffusion-confusion pipeline
- Deterministic domain separation
- 10–15× faster than the Python version

## Core Design

| Parameter | Value |
|------------|--------|
| State Size | 512 words |
| Rounds | 16 |
| Output | 1024 bits |
| Modulus | Large safe prime (~1024 bits) |
| Seed | b"HLS-1024-v0.2" |
| Block Size | 64 bytes |

## Usage

### Run from Command Line

```bash
cargo run --release -- --message "hello world"
```

### File Input

```bash
cargo run --release -- --file ./input.txt
```

### Self-Test

```bash
cargo run --release -- --selftest
```

## Integration Example

```rust
use hls1024::Hls1024Hash;

fn main() {
    let digest = Hls1024Hash(b"example message");
    println!("Digest: {}", hex::encode(digest));
}
```

## Build Info

**Language:** Rust  
**Dependencies:**  
```
num-bigint-dig = "0.8"
num-traits = "0.2"
sha3 = "0.10"
hex = "0.4"
```

## License

MIT License © 2025 JXPH
