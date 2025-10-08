# HLS-1024
**Post-Quantum Cryptographic Hash Function**  
**Version:** v0.1  
**Author:** JXPH

---

## Overview
**HLS-1024** is a 1024-bit post-quantum cryptographic hash function developed for the **SHI-1024** digital certificate framework.  
It employs modular arithmetic, nonlinear diffusion, and custom state transformations to ensure resistance against classical and quantum cryptanalysis.

The design is fully independent of SHA-family constructions and uses a deterministic sponge-like structure.

**Components**
- `hls1024.py` — Reference implementation  
- `test.py` — Validation and statistical analysis suite

---

## Key Features
- 1024-bit output digest  
- 512-element internal modular state  
- 24 nonlinear diffusion rounds  
- 4096-bit arithmetic modulus  
- Deterministic, non-SHA-based design  
- Pure Python reference, no third-party dependencies

---

## Default Parameters

| Parameter | Default | Description |
|------------|----------|-------------|
| `StateSize` | 512 | Number of integers in the internal state |
| `PrimeModulus` | 4096-bit prime | Modular arithmetic base |
| `RoundCount` | 24 | Transformation rounds per message block |
| `OutputBitLength` | 1024 | Output digest length |
| `_BLOCK_BYTES` | 64 | Input block size in bytes |

---

## Usage

### Hash a Message
```bash
python hls1024.py -m "Hello World"
```

### Hash a File
```bash
python hls1024.py -f path/to/file.bin
```

### Run Self-Test
```bash
python hls1024.py --selftest
```

If no argument is provided, the program reads data from **stdin**.

---

## Validation Suite

The validation suite (`test.py`) performs:  
- **Known-Answer Tests (KATs)**  
- **Avalanche analysis**  
- **Uniformity and autocorrelation statistics**  
- **Throughput and performance profiling**

### Run the Full Suite
```bash
python test.py
```

### Quick Mode
```bash
python test.py --fast
```

### Specify Custom Output Directory
```bash
python test.py --outdir results/custom
```

---

## Output Structure

All test results are stored under `results/<timestamp>/`.

| File | Description |
|------|--------------|
| `kats.json` | Known-answer test vectors |
| `avalanche.csv`, `avalanche_summary.json` | Avalanche effect data |
| `stats.json`, `bytefreq.csv` | Randomness and uniformity analysis |
| `throughput.txt` | Performance metrics |
| `profile.prof` | CPU profiling data |
| `summary.json` | Consolidated test results |

---

## Repository Layout

```
HLS1024/
├── hls1024.py       # Core reference implementation
├── test.py          # Validation suite
├── LICENSE          # License information
├── Kats.json        # Known Answer test Results
└── README.md        # Documentation
```

---

## Disclaimer
This implementation is **experimental** and intended **for research and educational purposes only**.  
It has **not been formally security-audited** and **must not** be used in production systems without independent review and verification.
