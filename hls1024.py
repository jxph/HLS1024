# =========================================================
#   HLS-1024 : Post-Quantum Hash Function
#   Version  : v0.1
#   Author   : JXPH
#   Purpose  : Reference Build (Baseline)
# =========================================================

from hashlib import shake_128, shake_256
from typing import List, Optional
import sys, argparse

# =========================================================
#   GLOBAL PARAMETERS
# =========================================================

PrimeModulus: Optional[int] = None
StateSize = 512
RoundCount = 16
OutputBitLength = 1024
_BLOCK_BYTES = 64
_SEED_STRING = b"HLS-1024-v0.1"

_WORD_BITS: Optional[int] = None
_BYTES_PER_ELEM: Optional[int] = None


# =========================================================
#   PARAMETER INITIALIZATION
# =========================================================
def InitializeParameters():
    global PrimeModulus, _WORD_BITS, _BYTES_PER_ELEM
    if PrimeModulus is None:
        PrimeModulus = int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A63A36210000000000090563", 16
        )
    _WORD_BITS = PrimeModulus.bit_length()
    _BYTES_PER_ELEM = (_WORD_BITS + 7) // 8


def WordBits() -> int:
    InitializeParameters()
    return _WORD_BITS


def BytesPerElem() -> int:
    InitializeParameters()
    return _BYTES_PER_ELEM


# =========================================================
#   INTERNAL UTILS
# =========================================================
def _shake_ints(seed: bytes, count: int, bytes_per_int: Optional[int] = None) -> List[int]:
    InitializeParameters()
    if bytes_per_int is None:
        bytes_per_int = BytesPerElem()
    xof = shake_128(seed)
    raw = xof.digest(count * bytes_per_int)
    return [int.from_bytes(raw[i * bytes_per_int:(i + 1) * bytes_per_int], "big") for i in range(count)]


def derive_const(label: bytes, n: int) -> List[int]:
    seed = _SEED_STRING + b"::const::" + label
    return [x % PrimeModulus for x in _shake_ints(seed, n)]


def InitializeState() -> List[int]:
    return derive_const(b"init", StateSize)


# =========================================================
#   CORE TRANSFORMS
# =========================================================
def rol(x: int, r: int, bits: int) -> int:
    r %= bits
    return ((x << r) | (x >> (bits - r))) & ((1 << bits) - 1)


def AbsorbMessageBlock(state: List[int], block: bytes) -> List[int]:
    s = state.copy()
    WB = WordBits()
    word_bytes = 8
    if len(block) % word_bytes != 0:
        block += b"\x00" * (word_bytes - len(block) % word_bytes)
    words = [int.from_bytes(block[i:i + word_bytes], "big") for i in range(0, len(block), word_bytes)]
    for i, w in enumerate(words):
        idx = i % len(s)
        s[idx] = (s[idx] + w) % PrimeModulus
        s[(idx + 1) % len(s)] ^= (w >> 16) & ((1 << WB) - 1)
    return s


def ApplyLinearDiffusion(state: List[int]) -> List[int]:
    n = len(state)
    WB = WordBits()
    out = [0] * n
    for i in range(n):
        a, b, c = state[i], state[(i + 1) % n], state[(i + 7) % n]
        mix = (a + (b ^ (c >> 3))) % PrimeModulus
        out[i] = rol(mix, (i * 3) % WB, WB)
    return out


def ApplyNonLinearConfusion(state: List[int]) -> List[int]:
    o = []
    for x in state:
        x3 = pow(x, 3, PrimeModulus)
        x5 = pow(x, 5, PrimeModulus)
        o.append((x3 + x5 + 17) % PrimeModulus)
    return o


def PerformRound(state: List[int]) -> List[int]:
    s = ApplyLinearDiffusion(state)
    s = ApplyNonLinearConfusion(s)
    return s


# =========================================================
#   FINALIZATION
# =========================================================
def FinalizeState(state: List[int]) -> List[int]:
    s = state.copy()
    for _ in range(4):
        s = ApplyLinearDiffusion(s)
        s = ApplyNonLinearConfusion(s)
    return s


def ExtractDigest(state: List[int]) -> bytes:
    InitializeParameters()
    xof = shake_256()
    xof.update(_SEED_STRING + b"::extract")
    for v in state:
        xof.update(int(v).to_bytes(BytesPerElem(), "big"))
    return xof.digest(OutputBitLength // 8)


# =========================================================
#   TOP-LEVEL HASH
# =========================================================
def SplitIntoBlocks(message: bytes) -> List[bytes]:
    L = len(message)
    rate = _BLOCK_BYTES
    padlen = (-L - 2) % rate
    padded = message + b'\x01' + b'\x00' * padlen + b'\x80'
    return [padded[i:i + rate] for i in range(0, len(padded), rate)]


def HLS1024Hash(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("HLS1024Hash expects bytes")
    state = InitializeState()
    for blk in SplitIntoBlocks(message):
        state = AbsorbMessageBlock(state, blk)
        for _ in range(RoundCount):
            state = PerformRound(state)
    state = FinalizeState(state)
    return ExtractDigest(state)


# =========================================================
#   SELF-TEST & CLI
# =========================================================
def run_selftest():
    print("Running HLS-1024 v0.1 self-test...")
    msg = b"selftest"
    d1 = HLS1024Hash(msg)
    d2 = HLS1024Hash(msg)
    if d1 != d2:
        print("FAIL: Non-deterministic output")
        return
    print("PASS: Deterministic")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HLS-1024 v0.1")
    parser.add_argument("-m", "--message", type=str, help="Message to hash")
    parser.add_argument("-f", "--file", type=str, help="File path to hash")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args()

    if args.selftest:
        run_selftest()
        sys.exit(0)

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    elif args.message:
        data = args.message.encode()
    else:
        data = sys.stdin.buffer.read() or b""

    print(HLS1024Hash(data).hex())
