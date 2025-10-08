# =========================================================
#   HLS-1024 : Post-Quantum Hash Function
#   Version  : v0.1
#   Author   : JXPH
#   Purpose  : Reference Build
# =========================================================

from hashlib import shake_128, shake_256
from typing import List, Optional
import sys, argparse

PrimeModulus: Optional[int] = None
StateSize = 512
RoundCount = 24
OutputBitLength = 1024
_BLOCK_BYTES = 64
_SEED_STRING = b"HLS-1024-SEED-v1.0"

_WORD_BITS: Optional[int] = None
_BYTES_PER_ELEM: Optional[int] = None


# =========================================================
#   PARAMETER / CONSTANT INITIALIZATION
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


def _shake_ints(seed: bytes, count: int, bytes_per_int: Optional[int] = None) -> List[int]:
    InitializeParameters()
    if bytes_per_int is None:
        bytes_per_int = BytesPerElem()
    xof = shake_128(seed)
    raw = xof.digest(count * bytes_per_int)
    return [int.from_bytes(raw[i * bytes_per_int:(i + 1) * bytes_per_int], "big") for i in range(count)]


def derive_const(label: bytes, n: int, bytes_per_int: Optional[int] = None) -> List[int]:
    seed = _SEED_STRING + b"::const::" + label
    return _shake_ints(seed, n, bytes_per_int)


def InitializeState() -> List[int]:
    InitializeParameters()
    return [x % PrimeModulus for x in derive_const(b"initial-state", StateSize)]


def GenerateMixingVector(seed_value: bytes) -> List[int]:
    label = b"mixvec::" + seed_value
    return [x % PrimeModulus for x in derive_const(label, StateSize)]


# =========================================================
#   CORE TRANSFORMS
# =========================================================
def rol(x: int, r: int, bits: int) -> int:
    r %= bits
    return ((x << r) | (x >> (bits - r))) & ((1 << bits) - 1)


def AbsorbMessageBlock(state: List[int], message_block: bytes) -> List[int]:
    InitializeParameters()
    n = len(state)
    word_bytes = 8
    if len(message_block) % word_bytes != 0:
        message_block += b"\x00" * (word_bytes - len(message_block) % word_bytes)
    words = [int.from_bytes(message_block[i:i + word_bytes], "big") for i in range(0, len(message_block), word_bytes)]
    s = state.copy()
    for i, w in enumerate(words):
        idx = i % n
        s[idx] = (s[idx] + (w % PrimeModulus)) % PrimeModulus
        s[(idx + 1) % n] ^= (w >> 32) & ((1 << WordBits()) - 1)
    extra = shake_128(_SEED_STRING + b"::absorb::" + message_block).digest(BytesPerElem() * 2)
    for j, bv in enumerate(extra):
        s[j % n] = (s[j % n] ^ bv) % PrimeModulus
    return s


def ApplyLinearDiffusion(state: List[int], mv: List[int]) -> List[int]:
    n = len(state)
    WB = WordBits()
    o = [0] * n
    for i in range(n):
        x, y, z, k = state[i], state[(i + 1) % n], state[(i + 7) % n], mv[i]
        v = (x + ((y ^ z) * (k | 1))) % PrimeModulus
        v = rol(v, k, WB)
        o[i] = (v + (y ^ (z >> 3))) % PrimeModulus
    return o


def ApplyNonLinearConfusion(state: List[int]) -> List[int]:
    WB = WordBits()
    o = []
    for x in state:
        x3, x5 = pow(x, 3, PrimeModulus), pow(x, 5, PrimeModulus)
        rot_amount = (x >> 5) & (WB - 1)
        rot = rol(x, int(rot_amount), WB)
        o.append((x3 + x5 + rot + 17) % PrimeModulus)
    return o


def RotateState(state: List[int], r: int) -> List[int]:
    n = len(state)
    if not n:
        return state.copy()
    r %= n
    return state[-r:] + state[:-r] if r else state.copy()


def PerformRound(state: List[int], block: bytes, mv: List[int]) -> List[int]:
    tweak = shake_128(_SEED_STRING + b"::round-tweak::" + block).digest(16)
    s = AbsorbMessageBlock(state, tweak)
    s = ApplyLinearDiffusion(s, mv)
    s = ApplyNonLinearConfusion(s)
    s = RotateState(s, mv[0] % len(s))
    return s


def FinalizeState(state: List[int]) -> List[int]:
    final_mv = GenerateMixingVector(_SEED_STRING + b"::finalize")
    s = AbsorbMessageBlock(state, b"HLS-1024-FINALIZE")
    for i in range(max(4, RoundCount // 3)):
        s = ApplyLinearDiffusion(s, final_mv)
        s = ApplyNonLinearConfusion(s)
        s = RotateState(s, (i * 13) % len(s))
    return s


def ExtractDigest(state: List[int]) -> bytes:
    InitializeParameters()
    out_bytes = OutputBitLength // 8
    xof = shake_256()
    domain_info = (
        f"HLS1024|v1.0|StateSize={StateSize}|Rounds={RoundCount}|PrimeBits={PrimeModulus.bit_length()}|OutBits={OutputBitLength}".encode()
    )
    xof.update(domain_info)
    bpe = BytesPerElem()
    for v in state:
        xof.update(int(v).to_bytes(bpe, "big"))
    xof.update(b"::hls1024-extract")
    return xof.digest(out_bytes)


# =========================================================
#   MESSAGE & TOP-LEVEL HASH
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
    InitializeParameters()
    state = InitializeState()
    for i, blk in enumerate(SplitIntoBlocks(bytes(message))):
        mv_seed = _SEED_STRING + b"::block::" + i.to_bytes(8, "big")
        mv = GenerateMixingVector(mv_seed)
        state = AbsorbMessageBlock(state, blk)
        for _ in range(RoundCount):
            state = PerformRound(state, blk, mv)
    return ExtractDigest(FinalizeState(state))


# =========================================================
#   SELF-TEST & CLI
# =========================================================
def run_selftest():
    print("Running quick self-test...")
    msg = b"selftest"
    if HLS1024Hash(msg) != HLS1024Hash(msg):
        print("FAIL determinism")
        return
    print("OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HLS-1024 v1.0-beta")
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












# vi9deo          ---
#video --------------------------
#
