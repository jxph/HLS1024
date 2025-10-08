#!/usr/bin/env python3
# ==========================================================
#   HLS-1024 : Production Validation Suite
#   Version  : v0.1
#   Author   : JXPH
# ==========================================================

import os, sys, time, json, csv, argparse, secrets, cProfile, pstats
from datetime import datetime, timezone
from collections import Counter

# --- Import from reference implementation ---
from hls1024 import (
    HLS1024Hash,
    InitializeParameters,
    SplitIntoBlocks,
    StateSize,
    _BLOCK_BYTES
)

# ==========================================================
#   CONFIGURATION
# ==========================================================

AvalancheTrials       = 256
AvalancheMsgBytes     = 64
PerRoundSamples       = 64
PerRoundMaxRounds     = 24
ThroughputSamples     = 16
ProfileHashes         = 32
CollisionToyAttempts  = 200000
FastModeFactor        = 0.1

# ==========================================================
#   HELPERS
# ==========================================================

def MkDir(path):
    os.makedirs(path, exist_ok=True)

def TimeStamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

def SaveJSON(path, obj):
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)

def AppendCSV(path, header, rows):
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if write_header: w.writerow(header)
        for r in rows: w.writerow(r)

def BitCount(b: bytes):
    return sum(bin(x).count("1") for x in b)

def ByteFreq(digests):
    cnt = Counter()
    for d in digests: cnt.update(d)
    total = sum(cnt.values())
    return {i: cnt[i]/total for i in range(256)}

def BitFreq(digests):
    counts = [0]*(len(digests[0])*8)
    for d in digests:
        bits = ''.join(f"{x:08b}" for x in d)
        for i,ch in enumerate(bits): counts[i] += (ch == '1')
    total = len(digests)
    return [counts[i]/total for i in range(len(counts))]

def AutoCorr(digests, lag=1):
    bits = ''.join(''.join(f"{x:08b}" for x in d) for d in digests)
    N = len(bits)
    if N <= lag: return 0.0
    same = sum(1 for i in range(N-lag) if bits[i] == bits[i+lag])
    return same / (N-lag)

# ==========================================================
#   CORE TESTS
# ==========================================================

def RunKATs(outroot):
    kat_msgs = [b"", b"abc", b"The quick brown fox jumps over the lazy dog", b"Wasrichie"]
    path = os.path.join(outroot, "kats.json")
    data = {}
    print("[KAT] generating known-answer tests...")
    for m in kat_msgs:
        h = HLS1024Hash(m).hex()
        data[m.decode("utf-8", errors="replace")] = h
        print(f"  {repr(m)} -> {h[:64]}...")
    SaveJSON(path, data)
    return data

def RunAvalanche(outroot, fast=False):
    trials = AvalancheTrials if not fast else int(AvalancheTrials * FastModeFactor)
    print(f"[Avalanche] {trials} trials on {AvalancheMsgBytes}-byte messages")
    csvpath = os.path.join(outroot, "avalanche.csv")
    header = ["trial","flip_index","diff_bits","fraction"]
    rows, fractions = [], []
    for t in range(trials):
        base = secrets.token_bytes(AvalancheMsgBytes)
        d0 = HLS1024Hash(base)
        pos, bit = secrets.randbelow(len(base)), 1 << secrets.randbelow(8)
        mod = bytearray(base)
        mod[pos] ^= bit
        d1 = HLS1024Hash(bytes(mod))
        diff = BitCount(bytes(x ^ y for x,y in zip(d0,d1)))
        frac = diff / (len(d0)*8)
        rows.append([t, f"{pos}:{bit}", diff, f"{frac:.6f}"])
        fractions.append(frac)
    AppendCSV(csvpath, header, rows)
    summary = {"mean": sum(fractions)/len(fractions), "min": min(fractions), "max": max(fractions)}
    SaveJSON(os.path.join(outroot, "avalanche_summary.json"), summary)
    print("[Avalanche] done", summary)
    return summary

def RunStats(outroot, fast=False):
    count = 512 if not fast else 64
    print(f"[Stats] generating {count} random digests")
    digests = [HLS1024Hash(secrets.token_bytes(64)) for _ in range(count)]
    bitfreq = BitFreq(digests)
    bytefreq = ByteFreq(digests)
    stats = {
        "bit_mean": sum(bitfreq)/len(bitfreq),
        "autocorr": AutoCorr(digests, lag=1)
    }
    SaveJSON(os.path.join(outroot, "stats.json"), stats)
    AppendCSV(os.path.join(outroot, "bytefreq.csv"), ["byte","frequency"], [(i, bytefreq[i]) for i in range(256)])
    return stats

def RunThroughput(outroot, fast=False):
    samples = ThroughputSamples if not fast else 4
    print(f"[Throughput] hashing {samples} × 4KB blocks")
    t0 = time.time()
    for _ in range(samples): HLS1024Hash(secrets.token_bytes(4096))
    dt = time.time() - t0
    kbps = samples * 4096 / dt / 1024
    with open(os.path.join(outroot, "throughput.txt"), "w") as f:
        f.write(f"{samples} samples, {dt:.3f}s, {kbps:.2f} KB/s\n")
    print(f"[Throughput] {kbps:.2f} KB/s")
    return {"samples": samples, "seconds": dt, "kbps": kbps}

def RunProfiler(outroot, fast=False):
    hashes = ProfileHashes if not fast else 8
    print(f"[Profile] running {hashes} hashes")
    pr = cProfile.Profile()
    pr.enable()
    for _ in range(hashes): HLS1024Hash(secrets.token_bytes(1024))
    pr.disable()
    prof_path = os.path.join(outroot, "profile.prof")
    pr.dump_stats(prof_path)
    print("[Profile] saved to", prof_path)
    return prof_path

# ==========================================================
#   MAIN ORCHESTRATION
# ==========================================================

def RunAll(outroot, fast=False):
    MkDir(outroot)
    result = {}
    result["kats"]       = RunKATs(outroot)
    result["avalanche"]  = RunAvalanche(outroot, fast)
    result["stats"]      = RunStats(outroot, fast)
    result["throughput"] = RunThroughput(outroot, fast)
    result["profile"]    = RunProfiler(outroot, fast)
    SaveJSON(os.path.join(outroot, "summary.json"), result)
    print("\ All core tests complete. Results in:", outroot)
    return result

# ==========================================================
#   CLI
# ==========================================================

def Main():
    parser = argparse.ArgumentParser(description="HLS-1024 Production Validation Suite")
    parser.add_argument("--fast", action="store_true", help="run reduced quick mode")
    parser.add_argument("--outdir", type=str, default=None, help="output directory (default ./results/timestamp)")
    args = parser.parse_args()

    outroot = args.outdir or os.path.join("results", TimeStamp())
    print("Results directory:", outroot)
    RunAll(outroot, fast=args.fast)

if __name__ == "__main__":
    Main()
