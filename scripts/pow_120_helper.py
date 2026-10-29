#!/usr/bin/env python3
"""PoW solver + connector helper for challenge 120 (It's Not My Fault 2).
PoW: find string starting with PREFIX (5 digits) whose md5 hex ends with SUFFIX (6 hex).
~16^6 = 16.7M expected trials; single-threaded Python does ~1M md5/s -> ~15-30s. Use 4 procs.
"""
import hashlib, itertools, multiprocessing as mp, sys

def pow_search(prefix, suffix, start=0, step=1, alphabet='0123456789abcdef', maxlen=12):
    suffix = suffix.lower()
    n = 0
    # variable-length suffix brute force: prefix + counter bytes
    i = start
    while True:
        cand = f"{prefix}{i}".encode()
        h = hashlib.md5(cand).hexdigest()
        if h.endswith(suffix):
            return cand.decode()
        i += step
        n += 1

def _worker(args):
    prefix, suffix, start, step, limit = args
    i = start
    end = start + limit
    while i < end:
        cand = f"{prefix}{i}".encode()
        if hashlib.md5(cand).hexdigest().endswith(suffix):
            return cand.decode()
        i += step
    return None

def solve_pow(prefix, suffix, workers=4, batch=2_000_000):
    suffix = suffix.lower()
    start = 0
    with mp.Pool(workers) as pool:
        while True:
            args = [(prefix, suffix, start + w * batch // workers, workers, batch // workers)
                    for w in range(workers)]
            # simpler: each worker scans stride
            args = [(prefix, suffix, start + w, workers, batch) for w in range(workers)]
            for res in pool.imap_unordered(_worker, args):
                if res:
                    pool.terminate()
                    return res
            start += batch * workers

if __name__ == '__main__':
    prefix, suffix = sys.argv[1], sys.argv[2]
    print(solve_pow(prefix, suffix))
