#!/usr/bin/env python3
"""
mutator.py -- AFL++ Python custom mutator for PDF structural mutations.

Improvements:
 - Dictionary mutation now infers new types from old values instead of always falling back to /Name.
 - Strings are mutated in-place (flip, extend, shrink, duplicate) or regenerated.
 - Arrays can be mutated heterogeneously: remove/duplicate/replace elements, add references from PDF.
 - Streams can mutate large slices, append big patterns, or inflate in size.
"""

import os
import io
import sys
import pickle
import hashlib
from pathlib import Path
from typing import Any, Dict, List
import random
import traceback

sys.setrecursionlimit(20000)

try:
    import pikepdf
    from pikepdf import Name, Dictionary, Array, Stream
except Exception as e:
    print("ERROR: pikepdf required. Install: pip3 install pikepdf", file=sys.stderr)
    raise

# -----------------------------
# Config
# -----------------------------
HEADER_SIZE = 4
DEFAULT_MUTATION_COUNT = 100
MAX_DB_SIZE = 30000
MAX_CALL_COUNT = 200000
MAX_STRING_SIZE = 1000
MAX_INTEGER_RANGE = 2**31
MAX_RECURSION = 8
MAX_SCALE_FACTOR = 1000.0

BANNED_KEYS = {"/Length", "/Kids"}

DEFAULT_PDF_DIR = Path(os.environ.get("MUTATOR_PDF_DIR", "./pdf_seed_corpus/"))
DEFAULT_PKL_PATH = Path(os.environ.get("MUTATOR_PKL_PATH", "./resources.pkl"))

_mutation_count = DEFAULT_MUTATION_COUNT
_initialized = False
_resources_db: List[Dict[str, Any]] = []

# -----------------------------
# Helpers
# -----------------------------
def dprint(msg: str):
    print("[DEBUG]", msg)

def rng_from_buf(buf: bytes) -> random.Random:
    # stable RNG seeded from input buf
    h = hashlib.sha256(buf[:128]).digest()
    seed = int.from_bytes(h[:8], "little")
    return random.Random(seed)

def pick_choice(seq, rng: random.Random):
    if not seq: return None
    return seq[rng.randrange(len(seq))]

def collect_named_objects(pdf) -> List[Name]:
    names = []
    try:
        for obj in pdf.objects:
            if isinstance(obj, Dictionary):
                for v in obj.values():
                    if isinstance(v, Name):
                        names.append(v)
            elif isinstance(obj, Array):
                for v in obj:
                    if isinstance(v, Name):
                        names.append(v)
    except Exception:
        pass
    if not names:
        names = [Name("/Fallback")]
    return names

# -----------------------------
# Mutation primitives
# -----------------------------
def mutate_string_value(s: str, rng: random.Random) -> str:
    if not s or rng.random() < 0.3:
        # regenerate random string
        return "".join(chr(32 + rng.randrange(95)) for _ in range(rng.randint(1, MAX_STRING_SIZE)))
    s = list(s)
    choice = rng.randrange(4)
    if choice == 0 and s:
        # flip char
        idx = rng.randrange(len(s))
        s[idx] = chr(32 + rng.randrange(95))
    elif choice == 1:
        # duplicate chunk
        if len(s) > 2:
            start = rng.randrange(len(s)-1)
            end = min(len(s), start + rng.randint(1, 10))
            s = s[:end] + s[start:end]*rng.randint(1,3) + s[end:]
    elif choice == 2 and s:
        # truncate
        s = s[:rng.randrange(len(s))]
    elif choice == 3:
        # extend
        s += [chr(32 + rng.randrange(95)) for _ in range(rng.randint(1,50))]
    return "".join(s)

def mutate_array_value(arr: Array, rng: random.Random, pdf=None) -> None:
    if not arr:
        arr.append(rng.randint(-100, 100))
        return
    choice = rng.randrange(4)
    if choice == 0:
        # remove random element
        idx = rng.randrange(len(arr))
        del arr[idx]
    elif choice == 1:
        # duplicate random element
        idx = rng.randrange(len(arr))
        arr.insert(idx, arr[idx])
    elif choice == 2:
        # replace with random value
        idx = rng.randrange(len(arr))
        val = arr[idx]
        if isinstance(val, int):
            arr[idx] = val + rng.randint(-500,500)
        elif isinstance(val, float):
            arr[idx] = val * (1.0 + (rng.random()-0.5)*2)
        elif isinstance(val, str):
            arr[idx] = mutate_string_value(val, rng)
        elif isinstance(val, Name) and pdf:
            arr[idx] = rng.choice(collect_named_objects(pdf))
        else:
            arr[idx] = rng.randint(-1000,1000)
    else:
        # append new random element
        arr.append(rng.choice([rng.randint(-1000,1000), rng.random(), Name("/Rand"+str(rng.randint(0,9999)))]))

def mutate_stream_inplace(stream: Stream, rng: random.Random) -> bool:
    try:
        data = bytearray(stream.read_bytes() or b"")
    except Exception:
        try:
            data = bytearray(stream.read_raw_bytes() or b"")
        except Exception:
            return False
    if not data:
        data = bytearray(b"A")

    choice = rng.randrange(5)
    if choice == 0:
        pos = rng.randrange(len(data))
        data[pos] ^= 0xFF
    elif choice == 1:
        # insert random byte
        pos = rng.randrange(len(data))
        data.insert(pos, rng.randrange(256))
    elif choice == 2:
        # delete chunk
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randint(1, 32))
        del data[start:end]
    elif choice == 3:
        # duplicate large slice
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randint(50, min(1000,len(data)-start)))
        chunk = data[start:end]
        where = rng.randrange(len(data))
        data = data[:where] + chunk* rng.randint(1,4) + data[where:]
    else:
        # append big block
        block = bytes([rng.randrange(256)])*rng.randint(100,1000)
        data.extend(block)

    try:
        stream.write(bytes(data))
        return True
    except Exception:
        return False

def mutate_dict_inplace(obj: Dictionary, rng: random.Random, depth=0, pdf=None) -> bool:
    if not isinstance(obj, Dictionary) or not obj.keys():
        return False
    key = pick_choice(list(obj.keys()), rng)
    if key is None: return False
    val = obj[key]

    try:
        if isinstance(val, int):
            obj[key] = val + rng.randint(-1000,1000)
        elif isinstance(val, float):
            obj[key] = val * (1.0 + (rng.random()-0.5)*MAX_SCALE_FACTOR)
        elif isinstance(val, str):
            obj[key] = mutate_string_value(val, rng)
        elif isinstance(val, Name):
            if pdf:
                obj[key] = rng.choice(collect_named_objects(pdf))
            else:
                obj[key] = Name("/Rand" + str(rng.randint(0,9999)))
        elif isinstance(val, Array):
            mutate_array_value(val, rng, pdf=pdf)
        elif isinstance(val, Dictionary) and depth < MAX_RECURSION:
            mutate_dict_inplace(val, rng, depth+1, pdf=pdf)
        elif isinstance(val, Stream):
            mutate_stream_inplace(val, rng)
        else:
            # fallback: random type
            obj[key] = rng.choice([rng.randint(-1000,1000),
                                   rng.random(),
                                   mutate_string_value("", rng),
                                   Name("/Rand"+str(rng.randint(0,9999)))])
    except Exception:
        return False

    # occasional add/remove keys
    if rng.random() < 0.1:
        new_key = Name("/MutExtra"+str(rng.randint(0,9999)))
        obj[new_key] = rng.randint(-100,100)
    if rng.random() < 0.05 and obj.keys():
        try:
            del obj[pick_choice(list(obj.keys()), rng)]
        except Exception:
            pass
    return True

# -----------------------------
# Resource DB (unchanged)
# -----------------------------
def extract_resource_samples_from_pdf(pdf_path: Path) -> List[Dict[str, Any]]:
    samples = []
    try:
        with pikepdf.open(pdf_path) as pdf:
            for obj in pdf.objects:
                if isinstance(obj, (Dictionary, Array, Stream)):
                    try:
                        raw = obj
                        samples.append({"__type__": "dict", "value": {}})
                    except Exception:
                        continue
    except Exception:
        pass
    return samples

def build_resources_db_from_dir(pdf_dir: Path, pkl_path: Path) -> List[Dict[str, Any]]:
    db = []
    for p in sorted(pdf_dir.iterdir()):
        if not p.is_file() or p.suffix.lower() != ".pdf": continue
        db.extend(extract_resource_samples_from_pdf(p))
        if len(db) >= MAX_DB_SIZE: break
    with open(pkl_path,"wb") as fh:
        pickle.dump(db[:MAX_DB_SIZE], fh)
    return db[:MAX_DB_SIZE]

def load_resources_db(pdf_dir: Path, pkl_path: Path) -> List[Dict[str, Any]]:
    if pkl_path.exists():
        try:
            with open(pkl_path,"rb") as fh:
                return pickle.load(fh)
        except Exception:
            pass
    return build_resources_db_from_dir(pdf_dir, pkl_path)

# -----------------------------
# Core structural mutator
# -----------------------------
def choose_target_object(pdf: pikepdf.Pdf, rng: random.Random):
    cands = []
    for obj in pdf.objects:
        if isinstance(obj,(Dictionary,Stream)):
            cands.append(obj)
    return rng.choice(cands) if cands else None

def mutate_pdf_structural(buf: bytes, max_size: int, rng: random.Random) -> bytes:
    pdf = pikepdf.open(io.BytesIO(buf))
    target = choose_target_object(pdf, rng)
    if target is None:
        return buf
    if isinstance(target, Stream):
        mutate_stream_inplace(target, rng)
    elif isinstance(target, Dictionary):
        mutate_dict_inplace(target, rng, pdf=pdf)

    out = io.BytesIO()
    pdf.save(out, linearize=False, compress_streams=False)
    return out.getvalue()[:max_size]

# -----------------------------
# AFL++ API
# -----------------------------
def init(seed: int):
    global _initialized, _resources_db
    if _initialized: return
    _resources_db = load_resources_db(DEFAULT_PDF_DIR, DEFAULT_PKL_PATH)
    _initialized = True

def deinit():
    global _initialized
    _initialized = False

def fuzz_count(buf: bytearray) -> int:
    if len(buf) <= HEADER_SIZE: return 0
    try:
        core = buf[HEADER_SIZE:]
        with pikepdf.open(io.BytesIO(core)): pass
        return _mutation_count
    except Exception:
        return 0

def fuzz(buf: bytearray, add_buf, max_size: int) -> bytearray:
    header = buf[:HEADER_SIZE]
    core = buf[HEADER_SIZE:]
    rng = rng_from_buf(buf)
    mutated = mutate_pdf_structural(core, max_size-HEADER_SIZE, rng)
    return bytearray(header+mutated)

# -----------------------------
# CLI test
# -----------------------------
if __name__=="__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--mutate", nargs=2)
    args=ap.parse_args()
    if args.mutate:
        init(0)
        infile,outfile=args.mutate
        data=open(infile,"rb").read()
        data=b"\x00\x00\x00\x00"+data
        mutated=fuzz(bytearray(data),None,10_000_000)
        open(outfile,"wb").write(mutated)
        print("Wrote",outfile)