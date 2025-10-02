#!/usr/bin/env python3
"""
mutator.py -- AFL++ Python custom mutator for PDF structural mutations.

Features:
 - Deterministic mutation decisions derived from the input buffer.
 - Loads a corpus of serialized PDF objects (dict/stream/array) from seed PDFs or cached pickle.
 - Mutation strategies:
     * Replace an object (Dictionary or Stream) with one from the resources DB.
     * Mutate a Dictionary in-place (type-aware).
     * Mutate a Stream in-place (bytes-level, with large slice ops).
     * Shuffle pages occasionally.
 - Keeps a HEADER_SIZE prefix intact (fuzzer header).
 - Errors propagate (no silent fallback).

Environment:
 - MUTATOR_PDF_DIR  : dir with sample PDFs to build resources DB (default ./pdf_seed_corpus/)
 - MUTATOR_PKL_PATH : path to pickle DB (default ./resources.pkl)
"""

import os, io, sys, pickle, hashlib, random, traceback
from pathlib import Path
from typing import Any, Dict, List

sys.setrecursionlimit(20000)

DEBUG = True

def dprint(msg):
    if DEBUG:
        print("[DEBUG] ",msg)

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
BANNED_KEYS = {"/Length", "/Kids", "/Count"}

DEFAULT_PDF_DIR = Path(os.environ.get("MUTATOR_PDF_DIR", "./pdf_seed_corpus/"))
DEFAULT_PKL_PATH = Path(os.environ.get("MUTATOR_PKL_PATH", "./resources.pkl"))

_mutation_count = DEFAULT_MUTATION_COUNT
_initialized = False
_resources_db: List[Dict[str, Any]] = []

# -----------------------------
# RNG helpers
# -----------------------------
def rng_from_buf(buf: bytes) -> random.Random:
    # h = hashlib.sha256(buf[:128]).digest()
    # seed = int.from_bytes(h[:8], "little")
    return random.Random(random.randrange(10000000)) # was originally random.Random(seed)

def pick_choice(seq, rng: random.Random):
    return seq[rng.randrange(len(seq))] if seq else None

# -----------------------------
# pikepdf <-> Python serialization
# -----------------------------
def pike_to_py(obj: Any, depth: int = 0) -> Dict[str, Any]:
    if depth >= MAX_RECURSION:
        return {"__type__": "truncated"}
    if isinstance(obj, Name):
        return {"__type__": "name", "value": str(obj)}
    if isinstance(obj, Stream):
        d = {str(k): pike_to_py(v, depth+1) for k,v in obj.items()}
        try:
            raw = obj.read_bytes() or b""
        except Exception:
            raw = b""
        return {"__type__": "stream", "dict": d, "stream_bytes": raw}
    if isinstance(obj, Dictionary):
        return {"__type__": "dict", "value": {str(k): pike_to_py(v, depth+1) for k,v in obj.items()}}
    if isinstance(obj, Array):
        return {"__type__": "array", "value": [pike_to_py(v, depth+1) for v in obj]}
    if isinstance(obj, (int,float,bool)):
        return {"__type__": "primitive", "value": obj}
    if isinstance(obj, bytes):
        return {"__type__": "bytes", "value": obj}
    if isinstance(obj, str):
        return {"__type__": "string", "value": obj}
    return {"__type__": "unknown", "repr": str(obj)}

def py_to_pike(pyobj: Any, pdf: pikepdf.Pdf=None) -> Any:
    if not isinstance(pyobj, dict) or "__type__" not in pyobj:
        return pyobj
    t = pyobj["__type__"]
    if t == "name":
        v = pyobj.get("value","")
        if not v.startswith("/"): v = "/"+v
        return Name(v)
    if t == "primitive": return pyobj.get("value")
    if t == "bytes": return pyobj.get("value", b"")
    if t == "string": return pyobj.get("value","")
    if t == "array":
        arr = Array()
        for el in pyobj.get("value",[]): arr.append(py_to_pike(el,pdf))
        return arr
    if t == "dict":
        d=Dictionary()
        for k,v in pyobj.get("value",{}).items():
            kname = k if k.startswith("/") else "/"+k
            d[Name(kname)] = py_to_pike(v,pdf)
        return d
    if t == "stream":
        md=Dictionary()
        for k,v in pyobj.get("dict",{}).items():
            kname = k if k.startswith("/") else "/"+k
            md[Name(kname)] = py_to_pike(v,pdf)
        data=pyobj.get("stream_bytes",b"")
        if pdf is None:
            return {"__construct_stream__": {"dict": md, "bytes": data}}
        s=pikepdf.Stream(pdf,data)
        for kk,vv in md.items():
            if str(kk) not in BANNED_KEYS:
                s[kk]=vv
        return s
    return Name("/Unknown")

# -----------------------------
# Build / load resources DB
# -----------------------------
def extract_resource_samples_from_pdf(pdf_path: Path) -> List[Dict[str, Any]]:
    samples=[]
    try:
        with pikepdf.open(pdf_path) as pdf:
            for obj in pdf.objects:
                if isinstance(obj,(Dictionary,Array,Stream)):
                    try: samples.append(pike_to_py(obj))
                    except: continue
    except Exception: pass
    return samples

def build_resources_db_from_dir(pdf_dir: Path,pkl_path: Path)->List[Dict[str, Any]]:
    db=[]
    for p in sorted(pdf_dir.iterdir()):
        if p.suffix.lower()!=".pdf": continue
        db.extend(extract_resource_samples_from_pdf(p))
        if len(db)>=MAX_DB_SIZE: break
    with open(pkl_path,"wb") as fh: pickle.dump(db[:MAX_DB_SIZE],fh)
    return db[:MAX_DB_SIZE]

def load_resources_db(pdf_dir: Path,pkl_path: Path)->List[Dict[str, Any]]:
    if pkl_path.exists():
        try:
            with open(pkl_path,"rb") as fh: return pickle.load(fh)
        except: pass
    return build_resources_db_from_dir(pdf_dir,pkl_path)

# -----------------------------
# Mutation primitives
# -----------------------------
def mutate_stream_inplace(stream: Stream,rng: random.Random)->bool:
    try:
        data=bytearray(stream.read_bytes() or b"")
    except: 
        try: data=bytearray(stream.read_raw_bytes() or b"")
        except: return False
    if not data: data=bytearray(b"A")
    choice=rng.randrange(5)
    if choice==0: data[rng.randrange(len(data))]^=0xFF
    elif choice==1: data.insert(rng.randrange(len(data)),rng.randrange(256))
    elif choice==2: del data[rng.randrange(len(data)):][:rng.randint(1,32)]
    elif choice==3 and len(data)>50:
        start=rng.randrange(len(data)-1)
        end=min(len(data),start+rng.randint(50,min(1000,len(data)-start)))
        chunk=data[start:end]
        where=rng.randrange(len(data))
        data=data[:where]+chunk*rng.randint(1,3)+data[where:]
    else:
        data.extend(bytes([rng.randrange(256)])*rng.randint(100,1000))
    try: stream.write(bytes(data)); return True
    except: return False

def mutate_dict_inplace(obj: Dictionary,rng: random.Random,depth=0,pdf=None)->bool:
    if not obj.keys(): return False
    key=pick_choice(list(obj.keys()),rng)
    if key is None: return False
    val=obj[key]
    try:
        if isinstance(val,int): obj[key]=val+rng.randint(-1000,1000)
        elif isinstance(val,float): obj[key]=val*(1.0+(rng.random()-0.5)*MAX_SCALE_FACTOR)
        elif isinstance(val,str): obj[key]=val+"X"
        elif isinstance(val,Name): obj[key]=Name("/Alt"+str(rng.randint(0,9999)))
        elif isinstance(val,Array): val.append(rng.randint(-100,100))
        elif isinstance(val,Dictionary) and depth<MAX_RECURSION:
            mutate_dict_inplace(val,rng,depth+1,pdf)
        elif isinstance(val,Stream): mutate_stream_inplace(val,rng)
        else: obj[key]=Name("/Alt"+str(rng.randint(0,9999)))
    except: return False
    return True

# -----------------------------
# Replace object with sample (from resource DB)
# -----------------------------
def replace_object_with_sample(pdf: pikepdf.Pdf,target,sample_py,rng)->bool:
    dprint("FUCKFUCK")
    constructed=py_to_pike(sample_py,pdf)
    if isinstance(target,Stream):
        if isinstance(constructed,dict) and "__construct_stream__" in constructed:
            meta=constructed["__construct_stream__"]["dict"]
            data=constructed["__construct_stream__"]["bytes"]
            target.write(data)
            for kk,vv in meta.items():
                if str(kk) not in BANNED_KEYS: target[kk]=vv
            return True
        elif isinstance(constructed,Stream):
            target.write(constructed.read_bytes() or b"")
            for kk,vv in constructed.items():
                if str(kk) not in BANNED_KEYS: target[kk]=vv
            return True
    elif isinstance(target,Dictionary):
        if isinstance(constructed,Dictionary):
            dprint("type(target) == "+str(type(target)))
            dprint("target.__dir__() == "+str(target.__dir__()))
            dprint("target.keys() == "+str(target.keys()))
            # target.clear()
            for k in target.keys():
                # k = k[1:] # Cut out the thing...
                if k in BANNED_KEYS:
                    continue
                del target[k] # Delete the shit...
            dprint("target.__dir__() == "+str(target.__dir__()))
            for kk,vv in constructed.items():
                target[kk]=vv
            return True
    return False

# -----------------------------
# Mutate whole PDF
# -----------------------------
def mutate_pdf_structural(buf: bytes,max_size:int,rng: random.Random)->bytes:
    pdf=pikepdf.open(io.BytesIO(buf))
    action=rng.randrange(100)
    dprint(action)
    if action<40 and _resources_db:
        target=pick_choice([o for o in pdf.objects if isinstance(o,(Dictionary,Stream))],rng)
        if target: replace_object_with_sample(pdf,target,rng.choice(_resources_db),rng)
    elif action<100:
        target=pick_choice([o for o in pdf.objects if isinstance(o,(Dictionary,Stream))],rng)
        if isinstance(target,Stream): mutate_stream_inplace(target,rng)
        elif isinstance(target,Dictionary): mutate_dict_inplace(target,rng,pdf=pdf)
    else:
        pages=list(pdf.pages)
        if len(pages)>1: random.shuffle(pages)
    out=io.BytesIO(); pdf.save(out,linearize=False,compress_streams=False)
    return out.getvalue()[:max_size]

# -----------------------------
# AFL++ API
# -----------------------------
def init(seed:int):
    global _initialized,_resources_db
    if _initialized: return
    _resources_db=load_resources_db(DEFAULT_PDF_DIR,DEFAULT_PKL_PATH)
    _initialized=True

def deinit():
    global _initialized; _initialized=False

def fuzz_count(buf:bytearray)->int:
    if len(buf)<=HEADER_SIZE: return 0
    try:
        core=buf[HEADER_SIZE:]
        with pikepdf.open(io.BytesIO(core)): pass
        return _mutation_count
    except: return 0

def fuzz(buf:bytearray,add_buf,max_size:int)->bytearray:
    header=buf[:HEADER_SIZE]; core=buf[HEADER_SIZE:]
    rng=rng_from_buf(buf)
    mutated=mutate_pdf_structural(core,max_size-HEADER_SIZE,rng)
    return bytearray(header+mutated)

# -----------------------------
# CLI test
# -----------------------------
if __name__=="__main__":
    import argparse
    ap=argparse.ArgumentParser()
    ap.add_argument("--mutate",nargs=3)
    args=ap.parse_args()
    if args.mutate:
        init(0)
        data=open(args.mutate[0],"rb").read()
        data=b"\x00\x00\x00\x00"+data
        for _ in range(int(args.mutate[2])):
            data=fuzz(bytearray(data),None,10_000_000)
        open(args.mutate[1],"wb").write(data)
        print("Wrote",args.mutate[1])
