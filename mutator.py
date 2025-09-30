#!/usr/bin/env python3
"""
mutator.py -- AFL++ Python custom mutator for PDF structural mutations.

Features:
 - Deterministic mutation decisions derived from the input bytes (no global RNG).
 - Loads a corpus of resource-like dictionaries from a PDF directory or a cached resources.pkl.
 - Mutation actions:
     * replace an entire object (Stream or Dictionary) with a sample from the resources DB
     * or mutate an object in-place (dictionary / stream) using type-aware modifications
     * or shuffle pages
 - Keeps a small header (HEADER_SIZE) unchanged.
 - Raises on conversion failures (no silent fallback to generic byte-level mutations).
 - Exposes AFL++ interface: init(seed), deinit(), fuzz_count(buf), fuzz(buf, add_buf, max_size).

Environment:
 - MUTATOR_PDF_DIR  : dir with sample PDFs to build resources DB (default ./pdf_seed_corpus/)
 - MUTATOR_PKL_PATH : path to pickle DB (default ./resources.pkl)
"""

import os
import io
import sys
import pickle
import hashlib
from pathlib import Path
from typing import Any, Dict, List, Tuple
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
# Config / Globals
# -----------------------------
HEADER_SIZE = 4  # keep header bytes unchanged in mutated output
DEFAULT_MUTATION_COUNT = 100
MAX_DB_SIZE = 30000
MAX_CALL_COUNT = 200000
BANNED_KEYS = set(["/Length", "/Kids"])  # Do not modify these on stream dicts
MAX_RECURSION = 8

DEFAULT_PDF_DIR = Path(os.environ.get("MUTATOR_PDF_DIR", "./pdf_seed_corpus/"))
DEFAULT_PKL_PATH = Path(os.environ.get("MUTATOR_PKL_PATH", "./resources.pkl"))

_mutation_count = DEFAULT_MUTATION_COUNT
_initialized = False
_resources_db: List[Dict[str, Any]] = []  # python-serializable resource dict samples
_call_counter = 0

# -----------------------------
# Type map (for guided dict edits)
# -----------------------------
DICT_TYPE_MAP = {
    "LW": "number", "LC": "int", "LJ": "int", "ML": "number",
    "D": "array", "RI": "name", "OP": "bool", "op": "bool",
    "OPM": "int", "Font": "array", "BG": "any", "BG2": "any",
    "UCR": "any", "UCR2": "any", "TR": "any", "TR2": "any",
    "FL": "number", "SM": "number", "SA": "bool",
    "BM": "name", "SMask": "dict", "CA": "number", "ca": "number",
    "AIS": "bool", "TK": "bool",
    "Frequency": "number", "Angle": "number", "SpotFunction": "any",
    "AccurateScreens": "bool", "HalftoneType": "int",
    "Width": "int", "Height": "int", "Width2": "int", "Height2": "int",
    "Xsquare": "int", "Ysquare": "int",
    "FontDescriptor": "dict", "BaseFont": "name", "DW": "number",
    "DW2": "array", "W": "array", "W2": "array", "CIDToGIDMap": "any",
    "CIDSystemInfo": "dict", "Registry": "string", "Ordering": "string",
    "Supplement": "int", "Flags": "int", "FontBBox": "array",
    "FontMatrix": "array", "Encoding": "any", "ToUnicode": "any",
    "FontName": "name", "StemV": "int", "XHeight": "int", "CapHeight": "int",
    "Ascent": "int", "Descent": "int", "AvgWidth": "int", "MaxWidth": "int",
    "ItalicAngle": "number", "Leading": "int", "MissingWidth": "int",
    "DecodeParms": "dict", "Filter": "name", "SMaskInData": "int",
    "Interpolate": "bool", "ImageMask": "bool",
    "MediaBox": "array", "CropBox": "array", "Rotate": "int",
    "UserUnit": "number", "Resources": "dict", "Annots": "array",
    "FunctionType": "int", "Order": "int", "BitsPerSample": "int",
    "Functions": "array", "Size": "int", "Index": "array", "Prev": "int",
    "Producer": "string", "Creator": "string", "Author": "string",
    "Title": "string", "Subject": "string", "Keywords": "string",
}

# -----------------------------
# Utilities: convert pikepdf objects -> python-serializable repr and back
# -----------------------------
def pike_to_py(obj: Any, depth: int = 0) -> Dict[str, Any]:
    """
    Convert pikepdf object to a Python-serializable structure.
    Supported: Name, Dictionary, Array, Stream (represented as dict), numbers, bool, bytes/str.
    """
    global _call_counter
    _call_counter += 1
    if _call_counter > MAX_CALL_COUNT:
        raise RuntimeError("conversion call limit exceeded")

    if isinstance(obj, Name):
        return {"__type__": "name", "value": str(obj)}  # e.g. "/F1"

    if isinstance(obj, Stream):
        d = {}
        try:
            for k, v in obj.items():
                # avoid deep recursion
                if depth >= MAX_RECURSION:
                    d[str(k)] = {"__type__": "unknown"}
                else:
                    d[str(k)] = pike_to_py(v, depth=depth+1)
        except Exception:
            pass
        # attempt to read bytes
        try:
            raw = obj.read_bytes() or b""
        except Exception:
            raw = b""
        return {"__type__": "stream", "dict": d, "stream_bytes": bytes(raw)}

    if isinstance(obj, Dictionary):
        out = {}
        if depth >= MAX_RECURSION:
            return {"__type__": "dict", "value": out}
        for k, v in obj.items():
            try:
                out[str(k)] = pike_to_py(v, depth=depth+1)
            except Exception as e:
                raise(e)
                out[str(k)] = {"__type__": "unknown"}
        return {"__type__": "dict", "value": out}

    if isinstance(obj, Array):
        lst = []
        for v in obj:
            try:
                lst.append(pike_to_py(v, depth=depth+1))
            except Exception as e:
                raise(e)
                lst.append({"__type__": "unknown"})
        return {"__type__": "array", "value": lst}

    if isinstance(obj, (int, float, bool, decimal.Decimal)): # Also check for decimal stuff...
        return {"__type__": "primitive", "value": obj}

    if isinstance(obj, bytes):
        return {"__type__": "bytes", "value": obj}

    if isinstance(obj, str):
        return {"__type__": "string", "value": obj}
    assert False
    # print("This here is unknown stuff: "+str(obj))
    # print("type of the thing: "+str(type(obj)))
    # return {"__type__": "unknown", "repr": str(obj)}


def py_to_pike(pyobj: Any, pdf: pikepdf.Pdf = None) -> Any:
    """
    Convert Python-serializable representation back to pikepdf objects.
    Returns pikepdf object (Name/Dictionary/Array/Stream/primitive) or special marker for stream construction.
    """
    if not isinstance(pyobj, dict) or "__type__" not in pyobj:
        # allow raw primitives
        if isinstance(pyobj, (int, float, bool)):
            return pyobj
        if isinstance(pyobj, bytes):
            return pyobj
        if isinstance(pyobj, str):
            return pyobj
        raise ValueError("pyobj missing type: %r" % (pyobj,))

    t = pyobj["__type__"]

    if t in ("name"):
        v = pyobj.get("value", "")
        if not isinstance(v, str):
            v = str(v)
        if not v.startswith("/"):
            v = "/" + v
        # if len(v) == 1:
        #     v = v + "A"
        return Name(v)

    if t == "primitive":
        return pyobj.get("value")

    if t == "bytes":
        return pyobj.get("value", b"")

    if t == "string":
        return pyobj.get("value", "")

    if t == "array":
        out = Array()
        for el in pyobj.get("value", []):
            out.append(py_to_pike(el, pdf=pdf))
        return out

    if t == "dict":
        d = pyobj.get("value", {})
        out = Dictionary()
        for k_str, v_py in d.items():
            if k_str.startswith("/"):
                key_name = k_str
            else:
                key_name = "/" + k_str
            k = Name(key_name)
            out[k] = py_to_pike(v_py, pdf=pdf)
        return out

    if t == "stream":
        metadata = pyobj.get("dict", {})
        stream_bytes = pyobj.get("stream_bytes", b"")
        md = Dictionary()
        for k_str, v_py in metadata.items():
            key_name = k_str if k_str.startswith("/") else "/" + k_str
            md[Name(key_name)] = py_to_pike(v_py, pdf=pdf)
        # pikepdf requires a Pdf owner to create Stream objects cleanly.
        # If we can't create a pike Stream (pdf is None) we return a special marker for caller to construct.
        if pdf is None:
            return {"__construct_stream__": {"dict": md, "bytes": stream_bytes}}
        s = pikepdf.Stream(pdf, stream_bytes)
        for kk, vv in md.items():
            kk_str = str(kk)
            if kk_str in BANNED_KEYS:
                continue
            s[kk] = vv
        return s

    raise ValueError("Unsupported py -> pike type: " + t)


# -----------------------------
# Build / load resources DB
# -----------------------------
'''
def extract_resource_samples_from_pdf(pdf_path: Path) -> List[Dict[str, Any]]:
    """
    Extract resource-like dictionaries from a single PDF file.
    Returns list of Python-serializable samples.
    """
    samples = []
    try:
        with pikepdf.open(pdf_path) as pdf:
            # pages' /Resources
            for p in pdf.pages:
                try:
                    r = p.get("/Resources")
                    if r:
                        samples.append(pike_to_py(r))
                except Exception:
                    pass
            # scan top-level objects for resource-like dicts
            for obj in pdf.objects:
                try:
                    if isinstance(obj, pikepdf.Dictionary):
                        keys = set(k.strip("/") for k in obj.keys())
                        indicator = {"Font", "XObject", "ColorSpace", "ProcSet", "ExtGState"}
                        if keys & indicator:
                            samples.append(pike_to_py(obj))
                    elif isinstance(obj, pikepdf.Stream):
                        sd = obj.stream_dict if hasattr(obj, "stream_dict") else obj
                        if sd is None:
                            continue
                        dkeys = set(k.strip("/") for k in sd.keys())
                        if dkeys & {"Font", "XObject", "ColorSpace", "ProcSet", "ExtGState"}:
                            samples.append(pike_to_py(sd))
                except Exception:
                    pass
    except Exception as e:
        print(f"Warning: failed to open {pdf_path}: {e}", file=sys.stderr)
    return samples
'''

def extract_resource_samples_from_pdf(pdf_path: Path) -> List[Dict[str, Any]]:
    """
    Extract arbitrary objects from a PDF file.
    Not limited to resources; captures any Dictionary, Array, or Stream.
    """
    samples = []
    try:
        with pikepdf.open(pdf_path) as pdf:
            # always try page resources first (still useful)
            for p in pdf.pages:
                try:
                    r = p.get("/Resources")
                    if r:
                        samples.append(pike_to_py(r))
                except Exception:
                    pass

            # now grab arbitrary objects
            for obj in pdf.objects:
                try:
                    if isinstance(obj, (pikepdf.Dictionary, pikepdf.Array, pikepdf.Stream)):
                        samples.append(pike_to_py(obj))
                except Exception:
                    continue
    except Exception as e:
        print(f"Warning: failed to open {pdf_path}: {e}", file=sys.stderr)
    return samples

# def obj_to_dict(obj) -> dict: # Convert object to dictionary...


def is_critical_object(obj, pdf) -> bool:
    try:
        # Catalog (Root is the Catalog in PDFs)
        if "/Type" in obj and str(obj["/Type"]) == "/Catalog":
            return True
        if "/Type" in obj and str(obj["/Type"]) == "/Pages":
            # print("stuff")
            # print(obj)
            # print(obj["/Kids"])
            return True
        if "/Kids" in obj:
            return True
        # Root dictionary
        if obj == pdf.root:
            return True
        # Pages dictionary
        if "/Pages" in pdf.root and obj == pdf.root["/Pages"]:
            return True
    except Exception:
        return False
    return False

def build_resources_db_from_dir(pdf_dir: Path, pkl_path: Path) -> List[Dict[str, Any]]:
    db: List[Dict[str, Any]] = []
    if not pdf_dir.exists() or not pdf_dir.is_dir():
        print(f"PDF dir {pdf_dir} not found; returning empty DB", file=sys.stderr)
        return db

    for p in sorted(pdf_dir.iterdir()):
        if not p.is_file() or p.suffix.lower() != ".pdf":
            continue
        try:
            print(p.name)
            samples = extract_resource_samples_from_pdf(p)
            if samples:
                db.extend(samples)
            if len(db) >= MAX_DB_SIZE:
                break
        except Exception:
            pass

    try:
        with open(pkl_path, "wb") as fh:
            pickle.dump(db[:MAX_DB_SIZE], fh)
    except Exception as e:
        print(f"Warning: could not write resources pkl {pkl_path}: {e}", file=sys.stderr)
    return db[:MAX_DB_SIZE]


def load_resources_db(pdf_dir: Path, pkl_path: Path) -> List[Dict[str, Any]]:
    # prefer pickle if present and up-to-date relative to pdf_dir
    if pkl_path.exists():
        try:
            pkl_mtime = pkl_path.stat().st_mtime
            rebuild = False
            if pdf_dir.exists() and pdf_dir.is_dir():
                for p in pdf_dir.iterdir():
                    if p.suffix.lower() == ".pdf" and p.stat().st_mtime > pkl_mtime:
                        rebuild = True
                        break
            if not rebuild:
                with open(pkl_path, "rb") as fh:
                    db = pickle.load(fh)
                    if isinstance(db, list):
                        return db
        except Exception:
            pass
    return build_resources_db_from_dir(pdf_dir, pkl_path)


# -----------------------------
# Deterministic RNG from input buffer
# -----------------------------
def rng_from_buf(buf: bytes) -> random.Random:
    """
    Create a deterministic RNG seeded from the input buffer bytes (excluding header).
    Use a stable hash of a slice to seed the RNG.
    """
    # raw = buf[HEADER_SIZE:HEADER_SIZE + 128]
    # if not raw:
    #     raw = buf[:HEADER_SIZE] or b"\x00"
    # h = hashlib.sha256(raw).digest()
    # seed_int = int.from_bytes(h[:8], "little")
    # seed_thing = random.randrange(1,1000)
    # print("seed: "+str(seed_thing))
    return random.Random(random.randrange(1,10000000)) # random.Random(len(buf)) # random.Random(seed_int) # random.Random(seed_thing) # random.Random(random.randrange(1000000)) # random.Random(seed_int)


# -----------------------------
# Mutation helpers (deterministic with provided rng)
# -----------------------------
def pick_choice(seq, rng: random.Random):
    if not seq:
        return None
    return seq[rng.randrange(len(seq))]

def collect_named_objects(pdf) -> List[Name]:
    """
    Collect all Name keys that look like indirect references or valid names
    inside the current PDF. Used to generate replacements instead of nonsense.
    """
    names = []
    try:
        for obj in pdf.objects:
            if isinstance(obj, Dictionary):
                for k, v in obj.items():
                    if isinstance(v, Name):
                        names.append(v)
            elif isinstance(obj, Array):
                for v in obj:
                    if isinstance(v, Name):
                        names.append(v)
    except Exception:
        pass
    # fallback if nothing found
    if not names:
        names = [Name("/Fallback")]
    return names


def mutate_dict_inplace(obj: Dictionary, rng: random.Random, depth: int = 0, pdf=None):
    """
    Mutate a pikepdf.Dictionary in-place using type-aware operations.
    Uses `rng` for all randomness.
    If pdf is passed, uses it to pick valid object/name references.
    """
    if not isinstance(obj, Dictionary) or not obj.keys():
        # assert False
        return False
    keys = list(obj.keys())
    key = pick_choice(keys, rng)
    if key is None:
        return False
    expected = DICT_TYPE_MAP.get(str(key).lstrip("/"), "any")

    try:
        val = obj[key]
        # int
        if expected == "int" and isinstance(val, int):
            obj[key] = val + rng.randint(-2000, 2000)

        elif expected == "number" and isinstance(val, (int, float)):
            factor = 1.0 + (rng.random() - 0.5) * 2.0
            obj[key] = float(val) * factor

        elif expected == "array" and isinstance(val, Array):
            if len(val) > 0 and isinstance(val[0], int):
                idx = rng.randrange(len(val))
                val[idx] = val[idx] + rng.randint(-500, 500)
            else:
                val.append(rng.randint(-1000, 1000))

        elif expected == "name":
            if pdf is not None:
                # replace with a real name from the PDF
                valid_names = collect_named_objects(pdf)
                obj[key] = rng.choice(valid_names)
            else:
                obj[key] = Name("/Alt" + str(rng.randint(0, 99999)))

        elif expected == "bool":
            obj[key] = not bool(val)

        elif expected == "string":
            s = "".join(chr(32 + (rng.randrange(95))) for _ in range(rng.randint(1, 12)))
            obj[key] = s

        elif expected == "dict" and isinstance(val, Dictionary) and depth < MAX_RECURSION:
            mutate_dict_inplace(val, rng, depth + 1, pdf=pdf)

        elif expected == "stream" and isinstance(val, Stream):
            mutate_stream_inplace(val, rng)

        else:
            # fallback: reference an existing name instead of nonsense
            if pdf is not None:
                obj[key] = rng.choice(collect_named_objects(pdf))
            else:
                obj[key] = Name("/Alt" + str(rng.randint(0, 99999)))

    except Exception:
        return False

    # occasionally add/remove entries
    if rng.random() < 0.12:
        if pdf is not None:
            # add a valid-looking key
            new_key = rng.choice(collect_named_objects(pdf))
            obj[new_key] = rng.randint(-10000, 10000)
        else:
            new_key = Name("/MutExtra" + str(rng.randint(0, 99999)))
            obj[new_key] = rng.randint(-10000, 10000)

    if rng.random() < 0.06 and obj.keys():
        kdel = pick_choice(list(obj.keys()), rng)
        try:
            if kdel is not None:
                del obj[kdel]
        except Exception:
            pass

    return True

def mutate_stream_inplace(stream: Stream, rng: random.Random):
    """
    Mutate stream bytes in-place (read-modify-write) using rng.
    """
    try:
        # print(stream.__dir__())
        data = bytearray(stream.read_bytes() or b"")
    except Exception as e:
        if "unfilterable" in str(e):
            data = bytearray(stream.read_raw_bytes() or b"")
        else:
            # print("Fuck!!!!")
            raise(e)
            return False
    if not data:
        # insert small content
        data = bytearray(b'\x00')
    choice = rng.randrange(4)
    if choice == 0:
        pos = rng.randrange(len(data))
        data[pos] ^= 0xFF
    elif choice == 1:
        pos = rng.randrange(len(data))
        data.insert(pos, rng.randrange(256))
    elif choice == 2:
        start = rng.randrange(len(data))
        end = min(len(data), start + rng.randint(1, min(16, len(data))))
        del data[start:end]
    else:
        # duplicate a small slice
        if len(data) >= 2:
            start = rng.randrange(len(data)-1)
            end = start + rng.randint(1, min(8, len(data)-start))
            slicev = data[start:end]
            where = rng.randrange(len(data))
            data = data[:where] + slicev + data[where:]
    try:
        stream.write(bytes(data))
        return True
    except Exception as e:
        raise(e)
        return False


def choose_target_object(pdf: pikepdf.Pdf, rng: random.Random):
    candidates = []
    for obj in pdf.objects:
        try:
            if isinstance(obj, (pikepdf.Stream, pikepdf.Dictionary)) and not is_critical_object(obj, pdf):
                candidates.append(obj)
        except Exception:
            continue
    if not candidates:
        return None
    return rng.choice(candidates)


def construct_pike_replacement(py_sample: Dict[str, Any], pdf: pikepdf.Pdf):
    """
    Convert py sample to pike object (or stream-construction marker).
    """
    return py_to_pike(py_sample, pdf=pdf)


def replace_object_with_sample(pdf: pikepdf.Pdf, target_obj, sample_py, rng: random.Random):
    """
    Replace target_obj inline in pdf with sample_py converted.
    Returns True on success. Raises on unsupported cases.
    """
    constructed = construct_pike_replacement(sample_py, pdf)

    # Helper to clear dictionary keys safely
    def clear_dict(d):
        for k in list(d.keys()):
            try:
                del d[k]
            except Exception:
                pass

    # Stream target
    if isinstance(target_obj, pikepdf.Stream):
        if isinstance(constructed, dict) and "__construct_stream__" in constructed:
            meta = constructed["__construct_stream__"]["dict"]
            data = constructed["__construct_stream__"]["bytes"]
            # remove all metadata except banned keys
            for k in list(target_obj.keys()):
                try:
                    if str(k) not in BANNED_KEYS:
                        del target_obj[k]
                except Exception:
                    pass
            # write new bytes and metadata
            target_obj.write(data)
            for kk, vv in meta.items():
                # kk is a Name object in the marker; ensure no banned keys
                kk_str = str(kk) if not isinstance(kk, str) else kk
                if kk_str in BANNED_KEYS:
                    continue
                try:
                    # if vv is a pike object already or py-serializable
                    target_obj[Name(kk_str if kk_str.startswith("/") else "/" + kk_str)] = vv
                except Exception:
                    try:
                        target_obj[Name(kk_str if kk_str.startswith("/") else "/" + kk_str)] = py_to_pike(vv, pdf=pdf)
                    except Exception:
                        pass
            return True
        elif isinstance(constructed, pikepdf.Stream):
            # rewrite bytes and copy allowed metadata
            data = constructed.read_bytes() or b""
            for k in list(target_obj.keys()):
                try:
                    if str(k) not in BANNED_KEYS:
                        del target_obj[k]
                except Exception:
                    pass
            target_obj.write(data)
            for kk, vv in constructed.items():
                kk_str = str(kk)
                if kk_str in BANNED_KEYS:
                    continue
                try:
                    target_obj[kk] = vv
                except Exception:
                    try:
                        target_obj[kk] = py_to_pike(pike_to_py(vv), pdf=pdf)
                    except Exception:
                        pass
            return True
        elif isinstance(constructed, pikepdf.Dictionary):
            # convert dictionary to stream's metadata with empty bytes
            for k in list(target_obj.keys()):
                try:
                    if str(k) not in BANNED_KEYS:
                        del target_obj[k]
                except Exception:
                    pass
            target_obj.write(b"")
            for kk, vv in constructed.items():
                kk_str = str(kk)
                if kk_str in BANNED_KEYS:
                    continue
                try:
                    target_obj[kk] = vv
                except Exception:
                    pass
            return True
        else:
            raise RuntimeError("Unsupported constructed type for stream replacement: %r" % type(constructed))

    # Dictionary target
    elif isinstance(target_obj, pikepdf.Dictionary):
        if isinstance(constructed, pikepdf.Dictionary):
            clear_dict(target_obj)
            for kk, vv in constructed.items():
                try:
                    target_obj[kk] = vv
                except Exception:
                    try:
                        target_obj[kk] = py_to_pike(pike_to_py(vv), pdf=pdf)
                    except Exception:
                        pass
            return True
        elif isinstance(constructed, dict) and "__construct_stream__" in constructed:
            clear_dict(target_obj)
            meta = constructed["__construct_stream__"]["dict"]
            for kk, vv in meta.items():
                kk_str = str(kk) if not isinstance(kk, str) else kk
                kname = Name(kk_str if kk_str.startswith("/") else "/" + kk_str)
                try:
                    target_obj[kname] = vv
                except Exception:
                    try:
                        target_obj[kname] = py_to_pike(vv, pdf=pdf)
                    except Exception:
                        pass
            return True
        elif isinstance(constructed, pikepdf.Stream):
            # copy stream's stream_dict entries into dict
            clear_dict(target_obj)
            for kk, vv in constructed.items():
                try:
                    target_obj[kk] = vv
                except Exception:
                    pass
            return True
        else:
            raise RuntimeError("Unsupported constructed type for dict replacement: %r" % type(constructed))

    else:
        raise RuntimeError("Unsupported target_obj type: %r" % type(target_obj))


# -----------------------------
# Mutate whole PDF bytes (combining replacement + in-place edits)
# -----------------------------
def mutate_pdf_structural(buf: bytes, max_size: int, rng: random.Random) -> bytes:
    """
    Parse the PDF, choose a target object and perform:
      - replacement (sample from resources DB) OR
      - in-place mutation of object (dict/stream) OR
      - shuffle pages
    Decisions are deterministic from rng.
    Raises on parse/convert errors (no silent fallback).
    """
    try:
        pdf = pikepdf.open(io.BytesIO(buf))
    except Exception as e:
        raise RuntimeError("pikepdf failed to open input: %s" % e)

    if not _resources_db:
        raise RuntimeError("empty resources DB")

    # Decide action: weights
    # 0-49 => replace object (50%)
    # 50-79 => mutate object in-place (30%)
    # 80-99 => shuffle/structural (20%)
    action_roll = rng.randrange(100)

    # Replacement path
    if action_roll < 50:
        target = choose_target_object(pdf, rng)
        if target is None:
            raise RuntimeError("no candidate objects found for replacement")
        sample_py = rng.choice(_resources_db)
        ok = replace_object_with_sample(pdf, target, sample_py, rng)
        if not ok:
            raise RuntimeError("replacement failed")
    # In-place mutation path
    elif action_roll < 100:
        target = choose_target_object(pdf, rng)
        if target is None:
            raise RuntimeError("no candidate objects found for in-place mutation")
        if isinstance(target, pikepdf.Stream):
            ok = mutate_stream_inplace(target, rng)
            if not ok:
                raise RuntimeError("stream mutate failed")
        elif isinstance(target, pikepdf.Dictionary):
            ok = False
            count = 10
            for i in range(count):
                ok = mutate_dict_inplace(target, rng, pdf=pdf)
                if ok:
                    break
            # if not ok:
            #     raise RuntimeError("dict mutate failed")
        else:
            raise RuntimeError("unsupported target for inplace mutation")
    # Structural / page operations
    else:
        # shuffle pages occasionally
        pages = list(pdf.pages)
        if len(pages) > 1:
            # deterministic shuffle by rng
            perm = list(range(len(pages)))
            # perform a small number of swaps depending on rng
            swap_count = 1 + (rng.randrange(min(5, len(pages))))
            for _ in range(swap_count):
                i = rng.randrange(len(pages))
                j = rng.randrange(len(pages))
                perm[i], perm[j] = perm[j], perm[i]
            # apply permutation
            new_pages = [pages[i] for i in perm]
            # pdf.pages.clear()
            for p in new_pages:
                pdf.pages.append(p)
        else:
            # fallback structural edit: replace resources object if present
            for obj in pdf.objects:
                try:
                    if isinstance(obj, pikepdf.Dictionary) and (set(k.strip("/") for k in obj.keys()) & {"Font", "XObject"}):
                        sample_py = rng.choice(_resources_db)
                        replace_object_with_sample(pdf, obj, sample_py, rng)
                        break
                except Exception:
                    pass

    # Save mutated PDF to bytes
    out_buf = io.BytesIO()
    try:
        pdf.save(out_buf, linearize=False, compress_streams=False)
    except Exception as e:
        raise RuntimeError("pikepdf.save failed: %s" % e)
    data = out_buf.getvalue()
    if len(data) > max_size:
        data = data[:max_size]
    return data


# -----------------------------
# Generic fallback mutator (kept but NOT used as fallback per request)
# -----------------------------
def remove_substring(b: bytes, rng: random.Random) -> bytes:
    if len(b) < 2:
        return b
    start = rng.randrange(len(b)-1)
    end = rng.randrange(start+1, len(b))
    return b[:start] + b[end:]


def multiply_substring(b: bytes, rng: random.Random) -> bytes:
    if len(b) < 2:
        return b
    start = rng.randrange(len(b)-1)
    end = rng.randrange(start+1, len(b))
    substr = b[start:end]
    where = rng.randrange(len(b))
    return b[:where] + substr * (1 + rng.randrange(4)) + b[where:]


def add_character(b: bytes, rng: random.Random) -> bytes:
    where = rng.randrange(len(b)) if b else 0
    return b[:where] + bytes([rng.randrange(256)]) + b[where:]


def mutate_generic(b: bytes, rng: random.Random) -> bytes:
    if not b:
        return bytes([rng.randrange(256)])
    choice = rng.randrange(3)
    if choice == 0:
        return remove_substring(b, rng)
    elif choice == 1:
        return multiply_substring(b, rng)
    else:
        return add_character(b, rng)


# -----------------------------
# AFL++ API: init / deinit / fuzz_count / fuzz
# -----------------------------
def init(seed: int):
    """
    Called once by AFL at startup with a seed.
    We load resources DB but do NOT use the provided seed for per-input mutation randomness.
    """
    global _initialized, _resources_db, _mutation_count

    if _initialized:
        return

    # Load resources DB from pickle or PDF dir
    try:
        _resources_db = load_resources_db(DEFAULT_PDF_DIR, DEFAULT_PKL_PATH)
    except Exception as e:
        print("Warning: load_resources_db failed: %s" % e, file=sys.stderr)
        _resources_db = []

    _initialized = True
    return


def deinit():
    global _initialized
    _initialized = False


def fuzz_count(buf: bytearray) -> int:
    """
    Return how many fuzz cycles to perform for this buffer.
    If the buffer cannot be parsed as a PDF (pikepdf), return 0 to skip mutating.
    """
    if not isinstance(buf, (bytes, bytearray)):
        return 0
    if len(buf) <= HEADER_SIZE:
        return 0
    # attempt to parse PDF (exclude header)
    try:
        core = bytes(buf[HEADER_SIZE:])
        with pikepdf.open(io.BytesIO(core)) as pdf:
            # open succeeded; schedule mutations
            return _mutation_count
    except Exception:
        # invalid PDFs we don't attempt to mutate structurally
        return 0


def fuzz(buf: bytearray, add_buf, max_size: int) -> bytearray:
    """
    Perform a single mutation. buf is bytes/bytearray input.
    Preserve HEADER_SIZE bytes and mutate the rest.
    Raises on structural failure (no silent fallback).
    """

    try:

        if not _initialized:
            raise RuntimeError("mutator not initialized; call init(seed) before fuzz()")

        if not isinstance(buf, (bytes, bytearray)):
            raise ValueError("buf must be bytes or bytearray")

        if len(buf) <= HEADER_SIZE:
            raise ValueError("buf too small (<= HEADER_SIZE)")

        header = bytes(buf[:HEADER_SIZE])
        core = bytes(buf[HEADER_SIZE:])

        rng = rng_from_buf(bytes(buf))  # deterministic RNG from buffer

        mutated_core = mutate_pdf_structural(core, max_size - HEADER_SIZE, rng)
        out = bytearray()
        out.extend(header)
        out.extend(mutated_core)
        if len(out) > max_size:
            out = out[:max_size]
        return out
    except Exception as e:
        print(e)
        return buf



# -----------------------------
# CLI helpers for maintenance (build pkl / test)
# -----------------------------
def cli_build_db(pdf_dir: str = None, pkl_path: str = None):
    pdf_dir = Path(pdf_dir or DEFAULT_PDF_DIR)
    pkl_path = Path(pkl_path or DEFAULT_PKL_PATH)
    db = build_resources_db_from_dir(pdf_dir, pkl_path)
    print(f"Built DB with {len(db)} samples; saved to {pkl_path}")


def cli_mutate_file(infile: str, outfile: str, times: int = 1):
    """
    Quick test: mutate a PDF file deterministically using its own bytes as seed.
    """
    with open(infile, "rb") as fh:
        data = fh.read()
    if len(data) <= HEADER_SIZE:
        data = (b"\x00" * HEADER_SIZE) + data
    else:
        data = b"\x00\x00\x00\x00" + data

    for i in range(times):
        mutated = fuzz(bytearray(data), None, 10_000_000)
        data = bytes(mutated)
        # with open(f"{outfile}.{i}", "wb") as fh:
        #     fh.write(data)
    with open(outfile, "wb") as fh:
        fh.write(data)
    print(f"Wrote mutated output to {outfile}")


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Mutator maintenance / testing")
    ap.add_argument("--build-db", action="store_true", help="Build resources.pkl from MUTATOR_PDF_DIR")
    ap.add_argument("--pdf-dir", default=str(DEFAULT_PDF_DIR))
    ap.add_argument("--pkl-path", default=str(DEFAULT_PKL_PATH))
    ap.add_argument("--mutate", nargs=2, metavar=("IN", "OUT"), help="Mutate IN -> OUT (single pass)")
    ap.add_argument("--mutate-iter", nargs=3, metavar=("IN", "OUT", "N"), help="Mutate IN repeatedly N times")
    args = ap.parse_args()

    if args.build_db:
        cli_build_db(args.pdf_dir, args.pkl_path)
        sys.exit(0)

    if args.mutate:
        infile, outfile = args.mutate
        init(0)
        try:
            cli_mutate_file(infile, outfile, times=1)
        except Exception as e:
            print("Mutation error: " + str(e))
            traceback.print_exc()
        sys.exit(0)

    if args.mutate_iter:
        infile, outfile, n = args.mutate_iter
        n = int(n)
        init(0)
        try:
            cli_mutate_file(infile, outfile, times=n)
        except Exception as e:
            print("Mutation error: " + str(e))
            traceback.print_exc()
        sys.exit(0)

    print("No action specified. This script is the AFL++ custom mutator module.")
