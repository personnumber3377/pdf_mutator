#!/usr/bin/env python3
"""
mutator.py -- AFL++ Python custom mutator for PDF structural mutations.

Features:
 - Deterministic mutation decisions derived from the input bytes (no global RNG seeding).
 - Loads a corpus of resource-like dictionaries from a PDF directory or a cached resources.pkl.
 - Mutation action: replace an entire object (Stream or Dictionary) from the input PDF
   with a sampled resource-dictionary converted into pikepdf objects.
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

try:
    import pikepdf
    from pikepdf import Name, Dictionary, Array, Stream
except Exception as e:
    print("ERROR: pikepdf required. Install: pip3 install pikepdf", file=sys.stderr)
    raise

# -----------------------------
# Config
# -----------------------------
HEADER_SIZE = 4  # keep header bytes unchanged in mutated output
DEFAULT_MUTATION_COUNT = 1000
DEFAULT_PDF_DIR = Path(os.environ.get("MUTATOR_PDF_DIR", "./pdf_seed_corpus/"))
DEFAULT_PKL_PATH = Path(os.environ.get("MUTATOR_PKL_PATH", "./resources.pkl"))

_mutation_count = DEFAULT_MUTATION_COUNT
_initialized = False
_resources_db: List[Dict[str, Any]] = []  # list of python-serializable resource dict samples

# -----------------------------
# Utilities: convert pikepdf objects -> python-serializable repr and back
# -----------------------------
def pike_to_py(obj):
    """
    Convert pikepdf object to a Python-serializable structure.
    Supported: Name, Dictionary, Array, Stream (represented as dict), numbers, bool, bytes/str.
    """

    # Names -> string with leading '/'
    if isinstance(obj, Name):
        return {"__type__": "name", "value": str(obj)}  # e.g. "/F1"
    # Stream -> dict with 'stream_bytes' and 'dict' (metadata)
    if isinstance(obj, Stream):
        d = {}
        for k, v in obj.items():
            try:
                d[str(k)] = pike_to_py(v)
            except Exception:
                d[str(k)] = {"__type__": "unknown"}
        # attempt to read bytes
        try:
            raw = obj.read_bytes() or b""
        except Exception:
            raw = b""
        return {"__type__": "stream", "dict": d, "stream_bytes": bytes(raw)}
    # Dictionary -> map
    if isinstance(obj, Dictionary):
        out = {}
        for k, v in obj.items():
            try:
                out[str(k)] = pike_to_py(v)
            except Exception:
                out[str(k)] = {"__type__": "unknown"}
        return {"__type__": "dict", "value": out}
    # Array -> list
    if isinstance(obj, Array):
        lst = []
        for v in obj:
            try:
                lst.append(pike_to_py(v))
            except Exception:
                lst.append({"__type__": "unknown"})
        return {"__type__": "array", "value": lst}
    # primitives
    if isinstance(obj, (int, float, bool)):
        return {"__type__": "primitive", "value": obj}
    # bytes/str
    if isinstance(obj, bytes):
        return {"__type__": "bytes", "value": obj}
    if isinstance(obj, str):
        return {"__type__": "string", "value": obj}
    # fallback
    return {"__type__": "unknown", "repr": str(obj)}


def py_to_pike(pyobj, pdf=None):
    """
    Convert Python-serializable representation back to pikepdf objects.
    Returns pikepdf object (Name/Dictionary/Array/Stream/primitive).
    `pdf` is optional pikepdf.Pdf instance used as a factory for certain constructors.
    """
    if not isinstance(pyobj, dict) or "__type__" not in pyobj:
        # primitive raw value maybe
        if isinstance(pyobj, (int, float, bool)):
            return pyobj
        if isinstance(pyobj, bytes):
            return pyobj
        if isinstance(pyobj, str):
            return pyobj
        raise ValueError("pyobj missing type: %r" % (pyobj,))

    t = pyobj["__type__"]

    if t == "name":
        # value is string like "/F1" or "F1"
        v = pyobj.get("value", "")
        if isinstance(v, str):
            if not v.startswith("/"):
                v = "/" + v
            return Name(v)
        raise ValueError("Invalid name representation")

    if t == "primitive":
        return pyobj.get("value")

    if t == "bytes":
        return pyobj.get("value", b"")

    if t == "string":
        return pyobj.get("value", "")

    if t == "array":
        lst = pyobj.get("value", [])
        out = Array()
        for el in lst:
            out.append(py_to_pike(el, pdf=pdf))
        return out

    if t == "dict":
        d = pyobj.get("value", {})
        out = Dictionary()
        for k_str, v_py in d.items():
            # keys are strings like "/Font" or "Font"
            if k_str.startswith("/"):
                k = Name(k_str)
            else:
                k = Name("/" + k_str)
            try:
                out[k] = py_to_pike(v_py, pdf=pdf)
            except Exception as ex:
                # fail fast (user asked raise on failures)
                raise RuntimeError(f"Failed to convert dict value for key {k_str}: {ex}")
        return out

    if t == "stream":
        metadata = pyobj.get("dict", {})
        stream_bytes = pyobj.get("stream_bytes", b"")
        # convert metadata keys
        md = Dictionary()
        for k_str, v_py in metadata.items():
            if k_str.startswith("/"):
                k = Name(k_str)
            else:
                k = Name("/" + k_str)
            md[k] = py_to_pike(v_py, pdf=pdf)
        # construct a Stream using pikepdf.Stream(pdf, data, stream_dict)
        # If pdf is None we create a temporary one (pike requires owner for Stream)
        if pdf is None:
            with pikepdf.Pdf.new() as tmp:
                s = pikepdf.Stream(tmp, stream_bytes)
                # attach metadata
                for kk, vv in md.items():
                    s[kk] = vv
                # We return the stream but its owner lifetime is bounded; to avoid subtle issues
                # better to return a Dictionary representing the metadata plus bytes; the caller
                # can write a new stream on the target PDF. We'll return a tuple marker for the caller.
                return {"__construct_stream__": {"dict": md, "bytes": stream_bytes}}
        else:
            s = pikepdf.Stream(pdf, stream_bytes)
            for kk, vv in md.items():
                s[kk] = vv
            return s

    raise ValueError("Unsupported py -> pike type: " + t)


# -----------------------------
# Build / load resources DB
# -----------------------------
def extract_resource_samples_from_pdf(pdf_path: Path) -> List[Dict[str, Any]]:
    """
    Extract resource-like dictionaries from a single PDF file.
    We gather `page.Resources` dictionaries and also dictionary-like objects found in pdf.objects
    that look like resource containers (i.e., contain keys /Font, /XObject, /ColorSpace, /ProcSet, /ExtGState).
    Returns a list of python-serializable resource dicts.
    """
    samples = []
    try:
        with pikepdf.open(pdf_path) as pdf:
            # scan pages' /Resources
            for p in pdf.pages:
                try:
                    r = p.get("/Resources")
                    if r is None:
                        continue
                    py = pike_to_py(r)
                    samples.append(py)
                except Exception:
                    continue

            # scan top-level objects to find resource-like dictionaries
            for obj in pdf.objects:
                try:
                    if isinstance(obj, pikepdf.Dictionary):
                        keys = set(k.strip("/") for k in obj.keys())
                        indicator = {"Font", "XObject", "ColorSpace", "ProcSet", "ExtGState"}
                        if keys & indicator:
                            samples.append(pike_to_py(obj))
                    elif isinstance(obj, pikepdf.Stream):
                        # check its stream dict for indicators
                        sd = obj.stream_dict if hasattr(obj, "stream_dict") else obj
                        if sd is None:
                            continue
                        dkeys = set(k.strip("/") for k in sd.keys())
                        if dkeys & {"Font", "XObject", "ColorSpace", "ProcSet", "ExtGState"}:
                            samples.append(pike_to_py(sd))
                except Exception:
                    continue
    except Exception as e:
        # propagate upwards; caller may want to skip but we design to be robust here
        print(f"Warning: failed to open {pdf_path}: {e}", file=sys.stderr)
    return samples


def build_resources_db_from_dir(pdf_dir: Path, pkl_path: Path) -> List[Dict[str, Any]]:
    db: List[Dict[str, Any]] = []
    if not pdf_dir.exists() or not pdf_dir.is_dir():
        print(f"PDF dir {pdf_dir} not found; returning empty DB", file=sys.stderr)
        return db

    for p in sorted(pdf_dir.iterdir()):
        if not p.is_file() or p.suffix.lower() != ".pdf":
            continue
        try:
            samples = extract_resource_samples_from_pdf(p)
            if samples:
                db.extend(samples)
            # keep DB size reasonable
            if len(db) > 5000:
                break
        except Exception:
            continue

    # save pickle
    try:
        with open(pkl_path, "wb") as fh:
            pickle.dump(db, fh)
    except Exception as e:
        print(f"Warning: could not write resources pkl {pkl_path}: {e}", file=sys.stderr)
    return db


def load_resources_db(pdf_dir: Path, pkl_path: Path) -> List[Dict[str, Any]]:
    # prefer pickle if present and up-to-date relative to pdf_dir
    if pkl_path.exists():
        try:
            pkl_mtime = pkl_path.stat().st_mtime
            # if pdf_dir exists and any pdf is newer than pickle, rebuild
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
        except Exception as e:
            print(f"Warning: failed to load or validate {pkl_path}: {e}", file=sys.stderr)
    # otherwise build from pdf_dir
    db = build_resources_db_from_dir(pdf_dir, pkl_path)
    return db


# -----------------------------
# Deterministic RNG from input buffer
# -----------------------------
def rng_from_buf(buf: bytes) -> random.Random:
    """
    Create a deterministic RNG seeded from the input buffer bytes (excluding header).
    We use a stable hash of an initial slice to seed the RNG.
    """
    # use up to 64 bytes after header
    raw = buf[HEADER_SIZE:HEADER_SIZE + 64]
    if not raw:
        raw = buf[:HEADER_SIZE] or b"\x00"
    h = hashlib.sha256(raw).digest()
    seed_int = int.from_bytes(h[:8], "little")
    return random.Random(seed_int)


# -----------------------------
# Mutation strategies (structural)
# -----------------------------
def choose_target_object(pdf: pikepdf.Pdf, rng: random.Random):
    # collect candidate objects: Stream and Dictionary
    candidates = []
    for obj in pdf.objects:
        try:
            if isinstance(obj, (pikepdf.Stream, pikepdf.Dictionary)):
                candidates.append(obj)
        except Exception:
            continue
    if not candidates:
        return None
    return rng.choice(candidates)


def construct_pike_replacement(py_sample: Dict[str, Any], pdf: pikepdf.Pdf):
    """
    Convert a py sample (serializable dict) into a replacement object for the target PDF.
    The function returns either:
      - a pikepdf.Dictionary
      - a pikepdf.Stream (or a marker object {"__construct_stream__": {...}} if we couldn't build stream directly)
    """
    pike_obj = py_to_pike(py_sample, pdf=pdf)
    # If py_to_pike returned the special stream-construction marker, return that marker to the caller so the caller can
    # create a proper stream on the target pdf.
    if isinstance(pike_obj, dict) and "__construct_stream__" in pike_obj:
        return pike_obj
    return pike_obj


def replace_object_with_sample(pdf: pikepdf.Pdf, target_obj, sample_py, rng: random.Random):
    """
    Replace target_obj (Stream or Dictionary) inline in pdf with sample_py converted.
    We try to preserve /Length fields correctly for streams.
    On failure, raise an exception (no fallback).
    """
    if isinstance(target_obj, pikepdf.Stream):
        # convert sample to stream metadata + bytes
        constructed = construct_pike_replacement(sample_py, pdf)
        if isinstance(constructed, dict) and "__construct_stream__" in constructed:
            meta = constructed["__construct_stream__"]["dict"]
            data = constructed["__construct_stream__"]["bytes"]
            # Clear existing stream dict keys except /Length and replace
            keys = list(target_obj.keys())
            for k in keys:
                try:
                    if k != "/Length":
                        del target_obj[k]
                except Exception:
                    pass
            # write new bytes
            target_obj.write(data)
            # insert metadata
            for kk, vv in meta.items():
                target_obj[kk] = vv
            # fix Length
            target_obj["/Length"] = len(data)
            return True
        elif isinstance(constructed, pikepdf.Stream):
            # if we got a stream object from py_to_pike, rewrite target stream's bytes and dict
            data = constructed.read_bytes() or b""
            keys = list(target_obj.keys())
            for k in keys:
                try:
                    if k != "/Length":
                        del target_obj[k]
                except Exception:
                    pass
            target_obj.write(data)
            for kk, vv in constructed.items():
                target_obj[kk] = vv
            target_obj["/Length"] = len(data)
            return True
        elif isinstance(constructed, pikepdf.Dictionary):
            # create a new stream from the dictionary metadata but with empty bytes
            keys = list(target_obj.keys())
            for k in keys:
                try:
                    if k != "/Length":
                        del target_obj[k]
                except Exception:
                    pass
            # write zero-length stream (or small filler)
            data = b""
            target_obj.write(data)
            for kk, vv in constructed.items():
                target_obj[kk] = vv
            target_obj["/Length"] = 0
            return True
        else:
            raise RuntimeError("Unsupported constructed type for stream replacement: %r" % type(constructed))

    elif isinstance(target_obj, pikepdf.Dictionary):
        constructed = construct_pike_replacement(sample_py, pdf)
        if isinstance(constructed, pikepdf.Dictionary):
            # Clear dict and replace keys
            for k in list(target_obj.keys()):
                try:
                    del target_obj[k]
                except Exception:
                    pass
            for kk, vv in constructed.items():
                target_obj[kk] = vv
            return True
        elif isinstance(constructed, dict) and "__construct_stream__" in constructed:
            # replace a dictionary with a stream's dict (ok)
            for k in list(target_obj.keys()):
                try:
                    del target_obj[k]
                except Exception:
                    pass
            meta = constructed["__construct_stream__"]["dict"]
            for kk, vv in meta.items():
                target_obj[kk] = vv
            return True
        elif isinstance(constructed, pikepdf.Stream):
            # a stream can't be inserted as a dictionary; but we can copy its stream_dict keys into dict
            sdict = Dictionary()
            for kk, vv in constructed.items():
                sdict[kk] = vv
            for k in list(target_obj.keys()):
                try:
                    del target_obj[k]
                except Exception:
                    pass
            for kk, vv in sdict.items():
                target_obj[kk] = vv
            return True
        else:
            raise RuntimeError("Unsupported constructed type for dictionary replacement: %r" % type(constructed))
    else:
        raise RuntimeError("Unsupported target_obj type: %r" % type(target_obj))


# -----------------------------
# Mutate whole PDF bytes
# -----------------------------
def mutate_pdf_structural(buf: bytes, max_size: int, rng: random.Random) -> bytes:
    """
    Parse the PDF from buf (bytes), choose a target object and replace it using resources DB.
    Return mutated bytes (<= max_size).
    Raises on parse/convert errors instead of falling back silently.
    """
    # parse PDF bytes using pikepdf
    pdf_stream = io.BytesIO(buf)
    try:
        pdf = pikepdf.open(pdf_stream, allow_overwriting_input=True)
    except Exception as e:
        raise RuntimeError("pikepdf failed to open input: %s" % e)

    # choose a replacement sample
    if not _resources_db:
        raise RuntimeError("resources DB is empty; cannot perform structural mutation")

    # pick target
    target = choose_target_object(pdf, rng)
    if target is None:
        raise RuntimeError("no candidate objects found in PDF for replacement")

    sample_py = rng.choice(_resources_db)
    # attempt replacement
    ok = replace_object_with_sample(pdf, target, sample_py, rng)
    if not ok:
        raise RuntimeError("replacement did not succeed for unknown reason")

    # Save to bytes
    out_buf = io.BytesIO()
    # Try to avoid recompression to preserve what we set: pikepdf save options
    pdf.save(out_buf, linearize=False, compress_streams=False)
    data = out_buf.getvalue()
    if len(data) > max_size:
        # truncate
        data = data[:max_size]
    return data


# -----------------------------
# Generic fallback mutator (kept but NOT used as fallback per request)
# -----------------------------
def remove_substring(b: bytes) -> bytes:
    if len(b) < 2:
        return b
    start = random.randrange(len(b)-1)
    end = random.randrange(start+1, len(b))
    return b[:start] + b[end:]


def multiply_substring(b: bytes) -> bytes:
    if len(b) < 2:
        return b
    start = random.randrange(len(b)-1)
    end = random.randrange(start+1, len(b))
    substr = b[start:end]
    where = random.randrange(len(b))
    return b[:where] + substr * random.randint(1, 5) + b[where:]


def add_character(b: bytes) -> bytes:
    where = random.randrange(len(b)) if b else 0
    return b[:where] + bytes([random.randrange(256)]) + b[where:]


def mutate_generic(b: bytes) -> bytes:
    if not b:
        return bytes([random.randrange(256)])
    choice = random.randrange(3)
    if choice == 0:
        return remove_substring(b)
    elif choice == 1:
        return multiply_substring(b)
    else:
        return add_character(b)


# -----------------------------
# AFL++ API: init / deinit / fuzz_count / fuzz
# -----------------------------
def init(seed: int):
    """
    Called once by AFL at startup with a seed.
    We load resources DB and initialize any global structures.
    """
    global _initialized, _resources_db, _mutation_count

    if _initialized:
        return

    # set mutation count
    try:
        seed = int(seed)
    except Exception:
        seed = 0

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
    # nothing else to cleanup


def fuzz_count(buf: bytearray) -> int:
    """
    Return how many fuzz cycles to perform for this buffer.
    If the buffer cannot be parsed as a PDF (pikepdf), return 0 to skip mutating.
    """
    # make sure header length is present
    if not isinstance(buf, (bytes, bytearray)):
        return 0
    if len(buf) <= HEADER_SIZE:
        return 0
    # attempt to parse PDF (exclude header)
    try:
        core = bytes(buf[HEADER_SIZE:])
        with pikepdf.open(io.BytesIO(core)) as pdf:
            # may be large; only need to know open succeeded
            pass
        return _mutation_count
    except Exception:
        # invalid PDFs we don't attempt to mutate structurally
        return 0


def fuzz(buf: bytearray, add_buf, max_size: int) -> bytearray:
    """
    Perform a single mutation. buf is a bytes/bytearray input.
    We will preserve HEADER_SIZE bytes and mutate the rest.
    Returns a bytes-like (bytearray) mutated output.
    On failure, raises an exception (no fallback).
    """
    if not _initialized:
        raise RuntimeError("mutator not initialized; call init(seed) before fuzz()")

    if not isinstance(buf, (bytes, bytearray)):
        raise ValueError("buf must be bytes or bytearray")

    if len(buf) <= HEADER_SIZE:
        raise ValueError("buf too small (<= HEADER_SIZE)")

    header = bytes(buf[:HEADER_SIZE])
    core = bytes(buf[HEADER_SIZE:])

    # Build deterministic RNG from core bytes (so mutation decisions are derived from buf)
    rng = rng_from_buf(buf)

    # perform structural mutation; if anything fails we raise an exception
    mutated_core = mutate_pdf_structural(core, max_size - HEADER_SIZE, rng)

    # combine header back
    out = bytearray()
    out.extend(header)
    out.extend(mutated_core)
    # truncate to max_size if necessary
    if len(out) > max_size:
        out = out[:max_size]
    return out


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
    # add header if not present
    if len(data) <= HEADER_SIZE:
        data = (b"\x00" * HEADER_SIZE) + data
    else:
        # Prepend a 4-byte header for testing
        data = b"\x00\x00\x00\x00" + data

    for i in range(times):
        rng = rng_from_buf(data)
        mutated = fuzz(data, None, 10_000_000)
        data = bytes(mutated)
    with open(outfile, "wb") as fh:
        fh.write(data)
    print(f"Wrote mutated output to {outfile}")


if __name__ == "__main__":
    # small CLI front-end
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
        # ensure mutator init
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