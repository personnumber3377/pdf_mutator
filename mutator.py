#!/usr/bin/env python3
"""
Custom PDF mutator for fuzzing.
Implements AFL++ Python custom mutator interface: init, deinit, fuzz_count, fuzz.
"""

import random
import io
import sys
import os
import copy

import pikepdf
from pikepdf import Name, Stream, Dictionary, Array

# -----------------------------
# Global state
# -----------------------------
_initialized = False
_mutation_count = 1000   # fuzz cycles per input

HEADER_SIZE = 4 # How many bytes is our fuzzing header???

# -----------------------------
# Expanded type map
# -----------------------------
DICT_TYPE_MAP = {
    # Graphics state
    "LW": "number", "LC": "int", "LJ": "int", "ML": "number",
    "D": "array", "RI": "name", "OP": "bool", "op": "bool",
    "OPM": "int", "Font": "array", "BG": "any", "BG2": "any",
    "UCR": "any", "UCR2": "any", "TR": "any", "TR2": "any",
    "FL": "number", "SM": "number", "SA": "bool",
    "BM": "name", "SMask": "dict", "CA": "number", "ca": "number",
    "AIS": "bool", "TK": "bool",

    # Halftone
    "Frequency": "number", "Angle": "number", "SpotFunction": "any",
    "AccurateScreens": "bool", "HalftoneType": "int",
    "Width": "int", "Height": "int", "Width2": "int", "Height2": "int",
    "Xsquare": "int", "Ysquare": "int",

    # Fonts
    "FontDescriptor": "dict", "BaseFont": "name", "DW": "number",
    "DW2": "array", "W": "array", "W2": "array", "CIDToGIDMap": "any",
    "CIDSystemInfo": "dict", "Registry": "string", "Ordering": "string",
    "Supplement": "int", "Flags": "int", "FontBBox": "array",
    "FontMatrix": "array", "Encoding": "any", "ToUnicode": "any",
    "FontName": "name", "StemV": "int", "XHeight": "int", "CapHeight": "int",
    "Ascent": "int", "Descent": "int", "AvgWidth": "int", "MaxWidth": "int",
    "ItalicAngle": "number", "Leading": "int", "MissingWidth": "int",

    # Images
    "Width": "int", "Height": "int", "BitsPerComponent": "int",
    "ColorSpace": "name", "DecodeParms": "dict", "Filter": "name",
    "SMaskInData": "int", "Interpolate": "bool", "ImageMask": "bool",
    "Intent": "name", "Mask": "any", "Alternates": "any", "Name": "name",

    # Pages
    "MediaBox": "array", "CropBox": "array", "ArtBox": "array",
    "BleedBox": "array", "TrimBox": "array", "Rotate": "int",
    "UserUnit": "number", "Resources": "dict", "Annots": "array",
    "Group": "dict",

    # Security / Encryption
    "Encrypt": "dict", "Filter": "name", "V": "int", "R": "int",
    "Length": "int", "P": "int", "O": "string", "U": "string",
    "CF": "dict", "StmF": "name", "StrF": "name", "EncryptMetadata": "bool",

    # Annotation
    "Subtype": "name", "Rect": "array", "Contents": "string",
    "CA": "number", "ca": "number", "F": "int", "BS": "dict",
    "Border": "array", "RD": "array", "QuadPoints": "array",
    "Open": "bool", "AP": "dict", "AS": "name",

    # Shading / Color
    "ShadingType": "int", "BitsPerCoordinate": "int", "BitsPerComponent": "int",
    "BitsPerFlag": "int", "VerticesPerRow": "int", "Background": "array",
    "BBox": "array", "AntiAlias": "bool", "ColorSpace": "any",
    "Function": "any", "WhitePoint": "array", "BlackPoint": "array",
    "Gamma": "array", "Matrix": "array", "Range": "array", "N": "int",

    # Patterns
    "PaintType": "int", "TilingType": "int", "XStep": "number",
    "YStep": "number", "PatternType": "int",

    # Functions
    "FunctionType": "int", "Order": "int", "BitsPerSample": "int",
    "Functions": "array",

    # XRef / Streams
    "Size": "int", "Index": "array", "Prev": "int",
    "DecodeParms": "dict", "W": "array", "First": "int",

    # Metadata / Info
    "Producer": "string", "Creator": "string", "Author": "string",
    "Title": "string", "Subject": "string", "Keywords": "string",
}

# -----------------------------
# Helpers
# -----------------------------
def random_int():
    return random.randint(-1000, 2000)

def random_number():
    return random.uniform(-100.0, 100.0)

def random_name():
    return Name("/MUT" + str(random.randint(0, 9999)))

def random_string():
    return "".join(chr(random.randint(32, 126)) for _ in range(random.randint(1, 12)))

def mutate_dict(obj: Dictionary):
    if not isinstance(obj, Dictionary):
        return
    if not obj.keys():
        return
    key = random.choice(list(obj.keys()))
    val = obj[key]
    expected = DICT_TYPE_MAP.get(str(key).lstrip("/"), "any")

    try:
        if expected == "int" and isinstance(val, int):
            obj[key] = val + random_int()
        elif expected == "number" and isinstance(val, (int, float)):
            obj[key] = val * (1.0 + random.random())
        elif expected == "array" and isinstance(val, Array):
            if val and isinstance(val[0], int):
                idx = random.randrange(len(val))
                val[idx] = val[idx] + random_int()
            else:
                val.append(random_int())
        elif expected == "name":
            obj[key] = random_name()
        elif expected == "bool":
            obj[key] = not bool(val)
        elif expected == "string":
            obj[key] = random_string()
        elif expected == "dict" and isinstance(val, Dictionary):
            mutate_dict(val)
        elif expected == "stream" and isinstance(val, Stream):
            mutate_stream(val)
        else:
            # fallback generic
            obj[key] = random_name()
    except Exception:
        pass

    # Occasionally add/remove a key
    if random.random() < 0.1:
        obj[Name("/MUTKEY" + str(random.randint(0, 999)))] = random_int()
    if random.random() < 0.05 and obj.keys():
        del obj[random.choice(list(obj.keys()))]

def mutate_stream(stream: Stream):
    try:
        data = bytearray(stream.read_bytes() or b"")
    except Exception:
        return
    if not data:
        return
    choice = random.randrange(3)
    if choice == 0:
        pos = random.randrange(len(data))
        data[pos] ^= 0xFF
    elif choice == 1:
        pos = random.randrange(len(data))
        data.insert(pos, random.randrange(256))
    else:
        start = random.randrange(len(data))
        end = min(len(data), start + random.randint(1, 8))
        del data[start:end]
    try:
        stream.write(bytes(data))
    except Exception:
        pass

def mutate_pdf(buf: bytes) -> bytes:
    try:
        with pikepdf.open(io.BytesIO(buf)) as pdf:
            objs = list(pdf.objects)
            if not objs:
                return buf
            target = random.choice(objs)
            if isinstance(target, Stream):
                mutate_stream(target)
            elif isinstance(target, Dictionary):
                mutate_dict(target)
            if random.random() < 0.2 and len(pdf.pages) > 1:
                random.shuffle(pdf.pages)
            out = io.BytesIO()
            pdf.save(out, linearize=False, compress_streams=False)
            return out.getvalue()
    except Exception as e:
        # raise(e)
        return mutate_generic(buf)

# -----------------------------
# Generic fallback mutator
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
# AFL++ required API
# -----------------------------
def init(seed):
    global _initialized
    random.seed(seed)
    _initialized = True

def deinit():
    global _initialized
    _initialized = False

def fuzz_count(buf):
    return _mutation_count

def fuzz(buf, add_buf, max_size):
    orig_header = buf[:HEADER_SIZE] # Save header for now...
    mutated = mutate_pdf(buf)
    if len(mutated) > max_size:
        mutated = mutated[:max_size]
    return_data = orig_header + mutated
    assert return_data[:HEADER_SIZE] == orig_header
    return return_data # Append header back

TEST_MAX_SIZE = 1_000_000

OUT_DIR = "./out/"

def run_tests():
    print("Running mutator in testing mode.")
    if len(sys.argv) != 2:
        print("Usage: "+str(sys.argv[0])+" PDF_FILE_DIR")
        exit(1)
    directory = sys.argv[1]
    if directory[-1] != "/":
        directory = directory + "/" # Add path separator
    for fn in os.listdir(directory):
        fh = open(directory+fn, "rb")
        data = bytearray(fh.read())
        fh.close()
        data = bytearray(b"\x00\x00\x00\x00") + data # Add the fuzzing header for now...
        for _ in range(_mutation_count):
            data = copy.deepcopy(data)
            data = fuzz(data, None, TEST_MAX_SIZE)
        data = data[HEADER_SIZE:] # Cut out the header... This is because we want to actually observe the result in a web browser etc...
        fh = open(OUT_DIR+fn, "wb")
        fh.write(bytes(data))
        fh.close()
    return

if __name__=="__main__":
    run_tests()
    exit()
