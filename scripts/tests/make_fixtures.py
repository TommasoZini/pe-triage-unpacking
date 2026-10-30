"""
make_fixtures.py
================
Genera PE32 SINTETICI e deterministici per la suite di test della Fase 1.

Perche' sintetici e non campioni reali:
  - la suite deve girare su qualunque macchina, anche senza il dataset di
    malware (e senza distribuire malware insieme alla tesi);
  - ogni fixture isola UN solo segnale, cosi' un test che fallisce indica
    esattamente quale regola di scoring si e' rotta;
  - il contenuto e' riproducibile byte per byte (nessun timestamp, nessun
    random non seminato), quindi gli hash sono stabili fra run.

I file prodotti sono PE32 minimi ma VALIDI: LIEF li parsa come
lief.PE.Binary, che e' cio' che la Fase 1 richiede.
"""
import os
import struct
import random

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000
IMAGE_BASE = 0x400000

# IMAGE_SCN_*
SCN_CODE = 0x00000020
SCN_IDATA = 0x00000040
SCN_MEM_EXECUTE = 0x20000000
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000

RX = SCN_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ
RWX = RX | SCN_MEM_WRITE
RW = SCN_IDATA | SCN_MEM_READ | SCN_MEM_WRITE


def _align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def _build_import_blob(base_rva, dlls):
    """IMAGE_IMPORT_DESCRIPTOR + ILT/IAT + hint/name + stringhe, tutto in un blob
    che vive a `base_rva`. Ritorna (bytes, (rva_descrittori, size_descrittori)).

    OriginalFirstThunk e FirstThunk puntano allo stesso ILT: basta perche' LIEF
    elenchi gli import, e queste fixture non devono essere eseguite."""
    desc_size = 20 * (len(dlls) + 1)               # +1 = descrittore nullo di chiusura
    cursor = desc_size
    blocks = []
    for dll, funcs in dlls.items():
        thunk_rva = base_rva + cursor
        cursor += 4 * (len(funcs) + 1)             # +1 = terminatore nullo dell'ILT
        entries, name_blobs = [], []
        for fn in funcs:
            entries.append(base_rva + cursor)
            blob = struct.pack("<H", 0) + fn.encode() + b"\x00"
            if len(blob) % 2:
                blob += b"\x00"
            name_blobs.append(blob)
            cursor += len(blob)
        dll_rva = base_rva + cursor
        dll_blob = dll.encode() + b"\x00"
        if len(dll_blob) % 2:
            dll_blob += b"\x00"
        cursor += len(dll_blob)
        blocks.append((thunk_rva, entries, dll_rva, name_blobs, dll_blob))

    out = b""
    for thunk_rva, _entries, dll_rva, _names, _dll in blocks:
        out += struct.pack("<IIIII", thunk_rva, 0, 0, dll_rva, thunk_rva)
    out += b"\x00" * 20
    for _thunk, entries, _dll_rva, name_blobs, dll_blob in blocks:
        out += b"".join(struct.pack("<I", e) for e in entries) + b"\x00\x00\x00\x00"
        out += b"".join(name_blobs)
        out += dll_blob
    return out, (base_rva, desc_size)


def build_pe(sections, entry_rva=None, is_dll=False, overlay=b"", n_data_dirs=16, imports=None):
    """
    sections: lista di dict {name: bytes(<=8), data: bytes, characteristics: int,
                             virtual_size: int|None}
    entry_rva: RVA dell'entry point. None -> inizio della prima sezione eseguibile.
    imports:   {"DLL.dll": ["Func1", ...]} -> costruisce una .idata reale e compila
               DataDirectory[1]. Serve al controllo negativo: senza IAT ogni fixture
               scatterebbe il segnale debole "numero import basso".
    Ritorna i byte completi del PE.
    """
    if imports:
        sections = list(sections) + [{"name": b".idata", "data": b"",
                                      "characteristics": SCN_IDATA | SCN_MEM_READ}]
    n_sections = len(sections)
    opt_size = 0xE0
    headers_size = 0x40 + 4 + 20 + opt_size + 40 * n_sections
    size_of_headers = _align(headers_size, FILE_ALIGN)

    # Layout: assegna a ogni sezione RVA e offset su file
    rva = _align(size_of_headers, SECT_ALIGN)
    raw = size_of_headers
    layout = []
    for s in sections:
        data = s["data"]
        raw_size = _align(len(data), FILE_ALIGN)
        vsize = s.get("virtual_size") or max(len(data), 1)
        layout.append({"name": s["name"], "data": data, "ch": s["characteristics"],
                       "rva": rva, "vsize": vsize,
                       "raw_off": raw if raw_size else 0, "raw_size": raw_size})
        rva = _align(rva + vsize, SECT_ALIGN)
        raw += raw_size

    # La .idata si puo' riempire solo ORA: gli RVA interni dipendono dal layout.
    import_dir = (0, 0)
    if imports:
        idata = layout[-1]
        blob, import_dir = _build_import_blob(idata["rva"], imports)
        idata["data"] = blob
        idata["vsize"] = len(blob)
        idata["raw_size"] = _align(len(blob), FILE_ALIGN)
        idata["raw_off"] = raw
        raw += idata["raw_size"]
        rva = _align(idata["rva"] + idata["vsize"], SECT_ALIGN)
    size_of_image = rva

    if entry_rva is None:
        entry_rva = next((l["rva"] for l in layout if l["ch"] & SCN_MEM_EXECUTE), 0)

    # --- DOS header (e_lfanew = 0x40) ---
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    # --- COFF header ---
    characteristics = 0x0102 | (0x2000 if is_dll else 0)   # EXECUTABLE_IMAGE | 32BIT [| DLL]
    coff = struct.pack("<HHIIIHH", 0x14C, n_sections, 0, 0, 0, opt_size, characteristics)

    # --- Optional header PE32 ---
    code_size = sum(l["raw_size"] for l in layout if l["ch"] & SCN_MEM_EXECUTE)
    opt = struct.pack(
        "<HBBIIIIII",
        0x10B, 14, 0,            # Magic PE32, LinkerVersion
        code_size, 0, 0,         # SizeOfCode, InitializedData, UninitializedData
        entry_rva, 0x1000, 0,    # EntryPoint, BaseOfCode, BaseOfData
    )
    opt += struct.pack("<IIIHHHHHHIIIIHH",
                       IMAGE_BASE, SECT_ALIGN, FILE_ALIGN,
                       4, 0, 0, 0, 4, 0,                 # OS/Image/Subsystem versions
                       0, size_of_image, size_of_headers, 0,
                       3, 0)                              # Subsystem=CUI, DllCharacteristics
    opt += struct.pack("<IIIIII", 0x100000, 0x1000, 0x100000, 0x1000, 0, n_data_dirs)
    dirs = [(0, 0)] * n_data_dirs
    if n_data_dirs > 1:
        dirs[1] = import_dir                              # IMAGE_DIRECTORY_ENTRY_IMPORT
    opt += b"".join(struct.pack("<II", a, b) for a, b in dirs)
    opt = opt.ljust(opt_size, b"\x00")[:opt_size]

    # --- Section table ---
    table = b""
    for l in layout:
        table += struct.pack("<8sIIIIIIHHI",
                             l["name"].ljust(8, b"\x00")[:8],
                             l["vsize"], l["rva"], l["raw_size"], l["raw_off"],
                             0, 0, 0, 0, l["ch"])

    out = bytearray(bytes(dos) + b"PE\x00\x00" + coff + opt + table)
    out += b"\x00" * (size_of_headers - len(out))
    for l in layout:
        out += l["data"].ljust(l["raw_size"], b"\x00")
    out += overlay
    return bytes(out)


def _code(n=0x40):
    """Byte plausibili come codice: bassa entropia, come un .text compilato."""
    return (b"\x55\x89\xe5\x83\xec\x08\xc7\x45\xfc\x00\x00\x00\x00\x8b\x45\xfc"
            b"\x83\xc4\x08\x5d\xc3\x90\x90\x90") * (n // 24 + 1)


def _high_entropy(n, seed):
    """Dati pseudo-casuali (H ~ 8.0) ma DETERMINISTICI: stesso seed, stessi byte.

    Il Random va istanziato UNA volta fuori dalla comprehension. Crearlo dentro
    (random.Random(seed).randrange(256) per ogni byte) lo ri-semina a ogni
    iterazione e produce n byte tutti IDENTICI, cioe' entropia 0: la fixture
    testerebbe l'esatto contrario di quello che dichiara."""
    rng = random.Random(seed)
    return bytes(rng.randrange(256) for _ in range(n))


FIXTURES = {}


def fixture(name):
    def deco(fn):
        FIXTURES[name] = fn
        return fn
    return deco


@fixture("clean_basic.exe")
def _clean():
    """Controllo NEGATIVO: sezioni standard, entropia bassa, IAT popolata (21 import),
    nessuna anomalia. Deve uscire Is_Packed_Label = 0 senza alcun segnale."""
    return build_pe([
        {"name": b".text", "data": _code(0x400), "characteristics": RX},
        {"name": b".rdata", "data": b"hello world\x00" * 40, "characteristics": SCN_IDATA | SCN_MEM_READ},
        {"name": b".data", "data": b"\x00" * 0x200, "characteristics": RW},
    ], imports={"KERNEL32.dll": ["CreateFileA", "ReadFile", "WriteFile", "CloseHandle",
                                 "GetLastError", "HeapAlloc", "HeapFree", "ExitProcess",
                                 "GetStdHandle", "WriteConsoleW", "GetCommandLineA",
                                 "VirtualAlloc", "VirtualFree", "Sleep", "GetTickCount"],
                "USER32.dll": ["MessageBoxA", "LoadStringA", "CharNextA", "wsprintfA",
                               "GetDesktopWindow", "SetWindowTextA"]})


@fixture("sec_name_bytes.exe")
def _sec_name_bytes():
    """Nome di sezione NON UTF-8: prima del fix _txt() sollevava TypeError e il file
    spariva in silenzio dal CSV (2 file su 16 nel batch reale)."""
    return build_pe([
        {"name": b"\xc0\xde\xff\x01", "data": _high_entropy(0x1000, 1), "characteristics": RX},
        {"name": b".data", "data": b"\x00" * 0x200, "characteristics": RW},
    ])


@fixture("ep_outside_sections.exe")
def _ep_outside():
    """Entry point fuori da OGNI sezione: anomalia fortissima che oggi non produce
    alcun segnale (EP_Section resta 'UNKNOWN' ed e' esclusa dal controllo). Vedi B7."""
    return build_pe([
        {"name": b".text", "data": _code(0x400), "characteristics": RX},
        {"name": b".data", "data": b"\x00" * 0x200, "characteristics": RW},
    ], entry_rva=0x900000)


@fixture("dll_ep_zero.dll")
def _dll_ep_zero():
    """DLL con AddressOfEntryPoint = 0: EP_Section resta 'UNKNOWN'. Vedi B7."""
    return build_pe([
        {"name": b".text", "data": _code(0x400), "characteristics": RX},
        {"name": b".data", "data": b"\x00" * 0x200, "characteristics": RW},
    ], entry_rva=0, is_dll=True)


@fixture("no_imports.exe")
def _no_imports():
    """PE senza import directory (IAT distrutta): oggi vale solo il debole '<20 import'
    perche' Suspicious_IAT pretende LoadLibrary+GetProcAddress. Vedi B8."""
    return build_pe([
        {"name": b".text", "data": _code(0x400), "characteristics": RX},
        {"name": b".data", "data": b"\x00" * 0x200, "characteristics": RW},
    ])


@fixture("stub_structural.exe")
def _stub_structural():
    """Layout tipico di stub: EP in sezione ad alta entropia + W+X, e una sezione
    eseguibile svuotata (raw=0, virtual grande) dove finira' il codice originale."""
    return build_pe([
        {"name": b"pack0", "data": b"", "characteristics": RX, "virtual_size": 0x8000},
        {"name": b"pack1", "data": _high_entropy(0x1000, 2), "characteristics": RWX},
    ], entry_rva=0x9000)      # EP nella sezione compressa, non in quella svuotata


@fixture("upx_like.exe")
def _upx_like():
    """Nomi di sezione di un packer NOMINATO: deve dare segnale FORTE via
    packer_label_from_section_name, senza bisogno di YARA/DIE/capa."""
    return build_pe([
        {"name": b"UPX0", "data": b"", "characteristics": RX, "virtual_size": 0x8000},
        {"name": b"UPX1", "data": _high_entropy(0x1000, 3), "characteristics": RWX},
    ], entry_rva=0x9000)      # come in UPX reale: l'EP sta nello stub, in UPX1


@fixture("overlay_high_entropy.exe")
def _overlay():
    """Wrapper tipo SFX/NSIS: sezioni normali, payload compresso nell'overlay."""
    return build_pe([
        {"name": b".text", "data": _code(0x400), "characteristics": RX},
        {"name": b".data", "data": b"\x00" * 0x200, "characteristics": RW},
    ], overlay=_high_entropy(300 * 1024, 4))


@fixture("not_executable.exe")
def _not_exec():
    """Estensione .exe ma magic 'DCS\\x01': 27 file su 173 del set benigno reale sono
    delta di Windows Update come questo. Deve uscire come Parse_Status=not_executable."""
    return b"DCS\x01" + _high_entropy(4096, 5)


def generate(out_dir=FIXTURES_DIR):
    os.makedirs(out_dir, exist_ok=True)
    written = {}
    for name, fn in sorted(FIXTURES.items()):
        path = os.path.join(out_dir, name)
        data = fn()
        with open(path, "wb") as f:
            f.write(data)
        written[name] = path
    return written


if __name__ == "__main__":
    for name, path in generate().items():
        print("%8d  %s" % (os.path.getsize(path), name))
