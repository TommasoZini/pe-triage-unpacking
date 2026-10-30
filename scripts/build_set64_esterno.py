"""
build_set64_esterno.py
======================
Costruisce il SET COMPLEMENTARE A 64 BIT: programmi che NON abbiamo scritto noi,
impacchettati con i nostri packer.

Che cosa misura, e cosa no
--------------------------
La Fase E e' misurata su `matrice_packed`: 53 programmi compilati in casa, 6 packer.
Due obiezioni possibili a quel 71%:

  (a) "i packer sono i vostri"      -> risponde la Fase F, 29 coppie esterne (docs/07),
                                       ma e' tutta a 32 bit e non esercita Qiling;
  (b) "gli originali sono programmini di prova vostri"  ->  risponde QUESTO set.

Qui i programmi vengono da distribuzioni ufficiali non-Microsoft gia' nella ground
truth (`goodware_non_ms`: VLC, MSYS2/MinGW64, Cygwin, Notepad++, PuTTY, curl): software
vero, grande, con molti import e toolchain diverse. Sono tutti a **64 bit**, quindi
esercitano il ramo Qiling che la Fase F lascia scoperto.

**I packer restano i nostri.** Questo set NON e' una validazione esterna: e' il
controllo dell'asse "complessita' dell'originale". Va etichettato cosi' in tesi.

Come si usa il risultato
------------------------
Il manifest prodotto ha le stesse colonne di `matrice_packed/manifest.csv`, quindi
l'oracolo della Fase E lo legge senza modifiche:

    python scripts/validate_phase2.py --manifest <out>/manifest.csv --masters <masters>

Uso
---
    python scripts/build_set64_esterno.py --masters 10
    python scripts/build_set64_esterno.py --masters 10 --packers UPX,MPRESS
"""
import argparse
import csv
import os
import random
import shutil
import struct
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger, compute_file_hash  # noqa: E402
import pack_samples as PS  # noqa: E402  — si riusano le sue funzioni di packing, non si modifica

log = setup_logger("Set64")

SORGENTE = os.environ.get("GOODWARE_NON_MS",
                          os.path.join("E:" + os.sep, "DATASET", "01_LABEL_CERTA",
                                       "goodware_non_ms"))
OUT_DIR = os.path.join("E:" + os.sep, "DATASET", "01_LABEL_CERTA", "set64_esterno")
MASTERS_DIR = os.path.join("E:" + os.sep, "DATASET", "02_MATERIA_PRIMA", "masters64_esterni")

# Inno e' escluso di proposito: nessun estrattore libero supporta Inno Setup 6.7
# (difetto A2b), quindi darebbe 0 per costruzione e costerebbe solo tempo.
PACKER_DEFAULT = ["UPX", "MPRESS", "Themida", "VMProtect", "NSIS"]

MIN_SIZE, MAX_SIZE = 50_000, 3_000_000
CAMPI = ["filename", "sha256", "layers", "origin_sha256", "arch", "source",
         "is_dotnet", "size_in", "size_out", "generated_at", "progetto"]


def info_pe(path):
    """(arch, ha_cfg, is_dotnet) oppure None se non e' un PE a 64 bit."""
    try:
        with open(path, "rb") as f:
            d = f.read(0x600)
        if d[:2] != b"MZ":
            return None
        off = struct.unpack_from("<I", d, 0x3C)[0]
        if d[off:off + 4] != b"PE\0\0":
            return None
        if struct.unpack_from("<H", d, off + 4)[0] != 0x8664:
            return None            # solo x64: e' il motivo per cui questo set esiste
        opt = off + 24
        dll_char = struct.unpack_from("<H", d, opt + 70)[0]
        ha_cfg = bool(dll_char & PS.IMAGE_DLLCHARACTERISTICS_GUARD_CF)
        # directory 14 = CLR. offset base delle directory per PE32+: opt + 112
        clr_rva = struct.unpack_from("<I", d, opt + 112 + 14 * 8)[0]
        return "x64", ha_cfg, bool(clr_rva)
    except (OSError, struct.error):
        return None


def progetto_di(path):
    """La prima cartella sotto la sorgente: serve a non prendere 10 binari dallo
    stesso progetto e chiamarla varieta'."""
    rel = os.path.relpath(path, SORGENTE)
    parti = rel.split(os.sep)
    return parti[0] if len(parti) > 1 else "(radice)"


def scegli_master(n, seed):
    """n eseguibili x64, senza CFG, non .NET, distribuiti fra i progetti disponibili."""
    candidati = []
    for dp, _dirs, files in os.walk(SORGENTE):
        for f in files:
            if not f.lower().endswith(".exe"):
                continue           # le DLL le salta il ramo emulato: inutili qui
            p = os.path.join(dp, f)
            try:
                size = os.path.getsize(p)
            except OSError:
                continue
            if not (MIN_SIZE <= size <= MAX_SIZE):
                continue
            nfo = info_pe(p)
            if nfo is None:
                continue
            arch, ha_cfg, dotnet = nfo
            if ha_cfg:
                continue           # UPX: "GUARD_CF enabled PE files are not supported"
            if dotnet:
                continue           # i packer nativi non li gestiscono
            candidati.append({"path": p, "size": size, "progetto": progetto_di(p)})

    log.info(f"candidati idonei: {len(candidati)} (x64, senza CFG, non .NET, "
             f"{MIN_SIZE // 1000}-{MAX_SIZE // 1000} KB)")
    if not candidati:
        return []

    per_progetto = {}
    for c in candidati:
        per_progetto.setdefault(c["progetto"], []).append(c)
    for v in per_progetto.values():
        v.sort(key=lambda c: c["path"])

    rnd = random.Random(seed)
    for v in per_progetto.values():
        rnd.shuffle(v)

    # round robin fra i progetti: varieta' prima di quantita'
    scelti, progetti = [], sorted(per_progetto)
    i = 0
    while len(scelti) < n and any(per_progetto[p] for p in progetti):
        p = progetti[i % len(progetti)]
        if per_progetto[p]:
            scelti.append(per_progetto[p].pop())
        i += 1
    return scelti


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--masters", type=int, default=10)
    ap.add_argument("--packers", default=",".join(PACKER_DEFAULT))
    ap.add_argument("--seed", type=int, default=20261011)
    ap.add_argument("--out", default=OUT_DIR)
    ap.add_argument("--masters-dir", default=MASTERS_DIR)
    args = ap.parse_args()

    packers = [p.strip() for p in args.packers.split(",") if p.strip() in PS.PACKERS]
    if not packers:
        ap.error(f"nessun packer valido; scegli fra: {', '.join(PS.PACKERS)}")

    scelti = scegli_master(args.masters, args.seed)
    if not scelti:
        log.error(f"nessun master idoneo in {SORGENTE}")
        return
    log.info(f"master scelti: {len(scelti)} da {len({c['progetto'] for c in scelti})} progetti")

    os.makedirs(args.masters_dir, exist_ok=True)
    os.makedirs(args.out, exist_ok=True)

    masters = []
    for c in scelti:
        h = compute_file_hash(c["path"])
        dst = os.path.join(args.masters_dir, f"x64_ext_{h[:12]}.exe")
        if not os.path.exists(dst):
            shutil.copy2(c["path"], dst)
        masters.append({"path": dst, "sha256": h, "progetto": c["progetto"],
                        "size": c["size"]})

    righe, falliti = [], []
    for m in masters:
        for nome in packers:
            out = os.path.join(args.out,
                               f"x64_ext_{m['sha256'][:12]}_{nome}.exe")
            if os.path.exists(out):
                os.remove(out)
            ok, msg = PS.PACKERS[nome](m["path"], out, "x64")
            if not ok or not os.path.exists(out):
                falliti.append((os.path.basename(m["path"]), nome, msg))
                log.warning(f"  [-] {nome} su {os.path.basename(m['path'])}: {msg[:90]}")
                continue
            righe.append({
                "filename": os.path.basename(out),
                "sha256": compute_file_hash(out),
                "layers": nome,
                "origin_sha256": m["sha256"],
                "arch": "x64",
                "source": "upstream-non-ms",
                "is_dotnet": "0",
                "size_in": m["size"],
                "size_out": os.path.getsize(out),
                "generated_at": "",
                "progetto": m["progetto"],
            })
            log.info(f"  [+] {nome:<10} {os.path.basename(out)}")

    manifest = os.path.join(args.out, "manifest.csv")
    with open(manifest, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CAMPI)
        w.writeheader()
        w.writerows(righe)

    log.info("=" * 56)
    log.info(f"campioni prodotti : {len(righe)} (attesi {len(masters) * len(packers)})")
    log.info(f"falliti           : {len(falliti)}")
    log.info(f"manifest          : {manifest}")
    log.info(f"master            : {args.masters_dir}")
    log.info("misura con:")
    log.info(f"  python scripts/validate_phase2.py --manifest {manifest} "
             f"--masters {args.masters_dir} --out-md Pipeline_Reports/validation_set64.md "
             f"--out-csv Pipeline_Reports/validation_set64.csv")


if __name__ == "__main__":
    main()
