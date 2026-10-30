"""
build_fase_f_pairs.py
=====================
Costruisce la TABELLA DI ACCOPPIAMENTO della Fase F: per ogni campione packed del
dataset esterno `v1_misto`, il corrispondente binario PULITO presente nello stesso
dataset.

Perche' esiste
--------------
La Fase E e' misurata con un oracolo forte (confronto byte a byte con l'originale),
ma su un corpus impacchettato DA NOI: 53 programmi, 6 packer, una versione per packer.
Il numero che ne esce dice "sappiamo disfare i packer che abbiamo applicato noi".

`v1_misto` (da `packing-box/dataset-packed-pe`) ha due meta': 200 packed e 70 puliti.
I nomi originali rivelano che parte dei packed sono versioni compresse di programmi
che stanno, NON compressi, nella meta' pulita. Dove l'accoppiamento esiste, la Fase F
puo' usare lo STESSO oracolo della Fase E su packer che non abbiamo applicato noi.

Come si accoppia
----------------
La chiave `v1_chiave.csv` ha una colonna `nome_originale`:
    packed     ->  "fsg_cpuz_x32.exe"      (prefisso = famiglia del packer)
    not-packed ->  "cpuz_x32.exe"
Si toglie il prefisso fino al PRIMO underscore e si cerca il nome risultante fra i
puliti. Il primo underscore e non l'ultimo: `cpuz_x32.exe` contiene un underscore suo.

VERIFICA DELL'ACCOPPIAMENTO, non assunzione
-------------------------------------------
Che i nomi combacino non prova che i binari siano la stessa cosa. La prova e' che
`upx -d` su un packed UPX ridia il pulito corrispondente. Verificato il 10/10/2026 su
entrambe le coppie UPX disponibili: match 0.9940 e 1.0000. Le altre 27 famiglie non
sono verificabili a priori (non esiste un decompressore di riferimento per ciascuna):
il loro accoppiamento poggia sul nome piu' sulla coerenza del dataset a monte, ed e'
un'assunzione DICHIARATA nel protocollo (docs/07 §3.2).

Uso
---
    python scripts/build_fase_f_pairs.py
    python scripts/build_fase_f_pairs.py --out config/fase_f_coppie.csv
"""
import argparse
import csv
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger, compute_file_hash  # noqa: E402

log = setup_logger("FaseF-Coppie")

CHIAVE = os.environ.get("V1_CHIAVE",
                        os.path.join("E:" + os.sep, "DATASET", "04_VALIDAZIONE_ESTERNA",
                                     "v1_chiave.csv"))
CAMPIONI = os.environ.get("V1_DIR",
                          os.path.join("E:" + os.sep, "DATASET", "04_VALIDAZIONE_ESTERNA",
                                       "v1_misto"))
OUT_DEFAULT = os.path.join(PARENT_DIR, "config", "fase_f_coppie.csv")

CAMPI = ["packed_file", "packed_sha256", "famiglia", "clean_file", "clean_sha256",
         "nome_originale", "packed_size", "clean_size", "nota"]


def nome_senza_packer(nome):
    """'fsg_cpuz_x32.exe' -> 'cpuz_x32.exe'. Primo underscore: il nome del programma
    puo' contenerne altri."""
    parti = nome.split("_", 1)
    return (parti[1] if len(parti) > 1 else nome).lower()


def e_pe(path):
    """True se il file comincia per MZ e ha una firma PE. Non si accoppia cio' che
    l'oracolo non sarebbe comunque in grado di confrontare."""
    try:
        with open(path, "rb") as f:
            testa = f.read(0x400)
        if testa[:2] != b"MZ":
            return False
        off = int.from_bytes(testa[0x3C:0x40], "little")
        return testa[off:off + 4] == b"PE\0\0"
    except OSError:
        return False


def costruisci(chiave_path, dir_campioni):
    with open(chiave_path, encoding="utf-8") as f:
        righe = list(csv.DictReader(f))

    puliti = {r["nome_originale"].strip().lower(): r
              for r in righe if r["vera_label"] == "not-packed"}
    packed = [r for r in righe if r["vera_label"] == "packed"]
    log.info(f"chiave: {len(righe)} righe — {len(packed)} packed, {len(puliti)} puliti distinti")

    coppie, scartate = [], []
    for r in packed:
        atteso = nome_senza_packer(r["nome_originale"].strip())
        pulito = puliti.get(atteso)
        if pulito is None:
            scartate.append((r["file_neutro"], "nessun pulito con quel nome"))
            continue

        p_path = os.path.join(dir_campioni, r["file_neutro"])
        c_path = os.path.join(dir_campioni, pulito["file_neutro"])
        if not (os.path.exists(p_path) and os.path.exists(c_path)):
            scartate.append((r["file_neutro"], "file non presente su disco"))
            continue
        if not (e_pe(p_path) and e_pe(c_path)):
            scartate.append((r["file_neutro"], "non e' un PE valido"))
            continue

        coppie.append({
            "packed_file": r["file_neutro"],
            "packed_sha256": compute_file_hash(p_path),
            "famiglia": r["famiglia"],
            "clean_file": pulito["file_neutro"],
            "clean_sha256": compute_file_hash(c_path),
            "nome_originale": r["nome_originale"],
            "packed_size": os.path.getsize(p_path),
            "clean_size": os.path.getsize(c_path),
            "nota": "",
        })
    return coppie, scartate


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--chiave", default=CHIAVE)
    p.add_argument("--dir", dest="dir_campioni", default=CAMPIONI)
    p.add_argument("--out", default=OUT_DEFAULT)
    args = p.parse_args()

    coppie, scartate = costruisci(args.chiave, args.dir_campioni)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CAMPI)
        w.writeheader()
        w.writerows(coppie)

    fam = {}
    for c in coppie:
        fam[c["famiglia"]] = fam.get(c["famiglia"], 0) + 1
    log.info(f"coppie accoppiate: {len(coppie)} su {len(coppie) + len(scartate)} packed")
    log.info(f"famiglie coperte : {len(fam)}")
    for k in sorted(fam):
        log.info(f"    {k:<22} {fam[k]}")
    if scartate:
        motivi = {}
        for _, m in scartate:
            motivi[m] = motivi.get(m, 0) + 1
        log.info("non accoppiati: " + ", ".join(f"{v} {k}" for k, v in sorted(motivi.items())))
    log.info(f"tabella scritta in: {args.out}")


if __name__ == "__main__":
    main()
