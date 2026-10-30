"""
validate_phase2.py
==================
Oracolo di correttezza della Fase 2: confronta cio' che la pipeline ha
scompattato con l'ORIGINALE PULITO da cui il campione e' stato prodotto.

Perche' serve
-------------
Il criterio attuale ("Ghidra trova >= 5 funzioni") ha gia' promosso a successo
un dump con `.text` interamente a zeri (awk_C57F, 1011 funzioni dichiarate).
Finche' resta l'unico giudice, qualunque numero aggregato della Fase 2 e'
inutilizzabile. Qui il giudice e' l'originale: `matrice_packed/manifest.csv`
conserva `origin_sha256`, e i 53 master corrispondenti sono tutti su disco.

Come confronta
--------------
Entrambi i file vengono mappati in memoria come li vedrebbe il loader
(`pefile.get_memory_mapped_image()`), quindi i byte sono indicizzati per RVA e
il confronto non dipende dal layout su disco (che nel dump e' diverso). Si
confrontano solo le SEZIONI ESEGUIBILI dell'originale.

Tre esiti, non due:
  ricostruito - i byte coincidono oltre MATCH_OK: il payload originale e' li';
  parziale    - c'e' codice, ma non coincide (IAT non ricostruita, rilocazioni
                applicate a una base diversa, dump a un layer intermedio);
  fallito     - la sezione e' assente o a zeri.
`parziale` e' esattamente cio' che il criterio Ghidra oggi conta come successo.

LIMITE DICHIARATO: su Themida e VMProtect l'identita' byte a byte NON e' il
bersaglio - un protector virtualizza il codice, non lo comprime. Quei campioni
sono riportati in una tabella separata e non concorrono al tasso di
ricostruzione: per loro l'unica domanda sensata e' "c'e' codice analizzabile".

Uso
---
    python scripts/validate_phase2.py --selftest
    python scripts/validate_phase2.py --make-baseline ..\BASELINE --per-group 5
    python scripts/validate_phase2.py
"""
import argparse
import csv
import json
import os
import shutil
import sys
from collections import defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger, compute_file_hash, OUTPUT_DIR  # noqa: E402

log = setup_logger("ValidateF2")

MANIFEST = os.environ.get("PACK_MATRIX_MANIFEST",
                          os.path.join("E:" + os.sep, "DATASET", "01_LABEL_CERTA",
                                       "matrice_packed", "manifest.csv"))
MASTERS = os.environ.get("PACK_MASTERS_DIR",
                         os.path.join("E:" + os.sep, "DATASET", "02_MATERIA_PRIMA", "masters"))
STATE_PATH = os.path.join(OUTPUT_DIR, "pipeline_state.json")
REPORT_MD = os.path.join(OUTPUT_DIR, "validation_phase2.md")
REPORT_CSV = os.path.join(OUTPUT_DIR, "validation_phase2.csv")

MATCH_OK = 0.95      # frazione di byte coincidenti per dichiarare "ricostruito"
NONZERO_MIN = 0.05   # sotto questa frazione di byte non-zero la sezione e' vuota
VIRTUALIZING = ("Themida", "VMProtect")   # riportati a parte: vedi docstring

IMAGE_SCN_MEM_EXECUTE = 0x20000000


def compare(orig_path, unp_path):
    """(match, nonzero, byte_confrontati) sulle sezioni eseguibili dell'originale, allineate per RVA."""
    import numpy as np
    import pefile

    po = pefile.PE(orig_path, fast_load=True)
    pu = pefile.PE(unp_path, fast_load=True)
    try:
        img_o = po.get_memory_mapped_image()
        img_u = pu.get_memory_mapped_image()
        same = nonzero = total = 0
        for s in po.sections:
            if not (s.Characteristics & IMAGE_SCN_MEM_EXECUTE):
                continue
            va = s.VirtualAddress
            size = max(s.Misc_VirtualSize, s.SizeOfRawData)
            # ljust: oltre la fine dell'immagine i byte mancano -> contano come zeri,
            # cosi' le due fette hanno sempre la stessa lunghezza e sono confrontabili.
            a = img_o[va:va + size].ljust(size, b"\x00")
            b = img_u[va:va + size].ljust(size, b"\x00")
            arr_a = np.frombuffer(a, dtype=np.uint8)
            arr_b = np.frombuffer(b, dtype=np.uint8)
            same += int(np.count_nonzero(arr_a == arr_b))
            nonzero += int(np.count_nonzero(arr_b))
            total += len(a)
        if not total:
            return 0.0, 0.0, 0
        return same / total, nonzero / total, total
    finally:
        po.close()
        pu.close()


def verdict(match, nonzero):
    if nonzero < NONZERO_MIN:
        return "fallito"
    if match >= MATCH_OK:
        return "ricostruito"
    return "parziale"


def index_masters(directory):
    """{sha256: path} dei binari originali puliti."""
    idx = {}
    for name in os.listdir(directory):
        path = os.path.join(directory, name)
        if os.path.isfile(path):
            digest = compute_file_hash(path)
            if digest:
                idx[digest] = path
    return idx


def evaluate(manifest_rows, masters, state):
    """Una riga di esito per campione."""
    out = []
    for row in manifest_rows:
        rec = {"filename": row["filename"], "layers": row["layers"], "arch": row["arch"],
               "sha256": row["sha256"], "match": None, "nonzero": None, "bytes": None,
               "method": None, "esito": None, "nota": ""}
        orig = masters.get(row["origin_sha256"])
        entry = state.get(row["sha256"])

        if orig is None:
            rec["esito"] = "senza_originale"
            rec["nota"] = "origin_sha256 non trovato fra i master"
        elif entry is None or not entry.get("unpack_attempted"):
            rec["esito"] = "non_processato"
        else:
            rec["method"] = entry.get("unpack_method")
            unp = entry.get("unpack_output")
            if not unp or not os.path.exists(unp):
                rec["esito"] = "fallito"
                rec["nota"] = "nessun output prodotto" if not unp else "output non piu' su disco"
            else:
                try:
                    m, nz, n = compare(orig, unp)
                    rec.update(match=round(m, 4), nonzero=round(nz, 4), bytes=n,
                               esito=verdict(m, nz))
                except Exception as e:
                    rec["esito"] = "non_confrontabile"
                    rec["nota"] = f"{type(e).__name__}: {e}"
        out.append(rec)
    return out


def render(rows):
    L = []
    a = L.append
    a("# Validazione Fase 2 — confronto con l'originale\n")
    a(f"- manifest: `{MANIFEST}`")
    a(f"- master: `{MASTERS}`")
    a(f"- stato pipeline: `{STATE_PATH}`")
    a(f"- soglie: ricostruito se byte coincidenti >= {MATCH_OK:.0%}; "
      f"fallito se byte non-zero < {NONZERO_MIN:.0%}\n")
    a("> Il confronto e' per RVA sulle sole sezioni ESEGUIBILI dell'originale. Codice")
    a("> rilocato a una base diversa produce `parziale`, non `ricostruito`: e' voluto,")
    a("> serve a non spacciare per identico un dump che identico non e'.\n")

    def table(subset, title):
        a(f"## {title}\n")
        if not subset:
            a("_nessun campione._\n")
            return
        groups = defaultdict(list)
        for r in subset:
            groups[(r["layers"], r["arch"])].append(r)
        esiti = ["ricostruito", "parziale", "fallito", "non_processato",
                 "non_confrontabile", "senza_originale"]
        a("| packer | arch | n | " + " | ".join(esiti) + " |")
        a("|---|---|---|" + "---|" * len(esiti))
        for (layers, arch), rs in sorted(groups.items()):
            counts = [sum(1 for r in rs if r["esito"] == e) for e in esiti]
            a(f"| {layers} | {arch} | {len(rs)} | " + " | ".join(str(c) for c in counts) + " |")
        tot = len(subset)
        ok = sum(1 for r in subset if r["esito"] == "ricostruito")
        part = sum(1 for r in subset if r["esito"] == "parziale")
        a("")
        a(f"**Ricostruiti: {ok}/{tot} ({100.0 * ok / tot:.0f}%)** · parziali: {part} "
          f"({100.0 * part / tot:.0f}%)\n")

    comprimenti = [r for r in rows if not any(v in r["layers"] for v in VIRTUALIZING)]
    virtualizzanti = [r for r in rows if any(v in r["layers"] for v in VIRTUALIZING)]

    table(comprimenti, "Compressori e installer — l'identita' byte a byte e' il bersaglio")
    table(virtualizzanti, "Protector che virtualizzano — identita' NON attesa")
    a("> Su questi ultimi `parziale` e' l'esito buono: il codice originale non esiste piu'")
    a("> come sequenza di byte. Non concorrono al tasso di ricostruzione.\n")

    by_method = defaultdict(lambda: defaultdict(int))
    for r in rows:
        if r["method"]:
            by_method[r["method"]][r["esito"]] += 1
    if by_method:
        a("## Per tecnica\n")
        a("| tecnica | ricostruito | parziale | fallito |")
        a("|---|---|---|---|")
        for m, c in sorted(by_method.items()):
            a(f"| {m} | {c['ricostruito']} | {c['parziale']} | {c['fallito']} |")
        a("")
    return "\n".join(L)


def make_baseline(rows, dest, per_group):
    """Copia `per_group` campioni per ogni coppia (packer, arch) in `dest`."""
    os.makedirs(dest, exist_ok=True)
    src_dir = os.path.dirname(MANIFEST)
    groups = defaultdict(list)
    for r in rows:
        groups[(r["layers"], r["arch"])].append(r)
    n = 0
    for key, rs in sorted(groups.items()):
        for r in rs[:per_group]:
            src = os.path.join(src_dir, r["filename"])
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(dest, r["filename"]))
                n += 1
            else:
                log.warning(f"campione mancante: {src}")
    log.info(f"Baseline: {n} campioni da {len(groups)} gruppi copiati in {dest}")
    return n


def selftest():
    """Il metro prima della misura: un file confrontato con se' stesso deve dare 1.0."""
    masters = index_masters(MASTERS)
    paths = sorted(masters.values())
    assert len(paths) >= 2, f"servono almeno 2 master in {MASTERS}"

    m, nz, n = compare(paths[0], paths[0])
    assert n > 0, "nessuna sezione eseguibile confrontata"
    assert m == 1.0, f"un file confrontato con se stesso deve dare 1.0, dato {m}"
    assert nz > NONZERO_MIN, f"sezione eseguibile a zeri? nonzero={nz}"
    assert verdict(m, nz) == "ricostruito"

    m2, _, _ = compare(paths[0], paths[1])
    assert m2 < MATCH_OK, f"due binari diversi non devono risultare identici, dato {m2}"

    assert verdict(0.99, 0.01) == "fallito", "sezione a zeri deve vincere sul match"
    assert verdict(0.50, 0.90) == "parziale"
    log.info(f"selftest OK ({len(paths)} master; identita' {m:.4f}, diversi {m2:.4f})")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--manifest", default=MANIFEST)
    p.add_argument("--masters", default=MASTERS)
    p.add_argument("--state", default=STATE_PATH)
    p.add_argument("--out-md", default=REPORT_MD)
    p.add_argument("--out-csv", default=REPORT_CSV)
    p.add_argument("--selftest", action="store_true",
                   help="verifica il metro, non i risultati: esce senza leggere lo stato.")
    p.add_argument("--make-baseline", metavar="DIR",
                   help="copia un sottoinsieme stratificato per la run di baseline e esce.")
    p.add_argument("--per-group", type=int, default=5,
                   help="campioni per coppia (packer, arch) con --make-baseline (default: 5).")
    args = p.parse_args()

    globals()["MANIFEST"] = args.manifest
    globals()["MASTERS"] = args.masters

    if args.selftest:
        selftest()
        return

    with open(args.manifest, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    log.info(f"{len(rows)} campioni nel manifest.")

    if args.make_baseline:
        make_baseline(rows, args.make_baseline, args.per_group)
        return

    masters = index_masters(args.masters)
    log.info(f"{len(masters)} master indicizzati.")
    with open(args.state, encoding="utf-8") as f:
        state = json.load(f)

    results = evaluate(rows, masters, state)

    with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        w.writeheader()
        w.writerows(results)

    markdown = render(results)
    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write(markdown)
    print(markdown)
    log.info(f"Report scritti: {args.out_md} | {args.out_csv}")


if __name__ == "__main__":
    main()
