"""
make_external_key.py
====================
Genera la CHIAVE DI RISPOSTA del dataset esterno `packing-box/dataset-packed-pe`
leggendo l'albero delle cartelle, e la confronta con una chiave esistente.

Perche' serve
-------------
`v2_chiave.csv` esisteva sul disco ma **nessuno script la produceva**: era un
artefatto non riproducibile, cioe' l'unica cosa che nel progetto non ha diritto
di esserlo, perche' e' l'oracolo con cui si misura il recall esterno. Questo
script la ricostruisce dai fatti (il nome della cartella di destinazione), e con
`--verify` dimostra di riprodurre la chiave firmata riga per riga.

L'oracolo e' COSTRUTTIVO: 432 programmi freeware sono stati passati dentro 25
packer e l'etichetta e' il nome della cartella in cui sono finiti. Nessun
rilevatore partecipa all'etichettatura, quindi misurare DIE e YARA su questo
insieme non e' circolare (protocollo §3.2).

La cartella `outliers/`
-----------------------
Il dataset contiene anche `outliers/`, che il suo README descrive come i
campioni *"we could identify as potentially disturbing our models, i.e. when they
were sorted among the not packed samples while demonstrating characteristics of
packed data"*. Sono **152 file distinti** che non stanno ne' in `packed/` ne' in
`not-packed/` (sovrapposizione misurata: zero), erano fuori da `v2_chiave.csv` e
quindi da ogni misura, pur essendo gia' stati analizzati nel run del 28/09.

I 142 sotto `outliers/packed/` sono organizzati per famiglia esattamente come
`packed/`, quindi hanno lo **stesso oracolo costruttivo** e possono entrare nella
misura del recall. I 10 sotto `outliers/not-packed/` restano `not-packed`, cioe'
nella meta' che il protocollo tiene fuori dalle metriche.

Uso
---
    python scripts/make_external_key.py --verify                # riproduce v2? (nessuna scrittura)
    python scripts/make_external_key.py --out <file.csv>        # scrive la chiave con gli outliers
"""
import argparse
import csv
import hashlib
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger  # noqa: E402

log = setup_logger("MakeExtKey")

DATASET_ROOT = os.environ.get("EXTERNAL_DATASET_ROOT",
                              os.path.join("E:" + os.sep, "dataset-packed-pe-main"))
BASE = os.path.join("E:" + os.sep, "DATASET", "04_VALIDAZIONE_ESTERNA")
OLD_KEY = os.path.join(BASE, "v2_chiave.csv")
NEW_KEY = os.path.join(BASE, "v3_chiave.csv")

FIELDS = ["sha256", "vera_label", "famiglia", "origine", "nome_originale", "size",
          "nota_divergenza"]
# File di servizio del dataset: `packed/README.md` e' documentazione, non un campione.
SERVICE_EXT = {".md", ".json", ".txt", ".py", ".csv"}


def scan(root, include_outliers=True):
    """Una riga per file, con l'etichetta dedotta dalla cartella di destinazione."""
    zone = [("packed", "packed"), ("not-packed", "not-packed")]
    if include_outliers:
        zone += [(os.path.join("outliers", "packed"), "packed"),
                 (os.path.join("outliers", "not-packed"), "not-packed")]
    rows, saltati = [], 0
    for rel_zone, label in zone:
        base = os.path.join(root, rel_zone)
        if not os.path.isdir(base):
            log.warning("zona assente: %s" % base)
            continue
        for dirpath, _dirs, files in os.walk(base):
            for name in sorted(files):
                if os.path.splitext(name)[1].lower() in SERVICE_EXT:
                    saltati += 1
                    continue
                path = os.path.join(dirpath, name)
                sub = os.path.relpath(dirpath, base)
                famiglia = "" if (sub == "." or label == "not-packed") else sub
                origine = rel_zone.replace(os.sep, "/")
                if famiglia:
                    origine += "/" + famiglia
                with open(path, "rb") as f:
                    data = f.read()
                rows.append({"sha256": hashlib.sha256(data).hexdigest(),
                             "vera_label": label,
                             "famiglia": famiglia,
                             "origine": origine,
                             "nome_originale": name,
                             "size": str(len(data)),
                             "nota_divergenza": ""})
    if saltati:
        log.info("%d file di servizio saltati (README e simili)" % saltati)
    return rows


def carry_notes(rows, old_key_path):
    """Le note di divergenza sono VERIFICHE MANUALI: non si deducono dall'albero,
    quindi si riportano dalla chiave precedente invece di perderle."""
    if not os.path.isfile(old_key_path):
        return 0
    with open(old_key_path, encoding="utf-8") as f:
        note = {r["sha256"]: r.get("nota_divergenza", "")
                for r in csv.DictReader(f) if r.get("nota_divergenza")}
    n = 0
    for r in rows:
        if r["sha256"] in note:
            r["nota_divergenza"] = note[r["sha256"]]
            n += 1
    return n


def verify(rows, old_key_path):
    """Confronta con la chiave esistente sugli hash in comune. Ritorna il numero
    di differenze: zero significa che il generatore riproduce la chiave firmata."""
    with open(old_key_path, encoding="utf-8") as f:
        old = {r["sha256"]: r for r in csv.DictReader(f)}
    gen = {r["sha256"]: r for r in rows}
    comuni = set(old) & set(gen)
    diff = 0
    for h in sorted(comuni):
        for campo in ("vera_label", "famiglia", "origine", "nome_originale", "size"):
            if (old[h].get(campo) or "") != (gen[h].get(campo) or ""):
                diff += 1
                if diff <= 10:
                    log.error("  %s: %s  vecchio=%r  generato=%r"
                              % (h[:12], campo, old[h].get(campo), gen[h].get(campo)))
    log.info("hash in comune: %d | differenze sui campi dedotti: %d" % (len(comuni), diff))
    solo_old = set(old) - set(gen)
    solo_new = set(gen) - set(old)
    if solo_old:
        log.warning("%d hash nella chiave vecchia e NON generati: %s"
                    % (len(solo_old), ", ".join(h[:12] for h in sorted(solo_old)[:5])))
    if solo_new:
        log.info("%d hash nuovi (non presenti nella chiave vecchia)" % len(solo_new))
        per_zona = {}
        for h in solo_new:
            per_zona[gen[h]["origine"].split("/")[0]] = per_zona.get(
                gen[h]["origine"].split("/")[0], 0) + 1
        log.info("   per zona: %s" % per_zona)
    return diff, len(solo_old), len(solo_new)


def write(rows, path):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(sorted(rows, key=lambda r: (r["origine"], r["nome_originale"])))
    os.replace(tmp, path)
    log.info("Chiave scritta: %s (%d righe)" % (path, len(rows)))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[2],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=DATASET_ROOT, help="Radice del dataset esterno.")
    ap.add_argument("--old-key", default=OLD_KEY, help="Chiave con cui confrontare.")
    ap.add_argument("--out", default=None, help="Dove scrivere la chiave nuova.")
    ap.add_argument("--verify", action="store_true",
                    help="Rigenera SENZA outliers e confronta con --old-key. Non scrive nulla.")
    args = ap.parse_args()

    if not os.path.isdir(args.root):
        sys.exit("Dataset esterno non trovato: %s" % args.root)

    if args.verify:
        rows = scan(args.root, include_outliers=False)
        log.info("generate %d righe (senza outliers)" % len(rows))
        diff, solo_old, solo_new = verify(rows, args.old_key)
        if diff or solo_old or solo_new:
            log.error("La chiave NON e' riprodotta: non usare il generatore finche' non torna.")
            return 1
        log.info("OK: il generatore riproduce %s riga per riga." % os.path.basename(args.old_key))
        return 0

    rows = scan(args.root, include_outliers=True)
    n = carry_notes(rows, args.old_key)
    log.info("generate %d righe | note di verifica manuale riportate: %d" % (len(rows), n))
    verify(rows, args.old_key)
    write(rows, args.out or NEW_KEY)
    return 0


if __name__ == "__main__":
    sys.exit(main())
