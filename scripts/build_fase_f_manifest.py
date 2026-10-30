"""
build_fase_f_manifest.py
========================
Presenta le 29 coppie del LIVELLO 1 della Fase F all'oracolo, nel formato che
l'oracolo si aspetta. Non calcola niente e non giudica niente: e' un ponte.

Perche' serve
-------------
`validate_phase2.py` legge un manifest con `origin_sha256` e indicizza per hash
una cartella di master. `config/fase_f_coppie.csv` ha un altro schema
(packed_file / clean_file / famiglia) e i 29 binari puliti non stanno in una
cartella a parte: sono mescolati fra i packed dentro `v1_misto`.

Il protocollo (`docs/07`, §4) vieta qualunque modifica all'oracolo fra la firma
e la fine del run. Quindi l'oracolo non si tocca: si adatta l'ingresso.

Nessuna copia di file
---------------------
Come `--masters` si passa **v1_misto stesso**: `index_masters()` costruisce
{sha256: path} su tutto cio' che trova nella cartella, e i 29 puliti sono la'
dentro. I 241 file in piu' finiscono nell'indice e non vengono mai cercati.
Costo: una passata di hash su 270 file. In cambio, zero duplicati su disco e
nessuna cartella da tenere sincronizzata.

Uso
---
    python scripts/build_fase_f_manifest.py
    python scripts/build_fase_f_manifest.py --selftest

Poi, dopo che la Fase 2 ha girato su v1_misto:

    python scripts/validate_phase2.py ^
        --manifest E:\\DATASET\\04_VALIDAZIONE_ESTERNA\\fase_f_manifest.csv ^
        --masters  E:\\DATASET\\04_VALIDAZIONE_ESTERNA\\v1_misto ^
        --out-md   Pipeline_Reports/validation_phase2_esterna.md ^
        --out-csv  Pipeline_Reports/validation_phase2_esterna.csv
"""
import argparse
import csv
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger  # noqa: E402

log = setup_logger("FaseF-Manifest")

REPO = os.path.dirname(SCRIPT_DIR)
COPPIE = os.path.join(REPO, "config", "fase_f_coppie.csv")
V1_MISTO = os.path.join("E:" + os.sep, "DATASET", "04_VALIDAZIONE_ESTERNA", "v1_misto")
OUT = os.path.join("E:" + os.sep, "DATASET", "04_VALIDAZIONE_ESTERNA", "fase_f_manifest.csv")

# Le colonne che evaluate() legge in validate_phase2.py: filename, sha256,
# layers, arch, origin_sha256. Non una di meno, non una di piu'.
CAMPI = ["filename", "sha256", "layers", "arch", "origin_sha256",
         "clean_file", "nome_originale"]


def arch_di(path):
    """'x86' / 'x64' dal Magic dell'optional header. 'ignota' se non e' un PE.

    Il protocollo (§1) dichiara che tutte le 29 coppie sono a 32 bit e che il
    ramo Qiling non viene esercitato dalla misura forte. Qui si rilegge dal
    file invece di fidarsi: se una coppia fosse x64, quella dichiarazione va
    corretta, non aggirata.
    """
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
        try:
            return "x64" if pe.OPTIONAL_HEADER.Magic == 0x20B else "x86"
        finally:
            pe.close()
    except Exception as e:
        log.warning(f"arch non determinabile per {os.path.basename(path)}: "
                    f"{type(e).__name__}: {e}")
        return "ignota"


def costruisci(coppie_path, dataset_dir):
    """Una riga di manifest per coppia. Salta le coppie incomplete su disco."""
    with open(coppie_path, encoding="utf-8") as f:
        coppie = list(csv.DictReader(f))

    righe, scartate = [], []
    for c in coppie:
        packed = os.path.join(dataset_dir, c["packed_file"])
        clean = os.path.join(dataset_dir, c["clean_file"])
        if not os.path.exists(packed) or not os.path.exists(clean):
            scartate.append((c["packed_file"], "packed o clean non su disco"))
            continue
        righe.append({
            "filename": c["packed_file"],
            "sha256": c["packed_sha256"],
            "layers": c["famiglia"],          # render() raggruppa per questa
            "arch": arch_di(packed),
            "origin_sha256": c["clean_sha256"],
            "clean_file": c["clean_file"],
            "nome_originale": c.get("nome_originale", ""),
        })
    return righe, scartate


def controlla(righe, dataset_dir):
    """Verifica il manifest PRIMA di darlo in pasto all'oracolo.

    Un manifest sbagliato non fa fallire validate_phase2.py: produce
    'senza_originale', che si legge come un fallimento della pipeline. Meglio
    accorgersene qui.
    """
    problemi = []

    sha = [r["sha256"] for r in righe]
    if len(set(sha)) != len(sha):
        problemi.append("sha256 duplicati fra i packed del manifest")

    # Ogni origin_sha256 deve esistere davvero nella cartella che faremo da
    # --masters, altrimenti l'esito e' 'senza_originale' per quella riga.
    from pipeline_utils import compute_file_hash
    presenti = set()
    for nome in os.listdir(dataset_dir):
        p = os.path.join(dataset_dir, nome)
        if os.path.isfile(p):
            d = compute_file_hash(p)
            if d:
                presenti.add(d)
    for r in righe:
        if r["origin_sha256"] not in presenti:
            problemi.append(f"{r['filename']}: origin_sha256 non trovato in {dataset_dir}")

    archi = sorted({r["arch"] for r in righe})
    if archi != ["x86"]:
        problemi.append(f"il protocollo §1 dichiara tutte le coppie a 32 bit, trovate: {archi}")

    return problemi


def selftest():
    """Controlla la logica, non i dati: nessun file di dataset necessario."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        a = os.path.join(d, "pack.exe")
        b = os.path.join(d, "clean.exe")
        with open(a, "wb") as f:
            f.write(b"A" * 64)
        with open(b, "wb") as f:
            f.write(b"B" * 64)

        from pipeline_utils import compute_file_hash
        coppie = os.path.join(d, "coppie.csv")
        with open(coppie, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["packed_file", "packed_sha256", "famiglia", "clean_file",
                        "clean_sha256", "nome_originale"])
            w.writerow(["pack.exe", compute_file_hash(a), "FSG", "clean.exe",
                        compute_file_hash(b), "fsg_x.exe"])
            # coppia il cui clean non esiste: deve essere scartata, non esplodere
            w.writerow(["pack.exe", "deadbeef", "MEW", "assente.exe", "cafe", "mew_y.exe"])

        righe, scartate = costruisci(coppie, d)
        assert len(righe) == 1, f"attesa 1 riga, ottenute {len(righe)}"
        assert len(scartate) == 1, f"attesa 1 scartata, ottenute {len(scartate)}"
        assert righe[0]["layers"] == "FSG", "famiglia non mappata su layers"
        assert righe[0]["origin_sha256"] == compute_file_hash(b), "origine sbagliata"
        assert set(CAMPI) == set(righe[0]), "colonne del manifest fuori contratto"
        # i due non-PE finti devono dare 'ignota', non far cadere lo script
        assert righe[0]["arch"] == "ignota", "un non-PE dovrebbe dare arch ignota"

        # il controllo deve accorgersi di un'origine assente
        falso = [dict(righe[0], origin_sha256="0" * 64)]
        assert controlla(falso, d), "controlla() non ha visto l'origine mancante"

    # le colonne attese sono quelle che l'oracolo legge davvero
    import validate_phase2
    src = open(validate_phase2.__file__, encoding="utf-8").read()
    for col in ["filename", "layers", "arch", "sha256", "origin_sha256"]:
        assert f'row["{col}"]' in src, f"l'oracolo non legge piu' {col}: contratto cambiato"

    print("selftest: ok (6 controlli)")


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--coppie", default=COPPIE)
    p.add_argument("--dataset", default=V1_MISTO,
                   help="cartella con packed e puliti (la stessa da passare a --masters).")
    p.add_argument("--out", default=OUT)
    p.add_argument("--selftest", action="store_true")
    p.add_argument("--no-check", action="store_true",
                   help="salta la verifica del manifest (sconsigliato).")
    args = p.parse_args()

    if args.selftest:
        selftest()
        return 0

    righe, scartate = costruisci(args.coppie, args.dataset)
    log.info(f"{len(righe)} coppie nel manifest, {len(scartate)} scartate.")
    for nome, perche in scartate:
        log.warning(f"  scartata {nome}: {perche}")

    if not righe:
        log.error("nessuna coppia utilizzabile: manifest non scritto.")
        return 1

    if not args.no_check:
        problemi = controlla(righe, args.dataset)
        if problemi:
            log.error("manifest NON scritto, prima vanno risolti questi problemi:")
            for x in problemi:
                log.error(f"  - {x}")
            return 1
        log.info("verifica superata: origini tutte presenti, nessun duplicato.")

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=CAMPI)
        w.writeheader()
        w.writerows(righe)
    log.info(f"Manifest scritto: {args.out}")

    fam = {}
    for r in righe:
        fam[r["layers"]] = fam.get(r["layers"], 0) + 1
    log.info(f"{len(fam)} famiglie: " + ", ".join(f"{k} {v}" for k, v in sorted(fam.items())))
    log.info("Ora: Fase 1+2 su v1_misto, poi validate_phase2.py con --masters "
             "sulla stessa cartella (vedi il docstring).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
