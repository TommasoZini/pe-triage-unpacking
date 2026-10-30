"""
build_ground_truth.py
=====================
Costruisce e mantiene il MANIFEST di ground truth della pipeline:
`Pipeline_Reports/ground_truth.json`, indicizzato per SHA-256 del contenuto.

Perche' serve
-------------
Senza un oracolo esplicito non esiste la nozione di "risultato corretto": i
numeri di precision/recall della tesi sarebbero conteggi a mano, non
riproducibili. Il manifest e' quell'oracolo, ed e' indicizzato sull'hash perche'
il NOME non identifica un campione:
  - `TEST_SAMPLES/awk_6DAD...exe` (268.800 B) e `TEST_BIN_PULITI/awk_6DAD...exe`
    (627.466 B) hanno lo stesso nome e contenuto diverso;
  - `pack_samples.py` produce file packati che conservano nel nome l'sha256
    dell'originale PULITO, quindi il nome mente sul contenuto.

Regola fondamentale: NIENTE label automatica "clean"
----------------------------------------------------
Una scansione automatica puo' solo creare voci `unknown`. "Non packed" e'
un'affermazione che va verificata a mano, per due motivi misurati su questo
dataset:
  - `TEST_BIN_PULITI` contiene 48 campioni del libro *Practical Malware
    Analysis* (`Lab01-02`, `Lab18-01`..`Lab18_05`, ...), cioe' malware, e il
    capitolo 18 e' proprio quello sul packing (UPX, PECompact, ASPack, WinUpack);
  - contiene inoltre tool di reverse engineering (`CFF Explorer`, `PE Detective`,
    `HookLibrary*`, `NTDLLEntryPatch`) che possono essere legittimamente protetti.
Contare quei file come "falsi positivi" gonfierebbe artificialmente il FP rate.

Uso
---
    python scripts/build_ground_truth.py --scan "E:/DATASET/03_NON_ETICHETTATI/malware_reali" --dataset malware
    python scripts/build_ground_truth.py --scan "E:/DATASET/03_NON_ETICHETTATI/legacy_misto" --dataset legacy_misto
    python scripts/build_ground_truth.py --import-packing-report
    python scripts/build_ground_truth.py --import-packing-matrix --stats
    python scripts/build_ground_truth.py --set <sha256|nome> --label clean --note "verificato in DIE"
    python scripts/build_ground_truth.py --stats
"""
import argparse
import csv
import json
import os
import re
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger, compute_file_hash, OUTPUT_DIR, PARENT_DIR, SERVICE_EXT  # noqa: E402

log = setup_logger("GroundTruth")

MANIFEST_PATH = os.path.join(OUTPUT_DIR, "ground_truth.json")
PACKING_REPORT = os.path.join(PARENT_DIR, "report_compressione.json")
# Manifest della matrice prodotta da pack_samples.py (formato attuale, per SHA-256).
# PACKING_REPORT sopra e' il formato PRECEDENTE (per nome, sovrascritto a ogni run):
# resta solo per rileggere i campioni storici gia' importati.
MATRIX_MANIFEST = os.environ.get("PACK_MATRIX_MANIFEST",
                                 os.path.join("E:" + os.sep, "DATASET", "01_LABEL_CERTA",
                                              "matrice_packed", "manifest.csv"))

LABELS = ("packed", "clean", "unknown")
AUTO_SOURCES = ("auto-scan",)          # voci che un altro scan puo' sovrascrivere

# Provenienze note che NON devono mai essere assunte benigne. Sono annotazioni,
# non label: servono a chi verifica a mano per sapere da dove guardare.
PROVENANCE_HINTS = (
    (re.compile(r"^Lab\d", re.I),
     "campione del libro Practical Malware Analysis (malware; il cap. 18 e' packing)"),
    (re.compile(r"shellcode_launcher", re.I),
     "tool di lancio shellcode del toolkit PMA"),
    (re.compile(r"CFF Explorer|PE Detective|Signature Explorer|Task Explorer", re.I),
     "tool di reverse engineering: puo' essere legittimamente protetto"),
    (re.compile(r"HookLibrary|NTDLLEntryPatch|CreateProcessPatch", re.I),
     "utility di hooking/patching: import e sezioni atipici per costruzione"),
)


def load_manifest(path=MANIFEST_PATH):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        log.error(f"Manifest illeggibile ({e}). Interrompo per non sovrascriverlo.")
        raise SystemExit(2)


def save_manifest(data, path=MANIFEST_PATH):
    """Scrittura atomica: un manifest a meta' e' peggio di nessun manifest."""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, path)
    log.info(f"Manifest salvato: {path} ({len(data)} voci)")


def _magic(filepath):
    try:
        with open(filepath, "rb") as f:
            return f.read(4).hex()
    except OSError:
        return ""


def _provenance_note(filename):
    for pattern, note in PROVENANCE_HINTS:
        if pattern.search(filename):
            return note
    return ""


def scan(directory, dataset, manifest):
    """Inventario di una cartella. Crea SOLO voci `unknown`: vedi docstring."""
    if not os.path.isdir(directory):
        log.error(f"Directory non esistente: {directory}")
        return 0, 0
    created = skipped = 0
    for root, _dirs, files in os.walk(directory):
        for filename in sorted(files):
            filepath = os.path.join(root, filename)
            # Un manifest.csv non e' un campione: creerebbe una voce 'unknown' permanente.
            if os.path.splitext(filename)[1].lower() in SERVICE_EXT:
                continue
            file_hash = compute_file_hash(filepath)
            if not file_hash:
                log.warning(f"Hash non calcolabile, saltato: {filename}")
                continue
            entry = manifest.get(file_hash)
            if entry and entry.get("source") not in AUTO_SOURCES:
                skipped += 1          # voce verificata a mano o da pack_samples: non si tocca
                continue
            note = _provenance_note(filename)
            manifest[file_hash] = {
                "relpath": os.path.relpath(filepath, directory).replace("\\", "/"),
                "filename": filename,
                "dataset": dataset,
                "size": os.path.getsize(filepath),
                "magic": _magic(filepath),
                "label": "unknown",
                "packers": [],
                "source": "auto-scan",
                "origin_sha256": None,
                "notes": note,
                "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            created += 1
            if note:
                log.warning(f"  [!] {filename}: {note}")
    return created, skipped


def import_packing_report(manifest, report_path=PACKING_REPORT, packed_dir=None):
    """Importa il ground truth prodotto da pack_samples.py.

    `report_compressione.json` e' indicizzato per NOME e viene SOVRASCRITTO a ogni
    run: qui viene convertito una volta per tutte in voci per hash, che
    sopravvivono al reset di TEST_SAMPLES."""
    if not os.path.exists(report_path):
        log.warning(f"Nessun report di packing in {report_path}")
        return 0
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    packed_dir = packed_dir or os.path.join("E:" + os.sep, "DATASET", "01_LABEL_CERTA",
                                           "autopacked_vecchi")
    imported = 0
    for filename, packers in report.items():
        filepath = os.path.join(packed_dir, filename)
        if not os.path.exists(filepath):
            log.warning(f"  File del report non piu' su disco (TEST_SAMPLES resettata?): {filename}")
            continue
        file_hash = compute_file_hash(filepath)
        if not file_hash:
            continue
        # Il nome conserva l'sha256 dell'originale PULITO: lo si estrae per legare
        # il campione packato al suo originale (design appaiato esplicito).
        m = re.search(r"([A-Fa-f0-9]{64})", filename)
        manifest[file_hash] = {
            "relpath": filename,
            "filename": filename,
            "dataset": "packed_by_us",
            "size": os.path.getsize(filepath),
            "magic": _magic(filepath),
            "label": "packed",
            "packers": list(packers),
            "source": "pack_samples",
            "origin_sha256": m.group(1).lower() if m else None,
            "notes": "packato da pack_samples.py: label certa",
            "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        imported += 1
        log.info(f"  [+] {filename} -> {' + '.join(packers)}")
    return imported



def import_packing_matrix(manifest, matrix_csv=MATRIX_MANIFEST, packed_dir=None):
    """Importa la MATRICE prodotta da pack_samples.py come label `packed` CERTE.

    Sostituisce import_packing_report() per il nuovo generatore: quello legge
    `report_compressione.json` (indicizzato per NOME e sovrascritto a ogni run),
    questo legge `manifest.csv` (per SHA-256, in append, una riga per campione).

    La label non e' un'inferenza di uno strumento: e' il fatto di aver ESEGUITO il
    packer. E' l'unica ground truth di packing certa al 100 %, ed e' anche l'unica
    APPAIATA, perche' ogni riga conserva `origin_sha256` dell'originale pulito.

    Controllo che il vecchio importer non faceva: lo SHA-256 viene RICALCOLATO dal
    file su disco e confrontato con la colonna `sha256` del manifest. Se non
    coincidono il campione viene SCARTATO, non importato: un file modificato dopo la
    generazione non e' piu' coperto dalla label, e una ground truth che accetta un
    contenuto diverso da quello dichiarato non e' una ground truth.

    Non tocca MAI i master: `DATASET_MASTERS` non viene scansionato e nessun master
    riceve label `clean` da qui. Vale la regola generale del modulo - "non packed" e'
    un'affermazione che richiede un oracolo esterno, non l'assenza di uno.
    """
    if not os.path.exists(matrix_csv):
        log.error(f"Manifest della matrice non trovato: {matrix_csv}")
        return 0
    packed_dir = packed_dir or os.path.dirname(os.path.abspath(matrix_csv))

    imported = 0
    missing = 0
    mismatch = 0
    conflicts = []
    by_layer = {}

    with open(matrix_csv, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            filename = (row.get("filename") or "").strip()
            if not filename:
                continue
            filepath = os.path.join(packed_dir, filename)
            if not os.path.isfile(filepath):
                missing += 1
                log.warning(f"  File del manifest non trovato su disco: {filename}")
                continue

            file_hash = compute_file_hash(filepath)
            if not file_hash:
                log.warning(f"  Hash non calcolabile, saltato: {filename}")
                continue
            declared = (row.get("sha256") or "").strip().lower()
            if declared and declared != file_hash:
                mismatch += 1
                log.error(f"  [X] {filename}: sha256 diverso da quello dichiarato nel manifest "
                          f"(atteso {declared[:16]}, trovato {file_hash[:16]}). "
                          f"Il file e' stato modificato dopo la generazione: NON importato.")
                continue

            # "UPX + MPRESS" -> ["UPX", "MPRESS"]: l'ordine e' quello di applicazione.
            layers = (row.get("layers") or "").strip()
            packers = [p.strip() for p in layers.split("+") if p.strip()]

            # Una voce gia' presente con label `clean` da un oracolo esterno e' una
            # contraddizione da guardare a mano, non da sovrascrivere in silenzio.
            existing = manifest.get(file_hash)
            if existing and existing.get("label") == "clean":
                conflicts.append((filename, existing.get("source"), existing.get("filename")))

            arch = (row.get("arch") or "").strip()
            source = (row.get("source") or "").strip()
            dotnet = (row.get("is_dotnet") or "").strip()
            note = f"matrice pack_samples.py: arch={arch or '?'}, toolchain={source or '?'}"
            if dotnet == "1":
                # AnyCPU: machine=I386 anche su assembly a 64 bit, quindi `arch` NON e'
                # significativa per questi campioni e vanno esclusi dalle tabelle per
                # architettura (che e' il confondente dichiarato del dataset).
                note += ", assembly .NET (arch non significativa: AnyCPU)"
            generated = (row.get("generated_at") or "").strip()
            if generated:
                note += f", generato {generated}"

            manifest[file_hash] = {
                "relpath": filename,
                "filename": filename,
                "dataset": "packed_matrix",
                "size": os.path.getsize(filepath),
                "magic": _magic(filepath),
                "label": "packed",
                "packers": packers,
                "source": "pack_samples_matrix",
                "origin_sha256": (row.get("origin_sha256") or "").strip().lower() or None,
                "notes": note,
                "updated": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            imported += 1
            by_layer[layers] = by_layer.get(layers, 0) + 1

    for layer in sorted(by_layer):
        log.info(f"  [+] {layer:<16} {by_layer[layer]} campioni")
    if missing:
        log.warning(f"  {missing} righe del manifest senza file su disco (saltate)")
    if mismatch:
        log.error(f"  {mismatch} campioni SCARTATI per sha256 non corrispondente: il manifest "
                  f"e la cartella non sono allineati, rigenera prima di usare queste metriche")
    if conflicts:
        log.error(f"  [!] {len(conflicts)} campioni avevano gia' label 'clean' nel manifest "
                  f"(ora sovrascritta a 'packed'): da verificare a mano")
        for name, src, old in conflicts[:10]:
            log.error(f"      {name}  (era clean da '{src}', come {old})")
    return imported


# Path con slash: Windows li accetta e restano leggibili nei log.
UPX_PATH = os.environ.get("UPX_PATH", "E:/Tools/upx/upx-5.1.1-win64/upx.exe")


def import_upx_test(manifest, directories):
    """Oracolo ESTERNO e non circolare: `upx -t` verifica l'integrita' di un file
    UPX-packed decomprimendolo in memoria. Se esce 0, il file E' UPX-packed, e la
    conferma arriva da UPX stesso, non dai segnali che stiamo valutando.

    Limite da dichiarare in tesi: risponde solo su UPX e fallisce sugli UPX con
    header modificati (e' esattamente l'esercizio di Lab18-02 del libro PMA).
    Produce quindi label `packed` affidabili ma non produce MAI label `clean`:
    un esito diverso da 0 significa solo "non e' UPX standard"."""
    import subprocess
    if not os.path.isfile(UPX_PATH):
        log.error("upx.exe non trovato in %s (impostabile con la variabile UPX_PATH)" % UPX_PATH)
        return 0
    labeled = 0
    for directory in directories:
        if not os.path.isdir(directory):
            log.warning("Directory inesistente, saltata: %s" % directory)
            continue
        for root, _dirs, files in os.walk(directory):
            for filename in sorted(files):
                filepath = os.path.join(root, filename)
                try:
                    rc = subprocess.run([UPX_PATH, "-t", filepath],
                                        capture_output=True, timeout=60).returncode
                except Exception as e:
                    log.debug("upx -t fallito su %s: %s" % (filename, e))
                    continue
                if rc != 0:
                    continue
                file_hash = compute_file_hash(filepath)
                if not file_hash:
                    continue
                entry = manifest.get(file_hash)
                if entry and entry.get("source") == "manual":
                    continue                      # una verifica a mano ha la precedenza
                if entry is None:
                    entry = {"relpath": filename, "filename": filename,
                             "dataset": os.path.basename(directory),
                             "size": os.path.getsize(filepath),
                             "magic": _magic(filepath), "origin_sha256": None}
                    manifest[file_hash] = entry
                entry["label"] = "packed"
                entry["packers"] = sorted(set(entry.get("packers", []) + ["UPX"]))
                entry["source"] = "upx-t"
                entry["notes"] = "confermato UPX-packed da 'upx -t' (oracolo esterno)"
                entry["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
                labeled += 1
                log.info("  [+] %s -> packed (UPX, verificato)" % filename[:60])
    return labeled


MICROSOFT_SUBJECT = "O=Microsoft Corporation"

_PS_SIGNATURE_SCRIPT = (
    "Get-ChildItem -LiteralPath '{dir}' -File -Recurse | ForEach-Object {{ "
    "$s = Get-AuthenticodeSignature -LiteralPath $_.FullName; "
    "$subj = if ($s.SignerCertificate) {{ $s.SignerCertificate.Subject }} else {{ '' }}; "
    "\"$($_.FullName)`t$($s.Status)`t$subj\" }}"
)


def import_authenticode(manifest, directories):
    """Oracolo ESTERNO per le label `clean`: firma Authenticode Microsoft valida.

    Il ragionamento e' in due passi, e vale entrambi:
      1. `Status = Valid` significa che il file non e' stato modificato dopo la
         firma. Packare un binario ne cambia i byte, quindi invaliderebbe la
         firma: una firma valida esclude un packing applicato a posteriori.
      2. Microsoft non distribuisce binari di sistema packati, quindi
         `O=Microsoft Corporation` + firma valida e' un `clean` difendibile.

    Restrizione deliberata a Microsoft: software commerciale firmato E protetto
    e' comune (VMProtect/Themida piu' firma sono la norma), quindi una firma
    valida di terze parti NON autorizza la label `clean`. Nel dataset attuale
    restano `unknown` i 7 file firmati Gen Digital e GitHub."""
    import subprocess
    labeled = skipped = 0
    for directory in directories:
        if not os.path.isdir(directory):
            log.warning("Directory inesistente, saltata: %s" % directory)
            continue
        script = _PS_SIGNATURE_SCRIPT.format(dir=os.path.abspath(directory))
        try:
            # Timeout generoso: Get-AuthenticodeSignature legge e hasha ogni file per
            # verificare la firma, quindi su decine di migliaia di campioni il tempo
            # cresce con i BYTE, non col numero di file. A 900 s il batch da 6.983
            # file di DATASET_BENIGN (6,9 GB) veniva troncato a meta'.
            proc = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                                  capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=7200)
        except Exception as e:
            log.error("Get-AuthenticodeSignature non eseguibile: %s" % e)
            return labeled
        for line in proc.stdout.splitlines():
            parts = line.rstrip("\r").split("\t")
            if len(parts) < 2:
                continue
            filepath, status, subject = parts[0], parts[1], (parts[2] if len(parts) > 2 else "")
            if status != "Valid":
                continue
            if MICROSOFT_SUBJECT not in subject:
                skipped += 1
                log.debug("Firma valida ma non Microsoft, lasciato unknown: %s"
                          % os.path.basename(filepath))
                continue
            file_hash = compute_file_hash(filepath)
            if not file_hash:
                continue
            entry = manifest.get(file_hash)
            # Non si declassa mai un `packed` gia' stabilito da un altro oracolo.
            if entry and (entry.get("source") == "manual" or entry.get("label") == "packed"):
                continue
            if entry is None:
                entry = {"relpath": os.path.basename(filepath), "filename": os.path.basename(filepath),
                         "dataset": os.path.basename(directory), "size": os.path.getsize(filepath),
                         "magic": _magic(filepath), "origin_sha256": None, "packers": []}
                manifest[file_hash] = entry
            entry["label"] = "clean"
            entry["source"] = "authenticode-ms"
            entry["notes"] = "firma Authenticode valida, firmatario Microsoft (oracolo esterno)"
            entry["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            labeled += 1
            log.info("  [+] %s -> clean (firma Microsoft valida)" % os.path.basename(filepath)[:60])
    if skipped:
        log.info("  %d file con firma valida NON Microsoft lasciati 'unknown' (vedi docstring)" % skipped)
    return labeled


def import_labels(manifest, labels_path, directory):
    """Applica un file di label verificate a mano, risolvendo i prefissi dei nomi
    sui file di `directory` e indicizzando per SHA-256.

    Serve a rendere RIPRODUCIBILE l'etichettatura manuale: le label vivono in un
    file versionato nel repository (es. `config/pma_labels.json`, dove la fonte e'
    l'Appendice C di *Practical Malware Analysis*), non dentro a comandi una
    tantum. Rilanciando l'import su una macchina diversa si ottiene lo stesso
    manifest.

    Formato: {"<prefisso del nome file>": {"label": ..., "packers": [...],
              "note": ..., "source": ...}}
    Il prefisso e' la parte del nome che precede `_<sha256>`, cosi' il file di
    label resta leggibile anche se i campioni vengono rinominati con l'hash."""
    if not os.path.isfile(labels_path):
        log.error("File di label non trovato: %s" % labels_path)
        return 0
    if not os.path.isdir(directory):
        log.error("Directory dei campioni non trovata: %s" % directory)
        return 0
    with open(labels_path, "r", encoding="utf-8") as f:
        labels = json.load(f)

    applied, unmatched = 0, []
    for root, _dirs, files in os.walk(directory):
        for filename in sorted(files):
            prefix = re.sub(r"_[A-Fa-f0-9]{64}\.\w+$", "", filename)
            spec = labels.get(prefix)
            if spec is None:
                unmatched.append(filename)
                continue
            filepath = os.path.join(root, filename)
            file_hash = compute_file_hash(filepath)
            if not file_hash:
                continue
            entry = manifest.get(file_hash)
            if entry is None:
                entry = {"relpath": filename, "filename": filename,
                         "dataset": os.path.basename(os.path.normpath(directory)),
                         "size": os.path.getsize(filepath), "magic": _magic(filepath),
                         "origin_sha256": None}
                manifest[file_hash] = entry
            entry["label"] = spec["label"]
            entry["packers"] = list(spec.get("packers", []))
            entry["source"] = spec.get("source", "manual")
            entry["notes"] = spec.get("note", "")
            entry["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
            applied += 1
            if spec["label"] == "packed":
                log.warning("  [!] %s -> packed (%s)" % (prefix, ", ".join(spec.get("packers")) or "?"))
    if unmatched:
        log.warning("%d file in %s senza label nel file: %s"
                    % (len(unmatched), directory, ", ".join(unmatched[:5])))
    used = {re.sub(r"_[A-Fa-f0-9]{64}\.\w+$", "", f)
            for _r, _d, fs in os.walk(directory) for f in fs}
    orfane = sorted(set(labels) - used)
    if orfane:
        log.warning("%d label senza file corrispondente: %s" % (len(orfane), ", ".join(orfane[:5])))
    return applied


def set_label(manifest, key, label, packers=None, note=None):
    """Etichettatura manuale. `key` puo' essere un sha256 o un pezzo di nome file."""
    matches = [h for h in manifest if h.startswith(key.lower())]
    if not matches:
        matches = [h for h, e in manifest.items() if key.lower() in e.get("filename", "").lower()]
    if not matches:
        log.error(f"Nessuna voce per '{key}'")
        return 0
    if len(matches) > 1:
        log.error(f"'{key}' e' ambiguo, corrisponde a {len(matches)} voci:")
        for h in matches[:10]:
            log.error(f"    {h[:16]}  {manifest[h]['filename']}")
        return 0
    entry = manifest[matches[0]]
    entry["label"] = label
    entry["source"] = "manual"
    if packers is not None:
        entry["packers"] = packers
    if note:
        entry["notes"] = note
    entry["updated"] = time.strftime("%Y-%m-%d %H:%M:%S")
    log.info(f"{entry['filename']} -> label={label} packers={entry['packers']}")
    return 1


def stats(manifest):
    from collections import Counter
    if not manifest:
        log.warning("Manifest vuoto.")
        return
    by_label = Counter(e["label"] for e in manifest.values())
    by_dataset = Counter(e["dataset"] for e in manifest.values())
    by_source = Counter(e["source"] for e in manifest.values())
    log.info("=" * 60)
    log.info(f"MANIFEST: {len(manifest)} voci")
    log.info("  per label   : " + ", ".join(f"{k}={v}" for k, v in sorted(by_label.items())))
    log.info("  per dataset : " + ", ".join(f"{k}={v}" for k, v in sorted(by_dataset.items())))
    log.info("  per fonte   : " + ", ".join(f"{k}={v}" for k, v in sorted(by_source.items())))
    labeled = by_label["packed"] + by_label["clean"]
    log.info(f"  utilizzabili per le metriche: {labeled} ({100.0 * labeled / len(manifest):.0f}%)")
    flagged = [e for e in manifest.values() if e["notes"] and e["label"] == "unknown"]
    if flagged:
        log.warning(f"  da verificare a mano per provenienza sospetta: {len(flagged)}")
        for e in sorted(flagged, key=lambda x: x["filename"])[:10]:
            log.warning(f"    {e['filename'][:55]:57s} {e['notes'][:60]}")
        if len(flagged) > 10:
            log.warning(f"    ... e altri {len(flagged) - 10}")
    log.info("=" * 60)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scan", metavar="DIR", help="Inventaria una cartella (crea solo voci 'unknown').")
    parser.add_argument("--dataset", default="unspecified", help="Nome del dataset per le voci create da --scan.")
    parser.add_argument("--import-packing-report", action="store_true",
                        help="Importa report_compressione.json come label 'packed' certe.")
    parser.add_argument("--packed-dir",
                        help="Cartella dei file packati "
                             "(default: E:/DATASET/01_LABEL_CERTA/autopacked_vecchi).")
    parser.add_argument("--import-packing-matrix", action="store_true",
                        help="Importa il manifest della MATRICE di pack_samples.py come label "
                             "'packed' certe (percorso: --matrix-csv). Ricalcola lo sha256 di ogni "
                             "file e scarta i campioni che non corrispondono al manifest.")
    parser.add_argument("--matrix-csv", default=MATRIX_MANIFEST,
                        help="Percorso del manifest della matrice (default: %(default)s).")
    parser.add_argument("--import-upx-test", metavar="DIR", action="append", default=[],
                        help="Verifica con 'upx -t' ed etichetta 'packed' i file UPX confermati (ripetibile).")
    parser.add_argument("--import-authenticode", metavar="DIR", action="append", default=[],
                        help="Etichetta 'clean' i file con firma Authenticode Microsoft valida (ripetibile).")
    parser.add_argument("--import-labels", metavar="FILE_JSON",
                        help="Applica un file di label verificate a mano (es. config/pma_labels.json). "
                             "Richiede --labels-dir.")
    parser.add_argument("--labels-dir", metavar="DIR",
                        help="Cartella dei campioni su cui risolvere i prefissi di --import-labels.")
    parser.add_argument("--set", metavar="SHA_O_NOME", help="Etichetta manualmente una voce.")
    parser.add_argument("--label", choices=LABELS, help="Label da assegnare con --set.")
    parser.add_argument("--packers", default=None, help="Packer noti, separati da virgola (con --set).")
    parser.add_argument("--note", help="Annotazione libera (con --set).")
    parser.add_argument("--stats", action="store_true", help="Riepilogo del manifest.")
    args = parser.parse_args()

    manifest = load_manifest()
    changed = False

    if args.scan:
        created, skipped = scan(args.scan, args.dataset, manifest)
        log.info(f"Scansione '{args.scan}': {created} voci nuove/aggiornate, {skipped} gia' etichettate (non toccate)")
        changed = changed or bool(created)

    if args.import_packing_report:
        n = import_packing_report(manifest, packed_dir=args.packed_dir)
        log.info(f"Importate {n} label 'packed' da report_compressione.json")
        changed = changed or bool(n)

    if args.import_packing_matrix:
        n = import_packing_matrix(manifest, matrix_csv=args.matrix_csv, packed_dir=args.packed_dir)
        log.info(f"Importate {n} label 'packed' CERTE dalla matrice di pack_samples.py")
        changed = changed or bool(n)

    if args.import_upx_test:
        n = import_upx_test(manifest, args.import_upx_test)
        log.info(f"Etichettati {n} file come 'packed' tramite l'oracolo esterno upx -t")
        changed = changed or bool(n)

    if args.import_authenticode:
        n = import_authenticode(manifest, args.import_authenticode)
        log.info(f"Etichettati {n} file come 'clean' tramite la firma Authenticode Microsoft")
        changed = changed or bool(n)

    if args.import_labels:
        if not args.labels_dir:
            parser.error("--import-labels richiede --labels-dir")
        n = import_labels(manifest, args.import_labels, args.labels_dir)
        log.info(f"Applicate {n} label verificate da {args.import_labels}")
        changed = changed or bool(n)

    if args.set:
        if not args.label:
            parser.error("--set richiede --label")
        packers = [p.strip() for p in args.packers.split(",") if p.strip()] if args.packers else None
        changed = bool(set_label(manifest, args.set, args.label, packers, args.note)) or changed

    if changed:
        save_manifest(manifest)

    if args.stats or not (args.scan or args.import_packing_report or args.set
                          or args.import_packing_matrix
                          or args.import_upx_test or args.import_authenticode
                          or args.import_labels):
        stats(manifest)


if __name__ == "__main__":
    main()
