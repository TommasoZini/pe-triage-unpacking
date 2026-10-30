"""
validate_phase1.py
==================
Harness di valutazione della Fase 1: prende il CSV prodotto dal triage e il
manifest di ground truth, e produce le metriche che finiscono in tesi.

Sostituisce il conteggio a mano ("17/30 falsi positivi", "16/16 rilevati") con
un comando ripetibile, che produce sempre gli stessi numeri a partire dagli
stessi artefatti:

  - matrice di confusione, precision / recall / F1 sul solo sottoinsieme
    ETICHETTATO (gli `unknown` vengono contati a parte, mai assunti benigni);
  - tabella di discriminazione per SINGOLO segnale (quanto spesso compare nei
    packed vs nei clean): e' la tabella che oggi e' scritta a mano nel
    documento di stato;
  - sweep della soglia WEAK_SIGNALS_REQUIRED, per mostrare che il valore
    scelto e' un ottimo misurato e non un'opinione;
  - esposizione al NON DETERMINISMO: quante classificazioni sono state decise
    mentre un tool era in timeout o in finestra di sondaggio scaduta.

Uso
---
    python scripts/validate_phase1.py
    python scripts/validate_phase1.py --csv <report.csv> --manifest <gt.json>
    python scripts/validate_phase1.py --resolve-dir "E:/DATASET/03_NON_ETICHETTATI/malware_reali"

`--resolve-dir` serve finche' il CSV non ha la colonna SHA256: ricalcola l'hash
dei file a partire dalla colonna `File`, che e' un path RELATIVO alla cartella
analizzata (e quindi, da solo, ambiguo fra dataset diversi).
"""
import argparse
import csv
import json
import os
import sys
from collections import Counter, defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger, compute_file_hash, OUTPUT_DIR  # noqa: E402

log = setup_logger("Validate")

DEFAULT_CSV = os.path.join(OUTPUT_DIR, "report_analisi_lief.csv")
DEFAULT_MANIFEST = os.path.join(OUTPUT_DIR, "ground_truth.json")
REPORT_MD = os.path.join(OUTPUT_DIR, "validation_phase1.md")
REPORT_JSON = os.path.join(OUTPUT_DIR, "validation_phase1.json")

# Stati dei tool che indicano una decisione presa SENZA l'informazione completa:
# il risultato dipende dal carico della macchina, non solo dal binario.
TRUNCATED_STATES = {"timeout", "probe_timeout", "no_banner_probe", "stopped_at_banner"}


def normalize_signal(text):
    """Riduce un segnale alla sua CLASSE, togliendo la parte variabile.

    'sezione tipica di packer: UPX0->UPX, UPX1->UPX' -> 'sezione tipica di packer'
    'entry point in sezione non standard (.themida)' -> 'entry point in sezione non standard'
    Senza questa normalizzazione ogni file avrebbe segnali "unici" e la tabella
    di discriminazione sarebbe inutile."""
    text = text.split(":")[0]
    text = text.split("(")[0]
    return text.strip().rstrip(".").lower()


def split_signals(cell):
    return [s.strip() for s in (cell or "").split("|") if s.strip()]


def load_rows(csv_path, resolve_dirs):
    """Righe del CSV, con l'hash risolto. Ritorna (righe, n_non_risolte)."""
    if not os.path.exists(csv_path):
        log.error(f"CSV non trovato: {csv_path}")
        raise SystemExit(2)
    with open(csv_path, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        log.error("CSV vuoto.")
        raise SystemExit(2)

    has_hash_col = "SHA256" in rows[0]
    unresolved = 0
    for row in rows:
        file_hash = (row.get("SHA256") or "").strip().lower() if has_hash_col else ""
        if not file_hash:
            for base in resolve_dirs:
                candidate = os.path.join(base, row["File"])
                if os.path.exists(candidate):
                    file_hash = compute_file_hash(candidate) or ""
                    if file_hash:
                        break
        row["_hash"] = file_hash
        if not file_hash:
            unresolved += 1
    if not has_hash_col:
        log.warning("Il CSV non ha la colonna SHA256: l'aggancio al manifest passa dal nome "
                    "file, che NON e' univoco fra dataset diversi (vedi B1).")

    # DEDUPLICA PER CONTENUTO. Il CSV ha una riga per FILE (ed e' giusto: e' il log
    # dell'analisi), ma la ground truth e' indicizzata per SHA-256 e l'unita' di misura
    # e' il BINARIO, non il nome. System32 contiene file byte-identici con nomi diversi:
    # x64_MicrosoftEdgeBCHost/CP/DevTools.exe sono lo stesso stub (3 nomi, 1 binario) e
    # x86_dplaysvr.exe/dpnaddr.dll/dpnhpast.dll/dpnsvr.exe altrettanto (4 nomi, 1 binario).
    # Contando le righe, quei 7 file gonfiavano TN di 5 unita' e il supporto totale di 5:
    # lo stesso binario veniva pesato fino a 4 volte nelle metriche.
    unique, seen, collapsed = [], {}, []
    for row in rows:
        h = row["_hash"]
        if h and h in seen:
            collapsed.append((seen[h], row["File"]))
            continue
        if h:
            seen[h] = row["File"]
        unique.append(row)
    if collapsed:
        log.warning(f"{len(collapsed)} righe del CSV sono duplicati per CONTENUTO (stesso sha256, "
                    f"nome diverso): escluse dal conteggio, si misura il binario non il nome.")
        for keep, drop in collapsed[:10]:
            log.warning(f"    {drop}  ==  {keep}")
    return unique, unresolved


def confusion(rows, manifest):
    """Matrice di confusione sul solo sottoinsieme etichettato."""
    tp = fp = tn = fn = 0
    unlabeled = unmatched = 0
    errors = {"fp": [], "fn": []}
    for row in rows:
        entry = manifest.get(row["_hash"]) if row["_hash"] else None
        if entry is None:
            unmatched += 1
            continue
        if entry["label"] not in ("packed", "clean"):
            unlabeled += 1
            continue
        predicted = row["Is_Packed_Label"] == "1"
        actual = entry["label"] == "packed"
        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
            errors["fp"].append((entry["filename"], row["Strong_Signals"] or row["Weak_Signals"]))
        elif not predicted and actual:
            fn += 1
            errors["fn"].append((entry["filename"], ", ".join(entry["packers"]) or "?"))
        else:
            tn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "unlabeled": unlabeled, "unmatched": unmatched, "errors": errors}


def metrics(cm):
    tp, fp, fn, tn = cm["tp"], cm["fp"], cm["fn"], cm["tn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / (tp + tn + fp + fn) if tp + tn + fp + fn else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy,
            "support": tp + tn + fp + fn}


def signal_discrimination(rows, manifest):
    """Per ogni classe di segnale: frequenza nei packed e nei clean."""
    counts = defaultdict(lambda: {"packed": 0, "clean": 0, "kind": ""})
    totals = {"packed": 0, "clean": 0}
    for row in rows:
        entry = manifest.get(row["_hash"]) if row["_hash"] else None
        if entry is None or entry["label"] not in ("packed", "clean"):
            continue
        label = entry["label"]
        totals[label] += 1
        for kind, column in (("forte", "Strong_Signals"), ("debole", "Weak_Signals"),
                             ("info", "Info_Signals")):
            for raw in split_signals(row.get(column, "")):
                key = normalize_signal(raw)
                counts[key][label] += 1
                counts[key]["kind"] = kind
    out = []
    for key, c in counts.items():
        p = 100.0 * c["packed"] / totals["packed"] if totals["packed"] else 0.0
        n = 100.0 * c["clean"] / totals["clean"] if totals["clean"] else 0.0
        out.append({"signal": key, "kind": c["kind"], "packed_pct": p, "clean_pct": n,
                    "packed_n": c["packed"], "clean_n": c["clean"], "lift": p - n})
    out.sort(key=lambda d: -d["lift"])
    return out, totals


def threshold_sweep(rows, manifest, lo=1, hi=6):
    """Ricalcola l'esito al variare di WEAK_SIGNALS_REQUIRED, tenendo i segnali
    forti come sono. Mostra il prezzo in FP di ogni TP guadagnato."""
    sweep = []
    for k in range(lo, hi + 1):
        tp = fp = tn = fn = 0
        for row in rows:
            entry = manifest.get(row["_hash"]) if row["_hash"] else None
            if entry is None or entry["label"] not in ("packed", "clean"):
                continue
            strong = bool(split_signals(row.get("Strong_Signals", "")))
            n_weak = len(split_signals(row.get("Weak_Signals", "")))
            predicted = strong or n_weak >= k
            actual = entry["label"] == "packed"
            if predicted and actual:
                tp += 1
            elif predicted and not actual:
                fp += 1
            elif not predicted and actual:
                fn += 1
            else:
                tn += 1
        cm = {"tp": tp, "fp": fp, "tn": tn, "fn": fn}
        m = metrics(cm)
        sweep.append({"weak_required": k, **cm, **m})
    return sweep


def determinism_exposure(rows):
    """Quante righe sono state decise con almeno un tool troncato da un timeout."""
    exposed, detail = 0, Counter()
    for row in rows:
        states = {row.get("Capa_Status", ""), row.get("Die_Status", ""), row.get("Yara_Status", "")}
        hit = states & TRUNCATED_STATES
        if hit:
            exposed += 1
            detail.update(hit)
    return exposed, dict(detail)


def render(report):
    """Markdown citabile in tesi."""
    L = []
    a = L.append
    a("# Validazione Fase 1\n")
    a(f"- CSV: `{report['csv']}`")
    a(f"- Manifest: `{report['manifest']}`")
    a(f"- Righe nel CSV: **{report['n_rows']}**")
    a(f"- Righe agganciate al manifest: **{report['matched']}**"
      f" (non agganciate: {report['cm']['unmatched']}, hash non risolto: {report['unresolved']})")
    a(f"- Righe utilizzabili per le metriche: **{report['metrics']['support']}**"
      f" (label `unknown`, escluse: {report['cm']['unlabeled']})\n")

    if not report["metrics"]["support"]:
        a("> **Nessuna riga etichettata.** Le metriche non sono calcolabili: popolare il")
        a("> manifest con `build_ground_truth.py` prima di interpretare qualsiasi numero.\n")
        return "\n".join(L)

    cm, m = report["cm"], report["metrics"]
    a("## Matrice di confusione\n")
    a("| | predetto packed | predetto clean |")
    a("|---|---|---|")
    a(f"| **reale packed** | TP = {cm['tp']} | FN = {cm['fn']} |")
    a(f"| **reale clean**  | FP = {cm['fp']} | TN = {cm['tn']} |\n")
    # Una metrica calcolata su una classe con supporto ZERO non vale 1.000: e'
    # indefinita. Stamparla come 1.000 sarebbe esattamente l'errore che questo
    # harness esiste per impedire (un FP e' impossibile se nessuna riga e'
    # etichettata 'clean', quindi la precision non misura nulla).
    n_clean = cm["tn"] + cm["fp"]
    n_packed = cm["tp"] + cm["fn"]
    both = n_clean and n_packed
    prec = f"**{m['precision']:.3f}**" if n_clean else "_non calcolabile_"
    rec = f"**{m['recall']:.3f}**" if n_packed else "_non calcolabile_"
    f1 = f"**{m['f1']:.3f}**" if both else "_non calcolabile_"
    acc = f"**{m['accuracy']:.3f}**" if both else "_non calcolabile_"
    a(f"- Supporto etichettato: {n_packed} packed, {n_clean} clean")
    a(f"- Precision: {prec} | Recall: {rec} | F1: {f1} | Accuracy: {acc}\n")
    if not n_clean:
        a("> **Nessuna riga etichettata `clean`.** Precision e accuracy non sono")
        a("> calcolabili: un falso positivo e' impossibile per costruzione. Il recall")
        a("> qui sopra vale solo sul sottoinsieme verificato e non dice nulla sul tasso")
        a("> di falsi positivi, che resta la meta' non misurata della valutazione.\n")
    if not n_packed:
        a("> **Nessuna riga etichettata `packed`.** Il recall non e' calcolabile.\n")

    if cm["errors"]["fn"]:
        a("### Falsi negativi (packer non intercettati)\n")
        for name, packers in cm["errors"]["fn"]:
            a(f"- `{name}` — packer reale: {packers}")
        a("")
    if cm["errors"]["fp"]:
        a("### Falsi positivi\n")
        for name, why in cm["errors"]["fp"]:
            a(f"- `{name}` — segnali: {why[:150]}")
        a("")

    a("## Discriminazione per segnale\n")
    a(f"Su {report['totals']['packed']} packed e {report['totals']['clean']} clean etichettati.\n")
    if not report["totals"]["clean"]:
        a("> Senza campioni `clean` la colonna *clean* e' vuota per costruzione e il")
        a("> *lift* coincide con la frequenza nei packed: la tabella dice quali segnali")
        a("> **coprono** i packed, non quali li **discriminano**.\n")
    a("| segnale | tipo | packed | clean | lift |")
    a("|---|---|---|---|---|")
    for s in report["signals"]:
        a(f"| {s['signal']} | {s['kind']} | {s['packed_pct']:.0f}% ({s['packed_n']}) | "
          f"{s['clean_pct']:.0f}% ({s['clean_n']}) | {s['lift']:+.0f} |")
    a("")

    a("## Sweep di WEAK_SIGNALS_REQUIRED\n")
    a("| soglia | TP | FP | FN | TN | precision | recall | F1 |")
    a("|---|---|---|---|---|---|---|---|")
    for s in report["sweep"]:
        mark = " **(attuale)**" if s["weak_required"] == report["current_weak_required"] else ""
        a(f"| {s['weak_required']}{mark} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} | "
          f"{s['precision']:.3f} | {s['recall']:.3f} | {s['f1']:.3f} |")
    a("")

    a("## Esposizione al non determinismo\n")
    exposed, detail = report["determinism"]["exposed"], report["determinism"]["detail"]
    a(f"Righe decise con almeno un tool troncato da un timeout o da una finestra di "
      f"sondaggio scaduta: **{exposed} / {report['n_rows']}**"
      f" ({100.0 * exposed / report['n_rows']:.0f}%).\n")
    if detail:
        a("| stato troncato | righe |")
        a("|---|---|")
        for k, v in sorted(detail.items(), key=lambda kv: -kv[1]):
            a(f"| {k} | {v} |")
        a("")
        a("> Queste classificazioni dipendono dal carico della macchina, non solo dal")
        a("> binario: vanno dichiarate come limite di riproducibilita' dell'esperimento.\n")
    return "\n".join(L)


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", default=DEFAULT_CSV)
    parser.add_argument("--manifest", default=DEFAULT_MANIFEST)
    parser.add_argument("--resolve-dir", action="append", default=[],
                        help="Cartella in cui cercare i file per ricalcolarne l'hash (ripetibile).")
    parser.add_argument("--out-md", default=REPORT_MD)
    parser.add_argument("--out-json", default=REPORT_JSON)
    args = parser.parse_args()

    if not os.path.exists(args.manifest):
        log.error(f"Manifest non trovato: {args.manifest}")
        log.error("Crealo con: python scripts/build_ground_truth.py --scan <dir> --dataset <nome>")
        raise SystemExit(2)
    with open(args.manifest, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    rows, unresolved = load_rows(args.csv, args.resolve_dir)
    cm = confusion(rows, manifest)
    sigs, totals = signal_discrimination(rows, manifest)
    exposed, detail = determinism_exposure(rows)

    try:
        import header_elf_lief as HL
        current_weak = HL.WEAK_SIGNALS_REQUIRED
    except Exception:
        current_weak = None

    report = {
        "csv": args.csv, "manifest": args.manifest,
        "n_rows": len(rows), "unresolved": unresolved,
        "matched": len(rows) - cm["unmatched"],
        "cm": cm, "metrics": metrics(cm), "signals": sigs, "totals": totals,
        "sweep": threshold_sweep(rows, manifest),
        "current_weak_required": current_weak,
        "determinism": {"exposed": exposed, "detail": detail},
    }

    markdown = render(report)
    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write(markdown)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(markdown)
    log.info(f"Report scritti: {args.out_md} | {args.out_json}")


if __name__ == "__main__":
    main()
