"""
score_fase_f_livello2.py
========================
Punteggia il LIVELLO 2 della Fase F: i campioni esterni per cui l'originale
pulito **non esiste**, quindi `validate_phase2.py` non e' applicabile.

L'esito si chiama `plausibile` e MAI `ricostruito`
--------------------------------------------------
Questo script misura plausibilita', non correttezza. Il numero che produce non
va sommato al livello 1 ne' messo nella sua stessa tabella, e in tesi non va
scritto come tasso di ricostruzione (`docs/07`, §3.3 e §11).

Le quattro condizioni, e perche' servono tutte
----------------------------------------------
Definite nel protocollo PRIMA del run, al §3.3. Devono valere **tutte**:

  1. la sezione che contiene l'entry point non e' a zeri (non-zero >= 5%);
  2. l'entropia massima di sezione scende sotto la soglia della Fase 1 (7.2);
  3. Ghidra headless trova almeno 5 funzioni;
  4. rieseguendo la Fase 1 sull'output, `Is_Packed_Label` passa da 1 a 0.

Nessuna basta da sola. La 3 da sola e' **esattamente** il criterio che in Fase B
aveva promosso 5 installer Inno con il 2,6% di corrispondenza. La 4 e'
parzialmente circolare - e' lo stesso rilevatore che aveva detto "packed" - e
per questo non basta nemmeno insieme alla 3.

Da dove vengono i dati
----------------------
Tre su quattro esistono gia' e non si ricalcolano:

  cond. 2 e 4  <- il CSV di Fase 1 rieseguita sugli output (--phase1-csv),
                  colonne `Max_Section_Entropy` e `Is_Packed_Label`;
  cond. 3      <- `ghidra_func_count` in pipeline_state.json;
  cond. 1      <- calcolata qui, e' l'unica che manca.

Il join col CSV di Fase 1 avviene **per SHA-256**, non per nome: 7-Zip estrae in
sottocartelle e due output possono avere lo stesso basename.

Le soglie si rileggono dal codice congelato
-------------------------------------------
Non sono riscritte a mano. Il protocollo (§9) vieta di ritarare dopo aver visto
i risultati, e una costante copiata e' una costante che prima o poi divergera':
qui si leggono da `subprocesses.py` e `validate_phase2.py`, e se non si trovano
lo script si ferma.

Uso
---
    python scripts/score_fase_f_livello2.py --selftest

    # 1. Fase 1 sugli output della cascata (serve per le condizioni 2 e 4)
    python scripts/parameters_info.py --dir UNPACKED_SAMPLES --phase1-only

    # 2. punteggio
    python scripts/score_fase_f_livello2.py ^
        --phase1-csv Pipeline_Reports/report_analisi_lief.csv ^
        --out-md  Pipeline_Reports/validation_fase_f_livello2.md ^
        --out-csv Pipeline_Reports/validation_fase_f_livello2.csv
"""
import argparse
import csv
import json
import os
import re
import sys
from collections import Counter, defaultdict

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger, compute_file_hash, OUTPUT_DIR  # noqa: E402

log = setup_logger("FaseF-Liv2")

REPO = os.path.dirname(SCRIPT_DIR)
STATE = os.path.join(OUTPUT_DIR, "pipeline_state.json")
COPPIE = os.path.join(REPO, "config", "fase_f_coppie.csv")

# I dataset esterni del §2 del protocollo. v1_misto compare con questo nome solo
# dopo che parameters_info.py ha girato su quella cartella.
DATASET_ESTERNI = ["v1_misto", "wild_malwarebazaar", "malware_reali",
                   "legacy_misto", "pma_book"]


def _soglia(sorgente, nome, cast=float):
    """Rilegge una soglia dal codice congelato invece di ricopiarla."""
    path = os.path.join(SCRIPT_DIR, sorgente)
    with open(path, encoding="utf-8") as f:
        src = f.read()
    m = re.search(r"^%s\s*=\s*([0-9.]+)" % re.escape(nome), src, re.MULTILINE)
    assert m, f"soglia {nome} non trovata in {sorgente}: il codice e' cambiato"
    return cast(m.group(1))


NONZERO_MIN = _soglia("validate_phase2.py", "NONZERO_MIN")
ENTROPY_MAX = _soglia("subprocesses.py", "MULTILAYER_ENTROPY_THRESHOLD")
MIN_FUNCS = _soglia("subprocesses.py", "MIN_FUNCTIONS_THRESHOLD", int)

CONDIZIONI = ["ep_non_a_zeri", "entropia_sotto_soglia", "ghidra_funzioni", "fase1_non_piu_packed"]


def frazione_nonzero_ep(path):
    """Frazione di byte non-zero nella sezione che contiene l'entry point.

    E' la condizione 1. Ritorna None se il file non e' leggibile come PE o se
    l'entry point cade fuori da ogni sezione: in quel caso il campione finisce
    `non_valutabile`, che non e' la stessa cosa di `non_plausibile`.
    """
    try:
        import pefile
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return None
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        for s in pe.sections:
            estensione = max(s.Misc_VirtualSize, s.SizeOfRawData)
            if s.VirtualAddress <= ep < s.VirtualAddress + estensione:
                dati = s.get_data()
                if not dati:
                    return 0.0
                return sum(1 for b in bytearray(dati) if b) / float(len(dati))
        return None
    except Exception:
        return None
    finally:
        pe.close()


def giudica(cond):
    """`plausibile` solo se tutte e quattro valgono. Un dato mancante non e' un no."""
    if any(cond.get(c) is None for c in CONDIZIONI):
        return "non_valutabile"
    return "plausibile" if all(cond[c] for c in CONDIZIONI) else "non_plausibile"


def indicizza_phase1(csv_path):
    """{sha256: riga} dal CSV di Fase 1 rieseguita sugli output."""
    idx = {}
    with open(csv_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            h = (row.get("SHA256") or "").strip().lower()
            if h:
                idx[h] = row
    return idx


def _num(valore):
    try:
        return float(valore)
    except (TypeError, ValueError):
        return None


def sha_nella_cartella(directory):
    """{sha256} dei file presenti in una cartella.

    Serve perche' il campo `dataset` dello stato NON e' affidabile: lo assegna
    un passo di indicizzazione separato (`make_dataset_index.py`), e sui 208
    campioni di v1_misto non e' girato, quindi valgono tutti None. Selezionare
    per etichetta avrebbe prodotto zero righe senza dirlo.
    """
    idx = set()
    for nome in os.listdir(directory):
        p = os.path.join(directory, nome)
        if os.path.isfile(p):
            h = compute_file_hash(p)
            if h:
                idx.add(h)
    return idx


def e_packed(sha, rec, phase1):
    """Il campione era etichettato packed dalla Fase 1?

    Tre fonti, in ordine di affidabilita', perche' lo stato NON e' una fonte
    completa: i record creati dalla Fase 2 contengono solo i campi `unpack_*`,
    mentre `is_packed`, `phase1_done` e `dataset` li scrive un passo di
    indicizzazione separato che su v1_misto non e' girato. Fidarsi del solo
    `is_packed` selezionava zero campioni su 208.
    """
    if rec.get("is_packed"):
        return True
    # la Fase 2 gira solo su cio' che la Fase 1 ha marcato packed: averlo
    # tentato e' prova sufficiente
    if rec.get("unpack_attempted"):
        return True
    riga = phase1.get(sha.lower())
    return bool(riga) and (riga.get("Is_Packed_Label") or "").strip() == "1"


def valuta(state, phase1, datasets, esclusi, selezione=None, etichetta=""):
    """Una riga di esito per campione esterno packed e non appartenente al livello 1.

    `selezione`: insieme di SHA-256 da misurare. Se dato, vince sul campo
    `dataset`, che puo' essere None.
    """
    out = []
    for sha, rec in state.items():
        if selezione is not None:
            if sha not in selezione:
                continue
        elif rec.get("dataset") not in datasets:
            continue
        if not e_packed(sha, rec, phase1):
            continue
        if sha in esclusi:
            continue  # sta nel livello 1, ha l'oracolo forte

        r = {"sha256": sha, "filename": rec.get("filename", ""),
             "dataset": rec.get("dataset") or etichetta,
             "method": rec.get("unpack_method") or "",
             "nonzero_ep": None, "entropia_max": None, "ghidra_funzioni": None,
             "is_packed_dopo": None, "esito": None, "nota": ""}
        for c in CONDIZIONI:
            r[c] = None

        if not rec.get("unpack_attempted"):
            r["esito"] = "non_processato"
            out.append(r)
            continue

        unp = rec.get("unpack_output")
        if not unp or not os.path.exists(unp):
            r["esito"] = "non_plausibile"
            r["nota"] = "nessun output prodotto" if not unp else "output non piu' su disco"
            out.append(r)
            continue

        # condizione 1 — calcolata qui
        nz = frazione_nonzero_ep(unp)
        r["nonzero_ep"] = None if nz is None else round(nz, 4)
        r["ep_non_a_zeri"] = None if nz is None else nz >= NONZERO_MIN

        # condizione 3 — dallo stato
        nfun = rec.get("ghidra_func_count")
        r["ghidra_funzioni"] = None if nfun is None else int(nfun) >= MIN_FUNCS
        r["ghidra_funzioni_n"] = nfun

        # condizioni 2 e 4 — dal CSV di Fase 1 sugli output, join per hash
        h = compute_file_hash(unp)
        p1 = phase1.get((h or "").lower())
        if p1 is None:
            r["nota"] = ("output assente dal CSV di Fase 1: la Fase 1 e' stata rieseguita "
                         "sugli output?")
        else:
            ent = _num(p1.get("Max_Section_Entropy"))
            r["entropia_max"] = ent
            r["entropia_sotto_soglia"] = None if ent is None else ent < ENTROPY_MAX
            lab = (p1.get("Is_Packed_Label") or "").strip()
            if lab in ("0", "1"):
                r["is_packed_dopo"] = int(lab)
                r["fase1_non_piu_packed"] = (lab == "0")

        r["esito"] = giudica(r)
        out.append(r)
    return out


def render(righe):
    L = []
    a = L.append
    a("# Fase F, livello 2 — criterio proxy, NON correttezza\n")
    a("> I campioni di questa tabella **non hanno un originale pulito**: l'esito `plausibile`")
    a("> dice che l'output supera quattro controlli definiti prima del run, non che il payload")
    a("> ricostruito sia corretto. **Non si somma al livello 1 e non va nella sua tabella.**\n")
    a(f"- condizione 1: byte non-zero nella sezione dell'entry point >= {NONZERO_MIN:.0%}")
    a(f"- condizione 2: entropia massima di sezione < {ENTROPY_MAX}")
    a(f"- condizione 3: Ghidra >= {MIN_FUNCS} funzioni")
    a("- condizione 4: Fase 1 rieseguita sull'output, `Is_Packed_Label` da 1 a 0")
    a("\nServono tutte e quattro. Soglie rilette dal codice congelato, non ricopiate.\n")

    stati = sorted({r["esito"] for r in righe})
    per_ds = defaultdict(Counter)
    for r in righe:
        per_ds[r["dataset"]][r["esito"]] += 1

    a("## Per dataset — criterio proxy, non correttezza\n")
    a("| dataset | campioni | " + " | ".join(stati) + " |")
    a("|---|---|" + "---|" * len(stati))
    tot = Counter()
    for ds in sorted(per_ds):
        c = per_ds[ds]
        n = sum(c.values())
        tot.update(c)
        a(f"| {ds} | {n} | " + " | ".join(str(c[s]) for s in stati) + " |")
    ntot = sum(tot.values())
    a(f"| **totale** | **{ntot}** | " + " | ".join(f"**{tot[s]}**" for s in stati) + " |\n")

    # Tre numeri, sempre tutti e tre. Un campione senza output finisce in
    # `non_plausibile` - correttamente, perche' per l'analista resta sul tavolo -
    # ma sommarlo ai valutati produce l'affermazione falsa "output prodotto per
    # N su N". Copertura e plausibilita' sono informazioni diverse.
    senza_output = sum(1 for r in righe
                       if r["nota"].startswith(("nessun output", "output non piu'")))
    valutabili = sum(1 for r in righe if r["esito"] in ("plausibile", "non_plausibile")
                     and not r["nota"].startswith(("nessun output", "output non piu'")))
    if valutabili:
        a(f"**Plausibili: {tot['plausibile']}/{valutabili} = "
          f"{tot['plausibile']/valutabili:.0%} dei campioni con un output** — criterio proxy, "
          "non correttezza.")
    else:
        a("**Nessun campione valutabile**: la cascata non ha prodotto output per nessuno.")
    if ntot:
        a(f"\nCopertura, che e' un numero diverso: la cascata ha prodotto un output "
          f"valutabile per **{valutabili} dei {ntot}** campioni ({valutabili/ntot:.0%}). "
          f"{senza_output} non hanno prodotto alcun output e {tot['non_processato']} non sono "
          "stati processati; entrambi restano sul tavolo dell'analista, quindi sul totale i "
          f"plausibili sono {tot['plausibile']}/{ntot} = {tot['plausibile']/ntot:.0%}.\n")

    a("## Quale condizione non regge\n")
    a("Solo sui campioni effettivamente valutati: dice dove si ferma la cascata.\n")
    valutati = [r for r in righe if r["esito"] in ("plausibile", "non_plausibile")]
    a("| condizione | soddisfatta | non soddisfatta |")
    a("|---|---|---|")
    for c in CONDIZIONI:
        si = sum(1 for r in valutati if r.get(c) is True)
        no = sum(1 for r in valutati if r.get(c) is False)
        a(f"| {c} | {si} | {no} |")
    a("")

    a("## Per strumento\n")
    per_tool = defaultdict(Counter)
    for r in righe:
        per_tool[r["method"] or "(nessuno)"][r["esito"]] += 1
    a("| strumento | " + " | ".join(stati) + " |")
    a("|---|" + "---|" * len(stati))
    for t in sorted(per_tool):
        c = per_tool[t]
        a(f"| {t} | " + " | ".join(str(c[s]) for s in stati) + " |")
    a("")
    return "\n".join(L)


def selftest():
    """La logica delle quattro condizioni, senza campioni e senza disco."""
    tutte = {c: True for c in CONDIZIONI}
    assert giudica(tutte) == "plausibile"

    # ognuna, da sola, deve poter bocciare: nessuna e' decorativa
    for c in CONDIZIONI:
        d = dict(tutte, **{c: False})
        assert giudica(d) == "non_plausibile", f"{c} non incide sul giudizio"

    # il criterio che in Fase B promosse 5 falsi successi non deve bastare
    solo_ghidra = {c: False for c in CONDIZIONI}
    solo_ghidra["ghidra_funzioni"] = True
    assert giudica(solo_ghidra) == "non_plausibile", "Ghidra da solo non deve bastare"

    # ne' Ghidra piu' la condizione circolare
    ghidra_e_fase1 = {c: False for c in CONDIZIONI}
    ghidra_e_fase1["ghidra_funzioni"] = True
    ghidra_e_fase1["fase1_non_piu_packed"] = True
    assert giudica(ghidra_e_fase1) == "non_plausibile", "3+4 non devono bastare"

    # un dato mancante non e' un no
    assert giudica(dict(tutte, entropia_sotto_soglia=None)) == "non_valutabile"

    # le soglie sono quelle del codice congelato
    assert NONZERO_MIN == 0.05, f"NONZERO_MIN cambiato: {NONZERO_MIN}"
    assert ENTROPY_MAX == 7.2, f"soglia entropia cambiata: {ENTROPY_MAX}"
    assert MIN_FUNCS == 5, f"MIN_FUNCTIONS_THRESHOLD cambiato: {MIN_FUNCS}"

    # la sezione a zeri deve risultare sotto soglia, non sopra
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "zeri.bin")
        with open(p, "wb") as f:
            f.write(b"\x00" * 4096)
        assert frazione_nonzero_ep(p) is None, "un non-PE deve dare None, non 0 o 1"

    # Regressione: un campione con `dataset` assente DEVE essere selezionato se il
    # suo hash e' nella selezione. Selezionare per etichetta dava zero righe in
    # silenzio su tutti i 208 campioni di v1_misto.
    finto = {"aa" * 32: {"filename": "x.exe", "dataset": None, "is_packed": True},
             "bb" * 32: {"filename": "y.exe", "dataset": "altro", "is_packed": True}}
    r = valuta(finto, {}, {"v1_misto"}, set(), selezione={"aa" * 32}, etichetta="v1_misto")
    assert len(r) == 1 and r[0]["filename"] == "x.exe", \
        "la selezione per cartella non ignora il campo dataset"
    assert r[0]["dataset"] == "v1_misto", "l'etichetta di ripiego non viene applicata"
    assert r[0]["esito"] == "non_processato", "senza unpack_attempted l'esito non e' quello"
    # e senza selezione deve tornare a filtrare per etichetta
    r2 = valuta(finto, {}, {"altro"}, set())
    assert len(r2) == 1 and r2[0]["filename"] == "y.exe", "il filtro per etichetta e' rotto"

    # Regressione: un record scritto dalla sola Fase 2 non ha is_packed ne' dataset.
    # Fidarsi di is_packed selezionava zero campioni su 208 senza dirlo.
    solo_f2 = {"cc" * 32: {"filename": "z.exe", "unpack_attempted": True}}
    assert e_packed("cc" * 32, solo_f2["cc" * 32], {}), \
        "un record con solo unpack_attempted deve contare come packed"
    assert len(valuta(solo_f2, {}, set(), set(), selezione={"cc" * 32})) == 1, \
        "il campione con solo i campi di Fase 2 non viene selezionato"
    # terza fonte: l'etichetta dal CSV di Fase 1
    nudo = {"dd" * 32: {"filename": "w.exe"}}
    assert e_packed("dd" * 32, nudo["dd" * 32], {"dd" * 32: {"Is_Packed_Label": "1"}}), \
        "l'etichetta dal CSV di Fase 1 non viene letta"
    assert not e_packed("dd" * 32, nudo["dd" * 32], {"dd" * 32: {"Is_Packed_Label": "0"}}), \
        "un file non packed viene selezionato comunque"

    print("selftest: ok (%d controlli)" % (4 + len(CONDIZIONI) + 5 + 5 + 4))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--state", default=STATE)
    p.add_argument("--phase1-csv", default=os.path.join(OUTPUT_DIR, "report_analisi_lief.csv"),
                   help="CSV di Fase 1 RIESEGUITA sugli output della cascata (condizioni 2 e 4).")
    p.add_argument("--coppie", default=COPPIE,
                   help="le 29 coppie del livello 1, da escludere da questa misura.")
    p.add_argument("--datasets", nargs="+", default=DATASET_ESTERNI,
                   help="selezione per etichetta `dataset`. Usare --dir quando l'etichetta "
                        "manca, che e' il caso di v1_misto.")
    p.add_argument("--dir", dest="cartella",
                   help="seleziona i campioni per APPARTENENZA a questa cartella, via SHA-256. "
                        "Piu' robusto di --datasets: il campo `dataset` nello stato lo assegna "
                        "un passo di indicizzazione separato e puo' essere assente.")
    p.add_argument("--label", default="",
                   help="nome del corpus nel report, quando lo stato non ha l'etichetta.")
    p.add_argument("--out-md", default=os.path.join(OUTPUT_DIR, "validation_fase_f_livello2.md"))
    p.add_argument("--out-csv", default=os.path.join(OUTPUT_DIR, "validation_fase_f_livello2.csv"))
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()

    if args.selftest:
        selftest()
        return 0

    with open(args.state, encoding="utf-8") as f:
        state = json.load(f)
    log.info(f"{len(state)} record nello stato.")

    esclusi = set()
    if os.path.exists(args.coppie):
        with open(args.coppie, encoding="utf-8") as f:
            esclusi = {r["packed_sha256"] for r in csv.DictReader(f)}
    log.info(f"{len(esclusi)} campioni esclusi perche' appartengono al livello 1.")

    phase1 = {}
    if os.path.exists(args.phase1_csv):
        phase1 = indicizza_phase1(args.phase1_csv)
        log.info(f"{len(phase1)} file nel CSV di Fase 1.")
    else:
        log.error(f"CSV di Fase 1 assente: {args.phase1_csv}")
        log.error("Le condizioni 2 e 4 non sono valutabili: tutto finira' 'non_valutabile'.")

    selezione = None
    etichetta = args.label
    if args.cartella:
        selezione = sha_nella_cartella(args.cartella)
        etichetta = etichetta or os.path.basename(os.path.normpath(args.cartella))
        log.info(f"{len(selezione)} file nella cartella {args.cartella}; "
                 f"corpus etichettato '{etichetta}'.")

    righe = valuta(state, phase1, set(args.datasets), esclusi, selezione, etichetta)
    if not righe:
        quale = args.cartella if args.cartella else args.datasets
        log.error(f"nessun campione packed selezionato da {quale}: "
                  "la Fase 1 e' stata eseguita su quella cartella?")
        return 1

    campi = (["sha256", "filename", "dataset", "method", "esito"] + CONDIZIONI
             + ["nonzero_ep", "entropia_max", "ghidra_funzioni_n", "is_packed_dopo", "nota"])
    with open(args.out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campi, extrasaction="ignore")
        w.writeheader()
        w.writerows(righe)

    md = render(righe)
    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write(md)
    print(md)
    log.info(f"Report scritti: {args.out_md} | {args.out_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
