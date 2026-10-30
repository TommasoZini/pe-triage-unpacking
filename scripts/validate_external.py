"""
validate_external.py
====================
Misura la Fase 1 contro `packing-box/dataset-packed-pe`, secondo il protocollo firmato
PRIMA del run in `docs/05_protocollo_validazione_esterna.md`.

Perche' NON produce precision, F1 o accuracy
--------------------------------------------
La meta' `not-packed/` di quel dataset **non e' un oracolo**, e il protocollo lo vieta
esplicitamente (§3.2). Tre motivi, in ordine di forza:

  1. vale la regola di `build_ground_truth.py`: una scansione non puo' dichiarare
     "non packed";
  2. il fork **ammette di aver rimosso da quella cartella campioni compressi con UPX**:
     la cartella conteneva file compressi, e chi l'ha costruita ha assunto che
     freeware scaricato = non compresso;
  3. per ripulirla sono stati usati rilevatori della **stessa famiglia dei nostri**
     (PEiD reimplementato, Bintropy, PyPackerDetect, REMINDer). I casi difficili sono
     gia' stati tolti: misurare FP = 0 la' sarebbe in parte una **tautologia**, e un
     bias ottimistico, cioe' il tipo che in tesi fa piu' danno.

Si produce quindi **una sola riga di matrice** - TP e FN sulla meta' packed - e si
scrive che e' una sola.

Cosa produce invece
-------------------
  - recall per famiglia, con l'evidenza scomposta (named / structural / weak_only);
  - il **recall `structural`-only**: questo dataset e' pubblico da anni ed e' il corpus
    di addestramento del progetto packing-box, quindi non si puo' escludere che parte
    dei match `named` venga da firme scritte conoscendolo (§6.4). Il numero che non usa
    nomi e' immune a quella contaminazione per costruzione;
  - il taglio fra famiglie **coperte** e **scoperte** da `PACKER_SECTION_PREFIXES`:
    sulle scoperte il verdetto puo' venire solo da una firma di terzi o dai segnali
    strutturali, ed e' il test diretto di cio' che la tesi rivendica (§6.3);
  - i file **non analizzabili** (magic non valido) contati a parte, mai come FN (§9.2).

Uso
---
    python scripts/validate_external.py
    python scripts/validate_external.py --key <chiave.csv> --dataset a,b
"""
import argparse
import collections
import csv
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger, OUTPUT_DIR  # noqa: E402

log = setup_logger("ValidateExt")

CSV_PATH = os.path.join(OUTPUT_DIR, "report_analisi_lief.csv")
BASE = os.path.join("E:" + os.sep, "DATASET", "04_VALIDAZIONE_ESTERNA")
# v3 = v2 (riprodotta riga per riga da make_external_key.py) + i 152 campioni della
# cartella `outliers/` del dataset, che erano fuori da ogni misura. `v2_chiave.csv`
# resta sul disco come record del run firmato del 28/09/2026.
DEFAULT_KEY = os.path.join(BASE, "v3_chiave.csv")

# Divisione dichiarata PRIMA del run (protocollo §5): in calibrazione le 3 famiglie gia'
# presenti nella matrice in casa, piu' due casi attesi come difficili e strutturalmente
# diversi fra loro - FSG (PE minimali, contiene i 2 file rotti) e Molebox (impacchetta
# invece di comprimere).
CALIBRAZIONE = {"UPX", "MPRESS", "Themida", "FSG", "Molebox"}

# Lista A PRIORI del protocollo §6.3: famiglie che dovrebbero avere una riga in
# PACKER_SECTION_PREFIXES. Viene confrontata con la copertura MISURATA (sotto), perche'
# dedurla dal nome della famiglia non e' affidabile: Enigma Virtual Box produce .enigma1,
# RLPack produce .packed - entrambe coperte - mentre NSPack e PECompact in questo dataset
# non producono le sezioni attese.
COPERTE_A_PRIORI = {"UPX", "MPRESS", "Themida", "ASPack", "NSPack", "PECompact", "PEtite"}


def coperte_misurate(packed_ok, chiave, soglia=0.5):
    """Famiglie in cui il segnale 'sezione tipica di packer' scatta su piu' della soglia
    dei campioni. E' la copertura reale, non quella dedotta dal nome."""
    import collections as _c
    agg = _c.defaultdict(lambda: [0, 0])
    for r in packed_ok:
        f = chiave[r["SHA256"]]["famiglia"] or "?"
        agg[f][0] += 1
        if "sezione tipica di packer" in r["Strong_Signals"]:
            agg[f][1] += 1
    return {f for f, (tot, sez) in agg.items() if tot and sez / tot > soglia}

ALIAS = {
    "enigmavirtualbox": ("enigma",),
    "yodacrypter": ("yoda",),
    "yodaprotector": ("yoda",),
    "eronanapacker": ("eronana",),
    "beroexepacker": ("bero",),
    "winupack": ("upack",),
    "telock": ("telock",),
    "petite": ("petite",),
}


def _norm(s):
    return (s or "").lower().replace(" ", "").replace("-", "").replace("_", "") \
                           .replace("(", "").replace(")", "").replace("'", "")


def die_nomina_atteso(r, famiglia):
    """DIE nomina proprio quel packer? Confronto tollerante: i nomi del dataset e quelli
    di DIE non coincidono alla lettera (PEtite/Petite, WinUpack/(Win)Upack, TELock/tElock)."""
    testo = _norm(r.get("Die_All_Packers", "") + " " + r.get("Die_Packer_Name", ""))
    chiave = _norm(famiglia)
    if chiave and chiave in testo:
        return True
    return any(a in testo for a in ALIAS.get(chiave, ()))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--key", default=DEFAULT_KEY, help=f"CSV con la chiave (default: {DEFAULT_KEY}).")
    ap.add_argument("--out", default=None, help="File Markdown di output.")
    args = ap.parse_args()

    if not os.path.isfile(args.key):
        sys.exit(f"Chiave non trovata: {args.key}")
    chiave = {r["sha256"]: r for r in csv.DictReader(open(args.key, encoding="utf-8"))}
    # Si sceglie per APPARTENENZA ALLA CHIAVE: la colonna Dataset registra il run di PRIMA
    # analisi, non l'insieme, e filtrandola uscivano 4 binari gia' visti come `legacy_misto`.
    rows = [r for r in csv.DictReader(open(CSV_PATH, encoding="utf-8")) if r["SHA256"] in chiave]
    if not rows:
        sys.exit(f"Nessuna riga di {CSV_PATH} combacia con la chiave {args.key}.")

    # dedup per CONTENUTO: l'unita' di misura e' il binario, non il nome (protocollo §3.4)
    visti, unici = set(), []
    for r in rows:
        if r["SHA256"] in visti:
            continue
        visti.add(r["SHA256"])
        unici.append(r)
    collassi = len(rows) - len(unici)
    rows = unici
    mancanti = len(chiave) - len(rows)
    provenienze = collections.Counter(r["Dataset"] for r in rows)
    log.info(f"{len(rows)}/{len(chiave)} voci della chiave agganciate "
             f"({collassi} duplicati per contenuto, {mancanti} mai analizzate)")

    packed = [r for r in rows if chiave[r["SHA256"]]["vera_label"] == "packed"]
    notpacked = [r for r in rows if chiave[r["SHA256"]]["vera_label"] != "packed"]

    # non analizzabili: fuori perimetro, MAI falsi negativi (protocollo §9.2)
    inan = [r for r in packed if r.get("Parse_Status") == "not_executable"]
    packed_ok = [r for r in packed if r.get("Parse_Status") != "not_executable"]
    tp = [r for r in packed_ok if r["Is_Packed_Label"] == "1"]
    fn = [r for r in packed_ok if r["Is_Packed_Label"] != "1"]

    COPERTE_DA_SEZIONE = coperte_misurate(packed_ok, chiave)

    fam = collections.defaultdict(collections.Counter)
    for r in packed_ok:
        f = chiave[r["SHA256"]]["famiglia"] or "?"
        c = fam[f]
        c["tot"] += 1
        if r["Is_Packed_Label"] == "1":
            c["ok"] += 1
            c[r.get("Packing_Evidence") or "none"] += 1
        if die_nomina_atteso(r, f):
            c["die"] += 1

    L = []
    A = L.append
    A("# Validazione esterna — `packing-box/dataset-packed-pe`")
    A("")
    A("Prodotta da `scripts/validate_external.py` secondo il protocollo firmato **prima** del run,")
    A("in `docs/05_protocollo_validazione_esterna.md`.")
    A("")
    A(f"- chiave di risposta: `{args.key}`")
    A(f"- voci della chiave: **{len(chiave)}**, agganciate a una riga del CSV: "
      f"**{len(rows)}**, mai analizzate: **{mancanti}**")
    A(f"- di cui {len(packed)} `packed` e {len(notpacked)} `not-packed`")
    A(f"- provenienza delle righe (colonna `Dataset` = run di PRIMA analisi, non appartenenza "
      f"all'insieme): " + ", ".join(f"`{k}` {n}" for k, n in provenienze.most_common()))
    A(f"- duplicati per contenuto collassati: {collassi}")
    A(f"- non analizzabili (magic non valido, fuori perimetro): **{len(inan)}**")
    A(f"- supporto reale della misura: **{len(packed_ok)}**")
    A("")
    A("## Una sola riga di matrice")
    A("")
    A("> La metà `not-packed` di questo dataset **non è un oracolo**, e il protocollo (§3.2) vieta")
    A("> di calcolarne precision, tasso di falsi positivi, accuracy o F1: è stata ripulita con")
    A("> rilevatori della stessa famiglia dei nostri, quindi misurare FP = 0 là sarebbe in parte")
    A("> una tautologia. Si riporta **una sola riga**, e si scrive che è una sola.")
    A("")
    A("| | predetto packed | predetto clean |")
    A("|---|---|---|")
    A(f"| **reale packed** ({len(packed_ok)}) | **TP = {len(tp)}** | **FN = {len(fn)}** |")
    A("")
    rec = len(tp) / len(packed_ok) if packed_ok else 0.0
    A(f"**Recall {rec:.4f}** — {len(tp)} su {len(packed_ok)}.")
    A("")

    # --- gli outliers del dataset, separati ---------------------------------------
    # Il README del dataset li descrive come i campioni "potentially disturbing our
    # models ... sorted among the not packed samples while demonstrating
    # characteristics of packed data": e' una selezione dei casi difficili fatta da
    # ALTRI, non da noi, ed e' il controllo piu' vicino a un test avversario che
    # questo corpus permette. Vanno mostrati a parte, altrimenti si diluiscono nei
    # 3.000 campioni facili e non dicono nulla.
    def _is_outlier(r):
        return chiave[r["SHA256"]]["origine"].startswith("outliers/")

    out_ok = [r for r in packed_ok if _is_outlier(r)]
    if out_ok:
        out_tp = [r for r in out_ok if r["Is_Packed_Label"] == "1"]
        base_ok = [r for r in packed_ok if not _is_outlier(r)]
        base_tp = [r for r in base_ok if r["Is_Packed_Label"] == "1"]
        ev = collections.Counter(r.get("Packing_Evidence") or "none" for r in out_tp)
        fam_out = collections.Counter(chiave[r["SHA256"]]["famiglia"] for r in out_ok)
        A("### La sottoparte `outliers/`, misurata a parte")
        A("")
        A("Il README del dataset descrive questi file come *\"samples we could identify as")
        A("potentially disturbing our models, i.e. when they were sorted among the not packed")
        A("samples while demonstrating characteristics of packed data\"*: sono i casi difficili")
        A("scelti da **altri**, non da noi, e non stanno ne\' in `packed/` ne\' in `not-packed/`")
        A("(sovrapposizione misurata: zero). Diluiti nel totale non direbbero niente, quindi")
        A("si riportano separati.")
        A("")
        A("| sottoinsieme | campioni | rilevati | recall |")
        A("|---|---|---|---|")
        A(f"| `packed/` (le cartelle principali) | {len(base_ok)} | {len(base_tp)} | "
          f"{len(base_tp) / max(len(base_ok), 1):.4f} |")
        A(f"| **`outliers/packed/`** | **{len(out_ok)}** | **{len(out_tp)}** | "
          f"**{len(out_tp) / max(len(out_ok), 1):.4f}** |")
        A("")
        A(f"Gli outliers coprono {len(fam_out)} delle famiglie gia' presenti — non ne aggiungono")
        A("di nuove, aggiungono gli esemplari piu' difficili di quelle. Evidenza sui rilevati: "
          + ", ".join(f"`{k}` {v}" for k, v in sorted(ev.items())) + ".")
        A("")

    so = [r for r in packed_ok
          if "DIE:" not in r["Strong_Signals"] and "YARA packer" not in r["Strong_Signals"]
          and "capa:" not in r["Strong_Signals"]]
    so_ok = [r for r in so if r["Is_Packed_Label"] == "1"]
    A("### Recall senza firme")
    A("")
    A("Questo dataset è pubblico da anni ed è il corpus di addestramento del progetto packing-box:")
    A("non si può escludere che parte dei match `named` venga da firme scritte conoscendolo (§6.4).")
    A("Il numero che segue **non usa nomi**, quindi è immune a quella contaminazione per costruzione.")
    A("")
    A(f"- campioni senza alcun segnale forte da firma: **{len(so)}**")
    A(f"- di questi, comunque segnalati packed: **{len(so_ok)}**")
    A("")

    A("## Recall per famiglia")
    A("")
    A("`cal` = calibrazione, `test` = gruppo di test (divisione dichiarata prima del run, §5).")
    A("`sez` = la famiglia ha una riga in `PACKER_SECTION_PREFIXES`.")
    A("")
    A("| famiglia | gruppo | sez | rilevati | campioni | named | struct | weak | DIE nomina |")
    A("|---|---|---|---|---|---|---|---|---|")
    for f in sorted(fam, key=lambda x: (fam[x]["ok"] / max(fam[x]["tot"], 1), x)):
        c = fam[f]
        A(f"| {f} | {'cal' if f in CALIBRAZIONE else 'test'} | "
          f"{'sì' if f in COPERTE_DA_SEZIONE else '—'} | {c['ok']} | {c['tot']} | "
          f"{c['named']} | {c['structural']} | {c['weak_only']} | {c['die']} |")
    A("")

    A("### Il taglio che porta il risultato in tesi")
    A("")
    for etichetta, coperte in (("coperte da un prefisso di sezione", True), ("**scoperte**", False)):
        sel = [f for f in fam if (f in COPERTE_DA_SEZIONE) == coperte]
        tot = sum(fam[f]["tot"] for f in sel)
        ok = sum(fam[f]["ok"] for f in sel)
        A(f"- famiglie {etichetta}: {len(sel)} — **{ok}/{tot}** rilevati")
    A("")
    solo_ap = COPERTE_A_PRIORI - COPERTE_DA_SEZIONE
    solo_mis = COPERTE_DA_SEZIONE - COPERTE_A_PRIORI
    if solo_ap or solo_mis:
        A("")
        A("> **La copertura misurata non coincide con la lista a priori del protocollo (§6.3).** "
          "Dedurla")
        A("> dal nome della famiglia non è affidabile:")
        if solo_mis:
            A(f"> coperte nei fatti ma non nella lista: **{', '.join(sorted(solo_mis))}** "
              f"(producono sezioni che un prefisso intercetta);")
        if solo_ap:
            A(f"> nella lista ma non nei fatti: **{', '.join(sorted(solo_ap))}** "
              f"(in questo dataset non producono le sezioni attese).")
        A("> Il conteggio qui sopra usa la copertura **misurata**.")
    A("")
    A("Sulle famiglie scoperte la tabella dei prefissi non ha una riga: il verdetto può venire solo")
    A("da una firma di terzi o dai segnali strutturali. È il test diretto di ciò che la tesi")
    A("rivendica, su etichette a oracolo costruttivo.")
    A("")

    A("### Per gruppo")
    A("")
    A("| gruppo | famiglie | rilevati | campioni |")
    A("|---|---|---|---|")
    for nome, pred in (("calibrazione", lambda f: f in CALIBRAZIONE),
                       ("test", lambda f: f not in CALIBRAZIONE)):
        sel = [f for f in fam if pred(f)]
        A(f"| {nome} | {len(sel)} | {sum(fam[f]['ok'] for f in sel)} | "
          f"{sum(fam[f]['tot'] for f in sel)} |")
    A("")

    if inan:
        A("### File non analizzabili")
        A("")
        A(f"{len(inan)} file con magic non valido, esclusi dal triage e **non contati come falsi "
          f"negativi** (§9.2):")
        A("")
        for r in inan[:10]:
            k = chiave[r["SHA256"]]
            A(f"- `{k.get('nome_originale', '?')}` — {k.get('origine', '?')}")
        A("")

    A("## Falsi negativi")
    A("")
    if fn:
        A("Ognuno va guardato a mano prima di essere contato, e classificato come **difetto del")
        A("rilevatore** oppure **caso di definizione**: entrambi si contano, il numero non si sconta")
        A("(§9.2).")
        A("")
        cf = collections.Counter(chiave[r["SHA256"]]["famiglia"] for r in fn)
        A("| famiglia | falsi negativi |")
        A("|---|---|")
        for k, v in cf.most_common():
            A(f"| {k} | {v} |")
        A("")
        for r in fn[:40]:
            k = chiave[r["SHA256"]]
            A(f"- **{k['famiglia']}** `{k.get('nome_originale', '')}` — score "
              f"{r['Packing_Score_%']}, import {r['Total_Imports']}, H "
              f"{r['Max_Entropy_No_Rsrc']}, EP `{r['EP_Section']}`")
            A(f"  - deboli: {r['Weak_Signals'][:130] or 'nessuno'}")
            A(f"  - DIE: {(r['Die_All_Packers'] or r['Die_Detections'])[:90] or 'muto'}")
        if len(fn) > 40:
            A(f"- ... e altri {len(fn) - 40}")
        A("")
    else:
        A("**Nessuno.**")
        A("")

    if notpacked:
        seg = [r for r in notpacked if r["Is_Packed_Label"] == "1"]
        A("## Osservazioni sulla metà `not-packed` (qualitative, non metriche)")
        A("")
        A(f"{len(seg)} dei {len(notpacked)} originali vengono segnalati. **Non sono falsi positivi**")
        A("**misurati**: quella metà non è un oracolo (§3.2). Sono un insieme di sospetti.")
        A("")
        # Controllo incrociato: il gruppo terzo ha isolato 10 file in `outliers/not-packed`
        # perche' li sospettava compressi. Quanti ne segnaliamo noi, in modo indipendente?
        out_np = [r for r in notpacked if chiave[r["SHA256"]]["origine"].startswith("outliers/")]
        if out_np:
            out_seg = [r for r in out_np if r["Is_Packed_Label"] == "1"]
            nomi = sum(1 for r in out_seg if "DIE:" in r["Strong_Signals"]
                       or "YARA packer" in r["Strong_Signals"])
            A("**Controllo incrociato fra due selezioni indipendenti.** Il gruppo terzo ha isolato")
            A(f"{len(out_np)} file in `outliers/not-packed` perché li sospettava compressi pur")
            A(f"essendo etichettati `not-packed`. Noi ne segnaliamo **{len(out_seg)} su {len(out_np)}**,")
            A(f"di cui **{nomi} con un packer nominato** da DIE o YARA. Due selezioni fatte con")
            A("criteri diversi convergono sugli stessi file: è un argomento a favore della")
            A("rilevazione, non un conteggio di falsi positivi — quei file sono probabilmente")
            A("compressi per davvero, ed è il motivo per cui i loro autori li hanno messi da parte.")
            A("")
            rimasti = [r for r in out_np if r["Is_Packed_Label"] != "1"]
            if rimasti:
                A(f"I {len(rimasti)} non segnalati sono i candidati a una classe pulita")
                A("**difficile**, ma solo dopo verifica manuale documentata: la loro etichetta")
                A("`not-packed` non è un oracolo.")
                A("")
                for r in rimasti:
                    k = chiave[r["SHA256"]]
                    A(f"- `{k['nome_originale']}` — score {r['Packing_Score_%']}, "
                      f"H {r['Max_Entropy_No_Rsrc']}, import {r['Total_Imports']}, "
                      f"deboli: {r['Weak_Signals'][:80] or 'nessuno'}")
                A("")
        cat = collections.Counter()
        for r in seg:
            s = r["Strong_Signals"].lower()
            cat["SFX / autoestraente" if "sfx identificato" in s else
                "installer" if "installer identificato" in s else
                "altro segnale forte" if r["Strong_Signals"] else "solo segnali deboli"] += 1
        A("| categoria | campioni |")
        A("|---|---|")
        for k, v in cat.most_common():
            A(f"| {k} | {v} |")
        A("")

    testo = "\n".join(L) + "\n"
    out = args.out or os.path.join(OUTPUT_DIR, "validation_external_dataset_packed_pe.md")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(testo)
    print()
    print(testo)
    log.info(f"Report scritto: {out}")


if __name__ == "__main__":
    main()
