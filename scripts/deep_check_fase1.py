#!/usr/bin/env python3
"""
deep_check_fase1.py
===================
I sette controlli del **controllo profondo** della Fase 1 (§24 di
`docs/04_fase1_log_sessioni.md`), rieseguibili con un comando.

Perche' esiste
--------------
I risultati di quei controlli erano documentati, ma i comandi che li avevano prodotti
no: erano script usa-e-getta. Per una tesi che rivendica riproducibilita' era il punto
piu' debole della catena. Questo script chiude il buco.

Cosa controlla
--------------
  0  riconciliazione dei conteggi      disco <-> CSV <-> manifest
  1  ogni etichetta ha un oracolo      nessuna label da scansione automatica
  2  il referto si rigenera identico    matrice ricalcolata == validation_phase1.json
  3  determinismo del rilevatore        confronto fra run; con --live rianalizza
  4  zero decisioni sotto timeout       colonne di stato + log delle invocazioni
  5  margine della classe negativa      quanto manca ai puliti per superare la soglia
  6  i casi limite                      elencati, non contati

Principio: **non si codificano i numeri attesi.** I numeri si stampano; si fallisce
solo sugli INVARIANTI, cioe' le proprieta' che devono valere qualunque sia il dataset.
Aggiungere campioni non deve far fallire il controllo; perdere una proprieta' si'.

Uso
---
    python scripts/deep_check_fase1.py                 # i sette controlli, read-only
    python scripts/deep_check_fase1.py --only 5        # un controllo solo
    python scripts/deep_check_fase1.py --live 200      # test 3 anche in rianalisi
    python scripts/deep_check_fase1.py --quiet         # solo PASS/FAIL ed esito finale

Esce con codice 1 se un invariante cade. Non scrive niente: nessun file di
`Pipeline_Reports/` viene modificato, nemmeno dal test 3 con --live.
"""
import argparse
import collections
import csv
import glob
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

# Si riusa il validatore ufficiale invece di riscriverne la logica: se i due calcoli
# divergessero, il controllo non dimostrerebbe niente sul referto che va in tesi.
import validate_phase1 as V                                            # noqa: E402
from pipeline_utils import SERVICE_EXT, compute_file_hash              # noqa: E402

AUTO_SOURCES = ("auto-scan",)
DIAG = os.path.join(V.OUTPUT_DIR, "tool_diagnostics.jsonl")

# Colonne che per costruzione cambiano fra due run (timestamp, percorsi) o che
# dipendono dalla LOGICA dei segnali, non dalla misura. Tutto il resto e' output di uno
# strumento e deve essere identico: e' quello che il test 3 verifica.
VOLATILI = {"Analyzed_At", "File", "Dataset"}
DERIVATE = {"Strong_Signals", "Weak_Signals", "Info_Signals", "Suspicious_Sections",
            "Packing_Score_%", "Is_Packed_Label", "Packing_Evidence", "Capa_Mode",
            "Exec_High_Entropy_Sections"}
DECISIVE = {"Is_Packed_Label", "Packing_Score_%", "Packing_Evidence",
            "Strong_Signals", "Weak_Signals"}

esiti = {}
_quiet = False


def say(*a):
    if not _quiet:
        print(*a)


def chiudi(n, nome, ok, nota=""):
    esiti[n] = (nome, ok, nota)
    print(f"  [{'PASS' if ok else 'FAIL'}] test {n} - {nome}" + (f"  ({nota})" if nota else ""))


def weak_of(row):
    return V.split_signals(row.get("Weak_Signals"))


def strong_of(row):
    return V.split_signals(row.get("Strong_Signals"))


def senza_die(row):
    return [w for w in weak_of(row) if not w.startswith("DIE euristica")]


# ----------------------------------------------------------------------------- test 0
def test0(rows, manifest, grezze, non_risolte):
    say("\n--- test 0: riconciliazione dei conteggi ---")
    unknown = sum(1 for v in manifest.values() if v["label"] not in ("packed", "clean"))
    etichettati = len(manifest) - unknown
    hash_csv = {r["_hash"] for r in rows if r["_hash"]}
    agganciate = sum(1 for h in manifest if h in hash_csv)
    say(f"  righe CSV grezze              {grezze}")
    say(f"  - duplicati per contenuto     -{grezze - len(rows)}")
    say(f"  = binari distinti             {len(rows)}")
    say(f"  voci nel manifest             {len(manifest)}")
    say(f"  - unknown                     -{unknown}")
    say(f"  = usati per le metriche       {etichettati}")
    say(f"  voci del manifest con una riga nel CSV: {agganciate}/{len(manifest)}")

    # INVARIANTI
    problemi = []
    if non_risolte:
        problemi.append(f"{non_risolte} righe senza SHA-256 risolto")
    orfane = [h for h in manifest if h not in hash_csv]
    if orfane:
        problemi.append(f"{len(orfane)} voci del manifest senza riga nel CSV")
        for h in orfane[:5]:
            say(f"      orfana: {h[:16]} {manifest[h].get('filename')} "
                f"({manifest[h].get('label')}, {manifest[h].get('source')})")
    # regressione del §24.1: un file di servizio non e' un campione
    servizio = [h for h, v in manifest.items()
                if os.path.splitext(v.get("filename", ""))[1].lower() in SERVICE_EXT]
    if servizio:
        problemi.append(f"{len(servizio)} file di SERVIZIO inventariati come campioni")
        for h in servizio[:5]:
            say(f"      servizio: {manifest[h].get('filename')}")
    chiudi(0, "riconciliazione dei conteggi", not problemi, "; ".join(problemi))


# ----------------------------------------------------------------------------- test 1
def test1(manifest):
    say("\n--- test 1: ogni etichetta ha un oracolo scritto ---")
    lab = [(h, v) for h, v in manifest.items() if v["label"] in ("packed", "clean")]
    da_scansione = [h for h, v in lab if v.get("source") in AUTO_SOURCES]
    senza_fonte = [h for h, v in lab if not (v.get("source") or "").strip()]
    senza_nota = [h for h, v in lab if not (v.get("notes") or "").strip()]
    say(f"  campioni etichettati                      {len(lab)}")
    say(f"  con label da scansione automatica          {len(da_scansione)}   (deve essere 0)")
    say(f"  senza fonte dichiarata                     {len(senza_fonte)}   (deve essere 0)")
    say(f"  senza nota che spiega l'oracolo            {len(senza_nota)}   (deve essere 0)")
    say("\n  oracoli dichiarati:")
    for (l, s), n in sorted(collections.Counter((v["label"], v.get("source")) for _, v in lab).items(),
                            key=lambda x: (x[0][0], -x[1])):
        say(f"     {l:7s} {s:24s} {n:5d}")

    # Supporto EFFETTIVO: i file dalla stessa fonte non sono osservazioni indipendenti
    # (§14.3). Si conta quante FONTI distinte stanno dietro i file, non quanti file.
    say("\n  supporto effettivo (fonti distinte, non file):")
    fonti = {
        "dist-ufficiale-non-ms": (r"archivio ([^,]+), sha256", "archivi upstream"),
        "wheel-pypi": (r"pacchetto '([^']+)'", "pacchetti"),
    }
    for src, (rx, etichetta) in fonti.items():
        trovate = {m.group(1).strip() for _, v in lab if v.get("source") == src
                   for m in [re.search(rx, v.get("notes") or "")] if m}
        n_file = sum(1 for _, v in lab if v.get("source") == src)
        if n_file:
            say(f"     {src:24s} {n_file:5d} file da {len(trovate)} {etichetta}")
    matrice = [v for _, v in lab if (v.get("source") or "").startswith("pack_samples")]
    if matrice:
        master = {v.get("origin_sha256") for v in matrice if v.get("origin_sha256")}
        senza_origine = [v for v in matrice if not v.get("origin_sha256")]
        celle = collections.Counter(tuple(v.get("packers") or []) for v in matrice)
        say(f"     matrice                  {len(matrice):5d} campioni da {len(master)} master, "
            f"{len(celle)} celle, senza origin_sha256: {len(senza_origine)}")

    problemi = []
    if da_scansione:
        problemi.append(f"{len(da_scansione)} label create da una scansione automatica")
    if senza_fonte:
        problemi.append(f"{len(senza_fonte)} senza fonte")
    if senza_nota:
        problemi.append(f"{len(senza_nota)} senza nota")
    chiudi(1, "ogni etichetta ha un oracolo", not problemi, "; ".join(problemi))


# ----------------------------------------------------------------------------- test 2
def test2(rows, manifest):
    say("\n--- test 2: il referto si rigenera identico ---")
    cm = V.confusion(rows, manifest)
    m = V.metrics(cm)
    say(f"  ricalcolata ora : TP={cm['tp']} FN={cm['fn']} FP={cm['fp']} TN={cm['tn']}")
    say(f"                    precision={m['precision']:.3f} recall={m['recall']:.3f} F1={m['f1']:.3f}")
    problemi = []
    if os.path.exists(V.REPORT_JSON):
        with open(V.REPORT_JSON, encoding="utf-8") as f:
            vecchio = json.load(f)
        c = vecchio.get("cm") or vecchio.get("confusion") or {}
        att = {k: c.get(k) for k in ("tp", "fp", "tn", "fn")}
        ora = {k: cm[k] for k in ("tp", "fp", "tn", "fn")}
        say(f"  nel referto su disco: {att}")
        if att != ora:
            problemi.append(f"matrice diversa dal referto: disco={att} ora={ora}")
        # anche i conteggi dichiarati nel referto devono ancora valere
        for chiave, adesso in (("n_rows", len(rows)), ("matched", None)):
            if chiave in vecchio and adesso is not None and vecchio[chiave] != adesso:
                problemi.append(f"{chiave}: referto={vecchio[chiave]} ora={adesso}")
        if vecchio.get("current_weak_required") not in (None, _soglia()):
            problemi.append(f"soglia cambiata: referto={vecchio['current_weak_required']} "
                            f"ora={_soglia()}")
    else:
        say("  (nessun validation_phase1.json su disco: confronto saltato)")
    if cm["fp"] or cm["fn"]:
        problemi.append(f"FP={cm['fp']} FN={cm['fn']}: il risultato dichiarato e' 0 e 0")
        for nome, seg in cm["errors"]["fp"][:5]:
            say(f"      FP: {nome}  <- {str(seg)[:70]}")
        for nome, pk in cm["errors"]["fn"][:5]:
            say(f"      FN: {nome}  ({pk})")
    chiudi(2, "il referto si rigenera identico", not problemi, "; ".join(problemi))
    return cm


# ----------------------------------------------------------------------------- test 3
def _carica_per_hash(path):
    d = {}
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            h = (r.get("SHA256") or "").strip().lower()
            if h and h not in d:
                d[h] = r
    return d


def test3(rows, manifest, live=0):
    say("\n--- test 3: determinismo del rilevatore ---")
    problemi = []

    # Metodo A, a costo zero: i CSV archiviati vengono da run precedenti.
    archivi = sorted(glob.glob(V.DEFAULT_CSV + ".bak_*"))
    say(f"  CSV archiviati trovati: {len(archivi)}")
    if len(archivi) >= 2:
        a, b = _carica_per_hash(archivi[-2]), _carica_per_hash(archivi[-1])
        comuni = sorted(set(a) & set(b))
        cols = [c for c in next(iter(a.values()))] if a else []
        if comuni and cols:
            diff = collections.Counter()
            for h in comuni:
                for c in cols:
                    if (a[h].get(c) or "") != (b[h].get(c) or ""):
                        diff[c] += 1
            identiche = [c for c in cols if c not in diff]
            say(f"  {os.path.basename(archivi[-2])} vs {os.path.basename(archivi[-1])}: "
                f"{len(comuni)} binari in comune")
            say(f"    colonne identiche: {len(identiche)}/{len(cols)}")
            for c, n in diff.most_common():
                quale = "volatile" if c in VOLATILI else "derivata" if c in DERIVATE else "DI MISURA"
                say(f"       {n:5d}  {c}   [{quale}]")
            # INVARIANTE: una colonna di MISURA non deve cambiare fra run.
            misura_rotte = [c for c in diff if c not in VOLATILI and c not in DERIVATE]
            if misura_rotte:
                problemi.append(f"colonne di misura diverse fra due run: {misura_rotte}")
        else:
            say("    (nessun binario in comune o schema vuoto: confronto saltato)")
    else:
        say("  meno di due archivi: confronto fra run non disponibile")

    # Metodo B, opzionale: rianalisi dal vivo contro l'artefatto congelato.
    if live:
        say(f"\n  rianalisi dal vivo di {live} binari (nessuna scrittura su disco)...")
        rotte = _rianalizza(rows, manifest, live, problemi)
        if rotte:
            problemi.append(f"colonne decisive diverse dal CSV: {sorted(rotte)}")
    else:
        say("\n  rianalisi dal vivo non richiesta (--live N per eseguirla)")
    chiudi(3, "determinismo del rilevatore", not problemi, "; ".join(problemi))


def _rianalizza(rows, manifest, quanti, problemi):
    """Rianalizza un campione e confronta ogni colonna con la riga del CSV.

    ATTENZIONE: `analyze_with_lief` chiama GIA' `_format_for_csv` alla fine. Richiamarla
    qui NON e' idempotente: `_as_list()` scarta le voci vuote, che sono gli import per
    ordinale, e sposta il troncamento a 10 elementi. Su 7.752 righe ne altererebbe 551,
    producendo differenze che nella pipeline non esistono (§24.7). Non va richiamata.
    """
    import header_elf_lief as HL
    radici = _radici_dataset()
    # campione deliberato: prima i casi limite, poi una fetta a seme fisso
    scelti, rnd = {}, __import__("random").Random(20261001)
    def prendi(r):
        scelti.setdefault(r["_hash"], r)
    for r in rows:
        e = manifest.get(r["_hash"])
        if not e or e["label"] not in ("packed", "clean"):
            continue
        if e["label"] == "packed" and not strong_of(r):
            prendi(r)
        if e["label"] == "clean" and len(senza_die(r)) >= 2:
            prendi(r)
        if r.get("Parse_Status") not in ("ok", "not_executable"):
            prendi(r)
        if e["label"] == "packed" and r.get("Packing_Evidence") == "structural":
            prendi(r)
    resto = [r for r in rows if r["_hash"] not in scelti and manifest.get(r["_hash"], {}).get("label")
             in ("packed", "clean")]
    rnd.shuffle(resto)
    for r in resto[:max(0, quanti - len(scelti))]:
        prendi(r)

    compiled = HL.get_yara_rules()
    die_ready = HL.is_die_available()
    say(f"    YARA: {'ok' if compiled else 'NON disponibile'} | "
        f"DIE: {'ok' if die_ready else 'NON disponibile'} | capa: {HL.CAPA_MODE}")
    if not compiled or not die_ready:
        problemi.append("un tool manca: il confronto non sarebbe valido")
        return set()

    diff = collections.Counter()
    confrontati = saltati = 0
    for h, atteso in sorted(scelti.items()):
        p = _risolvi(atteso, radici)
        if not p or compute_file_hash(p) != h:
            saltati += 1
            continue
        nuovo = HL.analyze_with_lief(atteso["File"], p, compiled, capa_ready=False,
                                     die_ready=die_ready, file_hash=h,
                                     dataset=atteso.get("Dataset", ""))
        confrontati += 1
        for c in atteso:
            if c in VOLATILI or c.startswith("_"):
                continue
            if str(atteso.get(c) or "") != str(nuovo.get(c) if nuovo.get(c) is not None else ""):
                diff[c] += 1
    say(f"    confrontati {confrontati} binari ({saltati} non risolti o cambiati sul disco)")
    if not diff:
        say("    nessuna differenza su nessuna colonna")
    else:
        for c, n in diff.most_common():
            say(f"       {n:4d}  {c}{'   <-- DECISIVA' if c in DECISIVE else ''}")
    return DECISIVE & set(diff)


def _radici_dataset():
    """dataset -> cartella. Dedotto dall'albero di E:\\DATASET piu' i set esterni."""
    radici = {}
    for base in (os.path.join("E:" + os.sep, "DATASET", "01_LABEL_CERTA"),
                 os.path.join("E:" + os.sep, "DATASET", "02_MATERIA_PRIMA"),
                 os.path.join("E:" + os.sep, "DATASET", "03_NON_ETICHETTATI"),
                 os.path.join("E:" + os.sep, "DATASET", "04_VALIDAZIONE_ESTERNA")):
        if os.path.isdir(base):
            for d in os.listdir(base):
                if os.path.isdir(os.path.join(base, d)):
                    radici[d] = os.path.join(base, d)
    esterno = os.path.join("E:" + os.sep, "dataset-packed-pe-main")
    if os.path.isdir(esterno):
        radici["dataset-packed-pe-main"] = esterno
    return radici


def _risolvi(row, radici):
    root = radici.get(row.get("Dataset", ""))
    if not root:
        return None
    p = os.path.join(root, (row.get("File") or "").replace("/", os.sep))
    return p if os.path.isfile(p) else None


# ----------------------------------------------------------------------------- test 4
def test4(rows, manifest):
    say("\n--- test 4: zero decisioni prese sotto timeout ---")
    met = [r for r in rows if manifest.get(r["_hash"], {}).get("label") in ("packed", "clean")]
    esposte, dettaglio = V.determinism_exposure(met)
    say(f"  righe nelle metriche: {len(met)}")
    for c in ("Die_Status", "Yara_Status", "Capa_Status", "Parse_Status"):
        d = collections.Counter(r.get(c, "") for r in met)
        say(f"    {c:14s} " + "  ".join(f"{v or '(vuoto)'}={n}" for v, n in d.most_common()))
    say(f"  decise con un tool troncato: {esposte} {dettaglio}   (deve essere 0)")

    # Riscontro indipendente: il log di una invocazione per riga.
    if os.path.exists(DIAG):
        per_tool = collections.Counter()
        with open(DIAG, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                s = str(d.get("status") or "")
                if s in V.TRUNCATED_STATES:
                    per_tool[(d.get("tool") or "?", s)] += 1
        tot = sum(per_tool.values())
        say(f"  nel log delle invocazioni: {tot} invocazioni troncate")
        for (t, s), n in per_tool.most_common():
            say(f"       {n:5d}  {t} / {s}")
        if tot and all(t == "capa" for (t, _) in per_tool):
            say("    tutte di capa: con CAPA_MODE=off non toccano nessun verdetto delle metriche")
    else:
        say("  (nessun tool_diagnostics.jsonl: riscontro indipendente saltato)")

    # Decisioni prese senza LIEF: non sono timeout, ma vanno dichiarate.
    senza_lief = [r for r in met if r.get("Parse_Status") not in ("ok", "not_executable")]
    if senza_lief:
        say(f"  decise senza LIEF (ripiego su DIE/YARA): {len(senza_lief)}")
        for r in senza_lief[:5]:
            say(f"       {r.get('File')[:52]}  {r.get('Parse_Status')} -> "
                f"{r.get('Packing_Evidence')}")
    chiudi(4, "zero decisioni sotto timeout", esposte == 0,
           "" if esposte == 0 else f"{esposte} righe esposte")


# ----------------------------------------------------------------------------- test 5
def test5(rows, manifest):
    say("\n--- test 5: margine della classe negativa ---")
    clean = [r for r in rows if manifest.get(r["_hash"], {}).get("label") == "clean"]
    soglia = _soglia()
    d = collections.Counter(len(weak_of(r)) for r in clean)
    con_forte = [r for r in clean if strong_of(r)]
    say(f"  puliti: {len(clean)}   soglia: {soglia} segnali deboli, oppure 1 forte")
    for k in sorted(d):
        say(f"    {k} deboli: {d[k]:5d}  ({100*d[k]/max(1,len(clean)):5.1f} %)"
            + ("   <-- A UN SEGNALE DALLA SOGLIA" if k == soglia - 1 else ""))
    say(f"  con almeno un segnale forte: {len(con_forte)}   (deve essere 0)")

    say("\n  margine per oracolo:")
    per_or = collections.defaultdict(list)
    for r in clean:
        per_or[manifest[r["_hash"]].get("source")].append(r)
    for src in sorted(per_or, key=lambda s: -len(per_or[s])):
        c = collections.Counter(len(weak_of(r)) for r in per_or[src])
        peggio = max(len(weak_of(r)) for r in per_or[src])
        say(f"    {src:24s} n={len(per_or[src]):5d}  " +
            " ".join(f"{k}:{c.get(k,0)}" for k in range(soglia + 1)) + f"   peggiore={peggio}")

    # Sensibilita' all'unico componente di TERZI fra i deboli (§24.5).
    say("\n  sensibilita' all'euristica DIE (solo misura, il rilevatore non cambia):")
    a = collections.Counter(len(weak_of(r)) for r in clean)
    b = collections.Counter(len(senza_die(r)) for r in clean)
    for k in range(soglia + 1):
        say(f"    {k} deboli: con DIE {a.get(k,0):5d}   senza {b.get(k,0):5d}")
    packed = [r for r in rows if manifest.get(r["_hash"], {}).get("label") == "packed"]
    persi = [r for r in packed if not strong_of(r) and len(senza_die(r)) < soglia]
    say(f"    packed che scenderebbero sotto soglia senza l'euristica DIE: {len(persi)}")
    for r in persi:
        say(f"       {r.get('File')[:56]}")

    problemi = []
    sopra = [r for r in clean if len(weak_of(r)) >= soglia]
    if sopra:
        problemi.append(f"{len(sopra)} puliti raggiungono la soglia")
    if con_forte:
        problemi.append(f"{len(con_forte)} puliti hanno un segnale forte")
    chiudi(5, "margine della classe negativa", not problemi, "; ".join(problemi))


def _soglia():
    try:
        import header_elf_lief as HL
        return int(HL.WEAK_SIGNALS_REQUIRED)
    except Exception:
        return 3


# ----------------------------------------------------------------------------- test 6
def test6(rows, manifest):
    say("\n--- test 6: i casi limite, uno per uno ---")
    clean = [r for r in rows if manifest.get(r["_hash"], {}).get("label") == "clean"]
    packed = [r for r in rows if manifest.get(r["_hash"], {}).get("label") == "packed"]

    say("\n  A) puliti a 2+ segnali STRUTTURALI (senza l'euristica DIE):")
    for r in [r for r in clean if len(senza_die(r)) >= 2]:
        say(f"     {r.get('File')[:48]:48s} H={r.get('Max_Entropy_No_Rsrc')} "
            f"EP={r.get('EP_Section')} H_EP={r.get('EP_Section_Entropy')}")
        for w in weak_of(r):
            say(f"        - {w}")

    say("\n  B) la coppia correlata: due segnali deboli da UN SOLO fatto")
    say("     (entropia >= soglia e EP in sezione ad alta entropia, quando l'EP e' la piu' calda)")
    for nome, ins in (("packed", packed), ("clean", clean)):
        coppia = [r for r in ins
                  if any(w.startswith("entropia sezione") for w in weak_of(r))
                  and any(w.startswith("entry point in sezione ad alta entropia") for w in weak_of(r))]
        un_fatto = [r for r in coppia if _stessa_misura(r)]
        say(f"     {nome:7s} con la coppia {len(coppia):4d}, di cui un solo fatto {len(un_fatto):4d}")
        for r in un_fatto:
            say(f"        {r.get('File')[:50]:50s} deboli={len(weak_of(r))}")

    say("\n  C) packed decisi dai SOLI segnali deboli:")
    for r in [r for r in packed if not strong_of(r)]:
        e = manifest[r["_hash"]]
        say(f"     {r.get('File')[:48]:48s} {','.join(e.get('packers') or []) or '?':24s} "
            f"deboli={len(weak_of(r))} (strutt. {len(senza_die(r))})")

    say("\n  D) evidenza, e chi porta il verdetto senza un nome:")
    ev = collections.Counter(r.get("Packing_Evidence") for r in packed)
    say(f"     {dict(ev)}")
    st = [r for r in packed if r.get("Packing_Evidence") == "structural"]
    if st:
        pk = collections.Counter(tuple(manifest[r["_hash"]].get("packers") or []) for r in st)
        for p, n in pk.most_common():
            say(f"     structural: {n:4d}  {' + '.join(p) or '(nessuno)'}")
    chiudi(6, "i casi limite", True, "elenco, nessun invariante")


def _stessa_misura(row):
    try:
        return abs(float(row.get("EP_Section_Entropy") or 0)
                   - float(row.get("Max_Entropy_No_Rsrc") or 0)) < 0.005
    except ValueError:
        return False


# ----------------------------------------------------------------------------- main
def main():
    global _quiet
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--csv", default=V.DEFAULT_CSV)
    ap.add_argument("--manifest", default=V.DEFAULT_MANIFEST)
    ap.add_argument("--only", type=int, choices=range(0, 7), action="append",
                    help="esegue solo i controlli indicati (ripetibile).")
    ap.add_argument("--live", type=int, default=0, metavar="N",
                    help="test 3: rianalizza N binari col codice attuale. Lento (~4 s/file), "
                         "non scrive nulla.")
    ap.add_argument("--quiet", action="store_true", help="solo PASS/FAIL ed esito finale.")
    args = ap.parse_args()
    _quiet = args.quiet

    with open(args.csv, newline="", encoding="utf-8") as f:
        grezze = sum(1 for _ in csv.DictReader(f))
    rows, non_risolte = V.load_rows(args.csv, [])
    with open(args.manifest, encoding="utf-8") as f:
        manifest = json.load(f)

    # Guardia contro il fallimento silenzioso: se il CSV cambiasse schema, i controlli
    # passerebbero a vuoto invece di fallire. E' lo stesso difetto che un indice scritto
    # a mano ha avuto una volta: dichiarava una cosa che i dati non confermavano.
    attese = {"SHA256", "Is_Packed_Label", "Strong_Signals", "Weak_Signals",
              "Packing_Evidence", "Parse_Status", "Die_Status", "Yara_Status", "Capa_Status"}
    mancanti = attese - set(rows[0])
    if mancanti:
        sys.exit(f"ERRORE: il CSV non ha le colonne {sorted(mancanti)}: i controlli non "
                 f"sarebbero validi. Interrompo invece di passare a vuoto.")
    if not rows or not manifest:
        sys.exit("ERRORE: CSV o manifest vuoti.")

    print(f"deep check Fase 1 - CSV {grezze} righe, manifest {len(manifest)} voci")
    scelti = sorted(set(args.only)) if args.only else list(range(7))
    if 0 in scelti:
        test0(rows, manifest, grezze, non_risolte)
    if 1 in scelti:
        test1(manifest)
    if 2 in scelti:
        test2(rows, manifest)
    if 3 in scelti:
        test3(rows, manifest, live=args.live)
    if 4 in scelti:
        test4(rows, manifest)
    if 5 in scelti:
        test5(rows, manifest)
    if 6 in scelti:
        test6(rows, manifest)

    falliti = [n for n, (_, ok, _) in esiti.items() if not ok]
    print(f"\n=== {len(esiti) - len(falliti)}/{len(esiti)} controlli superati ===")
    if falliti:
        print(f"FALLITI: {falliti}")
    return 1 if falliti else 0


if __name__ == "__main__":
    sys.exit(main())
