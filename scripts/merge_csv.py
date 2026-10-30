#!/usr/bin/env python3
"""
merge_datasets.py
==================
Costruisce un dataset unico per l'addestramento di un modello a partire da:
  - vt_dataset.csv               (BASE: benigni + malware, con label 0/1)
  - master_dataset_malware.csv   (solo malware, 0 hash in comune con VT ->
                                   viene CONCATENATO verticalmente a VT dopo
                                   aver mappato le colonne su uno schema comune)
  - ha_dataset.csv                (arricchimento: si sovrappone quasi solo con
                                   VT -> viene aggiunto con un LEFT JOIN su sha256)

Logica di standardizzazione VT <-> MASTER_MALWARE
--------------------------------------------------
I due file condividono molti nomi di colonna ma NON sempre lo stesso
significato/scala:

  - file_size, file_name, first_seen, av_malicious_count, av_suspicious_count,
    av_total_engines, yara_rules, sandbox_names
        -> stesso significato/scala -> tenuti diretti, o usati per derivare
           feature comparabili (yara_rules_count, sandbox_count, ecc.)

  - file_type
        -> vocabolario diverso ("exe" vs "Win32 EXE") -> mappato su una
           categoria comune, salvata con lo stesso nome originale file_type
           (pe_exe / pe_dll / elf / other)

  - sandbox_confidences
        -> scale INCOMPATIBILI e non lineari (VT: 0-100; MASTER: mix di 0-1 e
           0-10 a seconda del sandbox), NON convertita: tenuta grezza in
           sandbox_confidences_raw (nessuna normalizzazione affidabile
           trovata finora, da riprendere in futuro)

  - av_malicious_list
        -> in MASTER è la lista dei tool/DB che hanno segnalato il file, in
           VT è "vendor:signature" per singolo antivirus -> concetti diversi
           nonostante il nome identico -> tenuta grezza ma NON unificata
           (av_malicious_list_raw), nessuna feature derivata

  - triage_severity (VT) vs triage JSON {"score","family"} (MASTER)
        -> strumenti diversi, non lo stesso campo: triage_severity viene
           riempita per le righe mm mappando lo score 0-10 su bucket
           SEVERITY_LOW/MEDIUM/HIGH (soglie arbitrarie, vedi _score_to_severity)
        -> mm_triage_score e mm_triage_family restano ANCHE disponibili
           per intero (non solo come severity), su richiesta esplicita

Colonne rimosse
-----------------
  - delivery_method: mai popolato in VT (colonna vuota per meta' del
    dataset), rimosso.
  - type_tags: significato diverso tra le due fonti (family/packer in MB,
    formato file in VT), rimosso per evitare una categoriale ambigua.
  - source_origin: usata internamente per i controlli di leakage e poi
    tolta dal CSV finale su richiesta (non necessaria all'analisi).
  - magika, clamav_detections, yara_rules_count originale: esclusive di
    MB, sarebbero perfettamente correlate con label=1 per costruzione del
    dataset, non per segnale reale (yara_rules_count viene ricalcolato
    identico per entrambe le fonti, le altre due scartate).

Colonne mantenute anche se esclusive di VT
--------------------------------------------
signature_verified, signature_signers, sandbox_malware_names: popolate al
100% su TUTTE le righe VT (benigne e malware), quindi il NaN che avranno
le righe aggiunte da master_dataset_malware riflette "dato non misurato",
non un artefatto correlato alla label. Rischio più contenuto, comunque
segnalato.

mm_triage_score / mm_triage_family: tenute su richiesta esplicita pur
essendo esclusive di mm (quindi SEMPRE assenti per vt, SEMPRE presenti
per mm che e' sempre label=1) - qui la sola presenza/assenza predice la
label, va gestito esplicitamente in fase di training.

Uso:
    python3 merge_datasets.py --ha ha_dataset.csv --mm master_dataset_malware.csv \
        --vt vt_dataset.csv --outdir /mnt/user-data/outputs
"""

import argparse
import json
import re
import sys
from pathlib import Path

import pandas as pd

SHA_RE = r"[0-9a-f]{64}"


# ---------------------------------------------------------------------------
# 1. FIX DI PARSING
# ---------------------------------------------------------------------------
def fix_broken_lines(raw_text: str) -> tuple[str, int]:
    """
    In vt_dataset.csv esiste (almeno) un punto in cui manca un '\\n' tra due
    record: l'ultimo campo (label, singola cifra 0/1) del record N si fonde
    con lo sha256 del record N+1, es:
        ...,,,,,0<hash64>,file_name,...
    Il pattern è inequivocabile: una virgola, una cifra 0/1, 64 caratteri hex,
    una virgola -> non può comparire in nessun altro punto legittimo del file.
    Lo correggiamo reinserendo il newline mancante.
    """
    pattern = re.compile(r",([01])(" + SHA_RE + r"),")
    n_fix = len(pattern.findall(raw_text))
    fixed = pattern.sub(r",\1\n\2,", raw_text)
    return fixed, n_fix


def read_csv_robust(path: Path) -> pd.DataFrame:
    raw = path.read_text(encoding="utf-8", errors="replace")
    fixed, n_fix = fix_broken_lines(raw)
    if n_fix:
        print(f"  [fix] {path.name}: {n_fix} riga/e con newline mancante corrette")
    from io import StringIO

    df = pd.read_csv(StringIO(fixed))
    df.columns = [c.strip() for c in df.columns]  # es. 'first_seen ' -> 'first_seen'
    return df


def clean_keys(df: pd.DataFrame, source: str) -> pd.DataFrame:
    df = df.copy()
    df["sha256"] = df["sha256"].astype(str).str.strip().str.lower()
    n_before = len(df)
    df = df.drop_duplicates(subset="sha256", keep="first")
    n_dup = n_before - len(df)
    if n_dup:
        print(f"  [dedup] {source}: {n_dup} sha256 duplicati rimossi (tenuta la prima occorrenza)")
    return df


# ---------------------------------------------------------------------------
# 2. NORMALIZZAZIONE DATE (formati diversi per ogni fonte)
# ---------------------------------------------------------------------------
def parse_dates(series: pd.Series) -> pd.Series:
    return pd.to_datetime(series, errors="coerce", utc=True)


# ---------------------------------------------------------------------------
# 3. HELPER DI NORMALIZZAZIONE CAMPI
# ---------------------------------------------------------------------------
FILE_CATEGORY_MM = {"exe": "pe_exe", "dll": "pe_dll", "elf": "elf"}


def _vt_file_category(val):
    if not isinstance(val, str):
        return pd.NA
    v = val.lower()
    if "dll" in v:
        return "pe_dll"
    if "exe" in v:
        return "pe_exe"
    return "other"


def _ha_file_category(val):
    if not isinstance(val, str):
        return pd.NA
    v = val.lower()
    if not v.startswith("pe32"):
        return "other"
    return "pe_dll" if "dll" in v else "pe_exe"


def _count_pipe(series: pd.Series) -> pd.Series:
    """Conta gli elementi non vuoti di un campo pipe-separated ('a|b|' -> 2)."""
    return series.fillna("").astype(str).apply(lambda x: len([p for p in x.split("|") if p.strip()]))


def _parse_triage(series: pd.Series) -> tuple[pd.Series, pd.Series]:
    """Estrae score (0-10) e family dal JSON di triage di master_dataset_malware.
    family=='None' (stringa, non identificata dal tool) viene convertita in NaN vero."""
    scores, families = [], []
    for v in series:
        if not isinstance(v, str):
            scores.append(pd.NA)
            families.append(pd.NA)
            continue
        try:
            d = json.loads(v)
            scores.append(d.get("score", pd.NA))
            fam = d.get("family")
            families.append(pd.NA if fam in (None, "None") else fam)
        except (json.JSONDecodeError, TypeError):
            scores.append(pd.NA)
            families.append(pd.NA)
    return pd.Series(scores, index=series.index, dtype="Int64"), pd.Series(families, index=series.index, dtype="object")


def _score_to_severity(score) -> str:
    """DEPRECATA: bucket arbitrari sullo score 0-10, sostituita da
    _compute_triage_severity che replica la formula reale di VT.
    Lasciata solo per compatibilita', non piu' usata."""
    if pd.isna(score):
        return pd.NA
    if score <= 3:
        return "SEVERITY_LOW"
    if score <= 7:
        return "SEVERITY_MEDIUM"
    return "SEVERITY_HIGH"


def _compute_triage_severity(av_malicious, av_suspicious, av_total, yara_rules, sb_categories) -> str:
    """Replica ESATTA della formula usata in Virus_Total.py (compute_triage_severity)
    per calcolare triage_severity, cosi' da poterla applicare anche a MB con la
    stessa metodologia. Unico scostamento: il confronto sulle categorie sandbox
    e' case-insensitive e per sottostringa ('malicious' in 'LIKELY_MALICIOUS'),
    perche' il vocabolario delle categorie di MB e' diverso da quello di VT
    (che usa esattamente le stringhe 'malicious'/'suspicious' dalla sua API).
    """
    av_malicious = av_malicious or 0
    av_suspicious = av_suspicious or 0
    av_total = av_total or 0

    score = 0
    if av_total > 0:
        ratio = av_malicious / av_total
        if ratio >= 0.50:
            score += 40
        elif ratio >= 0.20:
            score += 25
        elif ratio >= 0.05:
            score += 10
        elif ratio >= 0.01:
            score += 5
    if av_malicious >= 20:
        score += 20
    elif av_malicious >= 10:
        score += 12
    elif av_malicious >= 3:
        score += 6
    if av_suspicious >= 5:
        score += 10
    elif av_suspicious >= 1:
        score += 5

    cats_lower = [str(c).lower() for c in sb_categories if c]
    has_sb_malicious = any("malicious" in c or "malware" in c for c in cats_lower)
    has_sb_suspicious = any("suspicious" in c for c in cats_lower)
    if has_sb_malicious:
        score += 25
    elif has_sb_suspicious:
        score += 12

    if yara_rules:
        score += 8

    if score >= 50:
        return "SEVERITY_HIGH"
    if score >= 25:
        return "SEVERITY_MEDIUM"
    if score > 0:
        return "SEVERITY_LOW"
    return "SEVERITY_CLEAN"


MALICIOUS_TOKENS = ("malicious", "malware", "trojan", "high", "medium")


def _sandbox_flagged(cat_series: pd.Series, class_series: pd.Series) -> pd.Series:
    """True se in una qualsiasi delle sandbox compare un token 'malevolo'."""
    combined = (cat_series.fillna("") + "|" + class_series.fillna("")).str.lower()
    return combined.apply(lambda x: any(tok in x for tok in MALICIOUS_TOKENS)).astype("boolean")


# ---------------------------------------------------------------------------
# 4. CARICAMENTO + STANDARDIZZAZIONE VT / MASTER_MALWARE SU SCHEMA COMUNE
# ---------------------------------------------------------------------------
def load_vt(path: Path) -> pd.DataFrame:
    df = read_csv_robust(path)
    df = clean_keys(df, "vt_dataset")
    df["first_seen"] = parse_dates(df["first_seen"])

    out = pd.DataFrame()
    out["sha256"] = df["sha256"]
    out["source_origin"] = "vt"  # tenuta solo internamente per i report, tolta prima del salvataggio
    out["file_name"] = df["file_name"]
    out["file_size"] = df["file_size"]
    out["file_type"] = df["file_type"].map(_vt_file_category)
    out["first_seen"] = df["first_seen"]
    out["av_malicious_count"] = df["av_malicious_count"]
    out["av_total_engines"] = df["av_total_engines"]
    out["yara_rules"] = df["yara_rules"]
    out["yara_rules_count"] = _count_pipe(df["yara_rules"])
    out["sandbox_count"] = _count_pipe(df["sandbox_names"])
    out["virus_family"] = df["virus_family"].astype(str).str.lower().str.strip().replace({"nan": pd.NA})
    out["label"] = df["label"]

    # triage_severity: presa diretta, e' gia' calcolata da Virus_Total.py con
    # la stessa formula che replichiamo per mm (vedi _compute_triage_severity).
    # NOTA: questa severity concorre a determinare la label stessa di VT
    # (label=1 se av_malicious_count>=3 OR severity in {HIGH,MEDIUM}) quindi
    # usarla come feature per le righe vt e' in parte circolare - e' cosi'
    # che il dataset e' costruito a monte, non un artefatto del merge.
    out["triage_severity"] = df["triage_severity"]

    # NOTA: vt_sandbox_malware_names rimossa su richiesta (piena di "none"
    # letterali, poco utile as-is). vt_signature_verified/vt_signature_signers
    # rimossi in precedenza (non servono - indicavano solo firma digitale/
    # certificato del file)

    # raw grezzi tenuti per riferimento/audit, MAI da mischiare col corrispettivo mm
    out["av_malicious_list_raw"] = df["av_malicious_list"]
    out["sandbox_categories_raw"] = df["sandbox_categories"]
    out["sandbox_malware_classes_raw"] = df["sandbox_malware_classes"]
    out["sandbox_confidences_raw"] = df["sandbox_confidences"]

    return out


def load_mm(path: Path) -> pd.DataFrame:
    df = read_csv_robust(path)
    df = clean_keys(df, "master_dataset_malware")
    df["first_seen"] = parse_dates(df["first_seen"])

    out = pd.DataFrame()
    out["sha256"] = df["sha256"]
    out["source_origin"] = "mm"
    out["file_name"] = df["file_name"]
    out["file_size"] = df["file_size"]
    out["file_type"] = df["file_type"].map(FILE_CATEGORY_MM).fillna("other")
    out["first_seen"] = df["first_seen"]
    out["av_malicious_count"] = df["av_malicious_count"]
    out["av_total_engines"] = df["av_total_engines"]
    out["yara_rules"] = df["yara_rules"]
    out["yara_rules_count"] = _count_pipe(df["yara_rules"])
    out["sandbox_count"] = _count_pipe(df["sandbox_names"])
    out["virus_family"] = df["virus_family"].astype(str).str.lower().str.strip().replace({"nan": pd.NA})
    out["label"] = df["label"]

    # triage_severity: MB non ha il campo nativo, lo calcolo con la STESSA
    # formula di Virus_Total.py (compute_triage_severity), applicata alle
    # componenti equivalenti di MB (av_malicious_count, av_suspicious_count,
    # av_total_engines, yara_rules, sandbox_categories). Vero calcolo
    # equivalente, non piu' un bucket arbitrario sullo score esterno.
    sb_cat_lists = df["sandbox_categories"].fillna("").apply(lambda x: x.split("|"))
    out["triage_severity"] = [
        _compute_triage_severity(mal, susp, tot, yr, cats)
        for mal, susp, tot, yr, cats in zip(
            df["av_malicious_count"], df["av_suspicious_count"], df["av_total_engines"],
            df["yara_rules"], sb_cat_lists,
        )
    ]

    out["av_malicious_list_raw"] = df["av_malicious_list"]
    out["sandbox_categories_raw"] = df["sandbox_categories"]
    out["sandbox_malware_classes_raw"] = df["sandbox_malware_classes"]
    out["sandbox_confidences_raw"] = df["sandbox_confidences"]

    # NOTA: magika, clamav_detections, yara_rules_count originale vengono
    # scartati volutamente per lo stesso motivo di leakage (vedi sopra);
    # triage invece viene tenuto (score/family) su richiesta esplicita.

    return out


def load_ha(path: Path) -> pd.DataFrame:
    df = read_csv_robust(path)
    df = clean_keys(df, "ha_dataset")

    out = pd.DataFrame()
    out["sha256"] = df["sha256"]
    # Metadefender/crowdstrike e ov_verdict rimossi su richiesta - al momento
    # nessun campo di HA viene portato nel dataset finale, il left-join resta
    # comunque predisposto per aggiungere in futuro altri campi di HA.
    return out


# ---------------------------------------------------------------------------
# 5. COSTRUZIONE DATASET FINALE: concat verticale (vt+mm) poi left-join (ha)
# ---------------------------------------------------------------------------
def build_final_dataset(vt: pd.DataFrame, mm: pd.DataFrame, ha: pd.DataFrame) -> pd.DataFrame:
    core = pd.concat([vt, mm], ignore_index=True)

    n_before = len(core)
    core = core.drop_duplicates(subset="sha256", keep="first")
    if n_before != len(core):
        print(f"  [dedup cross-file] {n_before - len(core)} sha256 duplicati tra vt e mm rimossi")

    final = core.merge(ha, on="sha256", how="left")

    return final


# ---------------------------------------------------------------------------
# 6. MAIN
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ha", required=True, type=Path)
    ap.add_argument("--mm", required=True, type=Path)
    ap.add_argument("--vt", required=True, type=Path)
    ap.add_argument("--outdir", required=True, type=Path)
    args = ap.parse_args()

    args.outdir.mkdir(parents=True, exist_ok=True)

    print("Caricamento e standardizzazione fonti...")
    vt = load_vt(args.vt)
    mm = load_mm(args.mm)
    ha = load_ha(args.ha)
    print(f"  vt={len(vt)}  mm={len(mm)}  ha={len(ha)} righe (dopo pulizia)")

    print("\nCostruzione dataset finale (concat vt+mm su schema comune, poi left-join ha)...")
    final = build_final_dataset(vt, mm, ha)

    # --- report leakage residuo (uso source_origin PRIMA di rimuoverlo) ---
    print("\n--- Controllo colonne ancora fortemente correlate con source_origin ---")
    for col in ["triage_severity"]:
        if col in final.columns:
            not_null_by_origin = final.groupby("source_origin")[col].apply(lambda s: s.notna().mean())
            print(f"  % non-null di '{col}' per source_origin:\n{not_null_by_origin.to_string()}")

    print("\n--- Distribuzione label nel dataset finale ---")
    print(final["label"].value_counts(dropna=False).to_string())
    print("\n--- Righe per source_origin ---")
    print(final["source_origin"].value_counts().to_string())

    final = final.drop(columns=["source_origin"])

    # label spostata come ultima colonna
    cols = [c for c in final.columns if c != "label"] + ["label"]
    final = final[cols]

    out_final = args.outdir / "dataset_finale.csv"
    final.to_csv(out_final, index=False)
    print(f"\n  -> {out_final}  ({len(final)} righe, {len(final.columns)} colonne)")


if __name__ == "__main__":
    main()