"""
make_dataset_index.py
=====================
Genera `E:\\DATASET\\INDICE.md`: la mappa dei dataset, ricavata dai FATTI e non
scritta a mano.

Perche' generato e non redatto
------------------------------
Un indice scritto a mano va fuori sincrono al primo file aggiunto, e a quel punto
mente - che e' esattamente il difetto di `TEST_BIN_PULITI`, chiamata "puliti"
mentre conteneva malware. Qui ogni riga viene calcolata:

  - il numero di file si conta sul disco;
  - la label e l'oracolo si leggono da `ground_truth.json`;
  - l'aggancio fra i due e' lo **SHA-256 del contenuto**, mai il nome o il
    percorso, perche' il percorso e' appena cambiato e il nome puo' ripetersi.

Cosa segnala, oltre al conteggio
--------------------------------
  - i file su disco che NON hanno una voce nel manifest (orfani): sono campioni
    che nessuna metrica vedra' mai, ed e' meglio saperlo;
  - le voci del manifest il cui file non e' piu' su disco (label orfane);
  - per ogni gruppo, se concorre o no alle metriche di validazione: un gruppo
    concorre solo per i file con label diversa da `unknown`.

Uso
---
    python scripts/make_dataset_index.py
    python scripts/make_dataset_index.py --root E:/DATASET --out E:/DATASET/INDICE.md
"""
import argparse
import collections
import hashlib
import json
import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import OUTPUT_DIR, SERVICE_EXT  # noqa: E402

GT_PATH = os.path.join(OUTPUT_DIR, "ground_truth.json")
DEFAULT_ROOT = os.path.join("E:" + os.sep, "DATASET")
PROJ_DIR = os.path.dirname(SCRIPT_DIR)

# Cartelle di dataset che NON vivono sotto la radice. Vuota dal 27/09/2026: anche i
# campioni PMA, l'ultima eccezione (erano versionati in git), sono stati spostati sotto
# la radice come 01_LABEL_CERTA\pma_book. Il meccanismo resta perche' serve al primo
# dataset che non potra' stare su E:.
EXTRA_DIRS = []

# Descrizione dell'oracolo, per come e' registrato nel campo `source` del manifest.
ORACOLI = {
    "pack_samples_matrix": "packer eseguito da noi (label certa al 100 %)",
    "pack_samples": "packer eseguito da noi, prima versione dello script",
    "authenticode-ms": "firma Authenticode Microsoft valida",
    "upx-t": "`upx -t`: e' UPX stesso a confermare di poter decomprimere",
    "manual": "verifica manuale documentata",
    "compilato-in-proprio": "compilati da noi, comando di build registrato",
    "wheel-pypi": "wheel ufficiali da PyPI installate via pip: provenienza, "
                  "non verifica strutturale",
    "dist-ufficiale-non-ms": "binari da distribuzioni ufficiali non-Microsoft "
                             "(MSYS2, Cygwin, VLC, PuTTY, Notepad++, curl), digest "
                             "upstream verificato dove pubblicato: provenienza, "
                             "non verifica strutturale",
    "auto-scan": "nessun oracolo: inventario, label `unknown`",
}


def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for c in iter(lambda: f.read(chunk), b""):
                h.update(c)
    except OSError:
        return None
    return h.hexdigest()


def leaf_dirs(root):
    """Cartelle foglia (quelle che contengono i campioni), con il gruppo di appartenenza."""
    out = []
    if not os.path.isdir(root):
        return out
    for group in sorted(os.listdir(root)):
        gpath = os.path.join(root, group)
        if not os.path.isdir(gpath):
            continue
        subs = sorted(d for d in os.listdir(gpath) if os.path.isdir(os.path.join(gpath, d)))
        if subs:
            for sub in subs:
                out.append((group, sub, os.path.join(gpath, sub)))
        else:
            out.append((group, "", gpath))
    return out


def scan_dir(path, gt):
    """(n_file, Counter(label), Counter(source), n_orfani, hash_visti, n_servizio)"""
    labels = collections.Counter()
    sources = collections.Counter()
    seen = set()
    n = orphans = service = 0
    for dp, _dirs, names in os.walk(path):
        for name in names:
            fp = os.path.join(dp, name)
            if os.path.splitext(name)[1].lower() in SERVICE_EXT:
                service += 1
                continue
            n += 1
            h = sha256(fp)
            if not h:
                continue
            entry = gt.get(h)
            if entry is None:
                orphans += 1
                continue
            seen.add(h)
            labels[entry.get("label", "?")] += 1
            sources[entry.get("source") or "?"] += 1
    return n, labels, sources, orphans, seen, service


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=DEFAULT_ROOT, help=f"Radice dei dataset (default: {DEFAULT_ROOT}).")
    ap.add_argument("--out", default=None, help="File di output (default: <root>/INDICE.md).")
    args = ap.parse_args()

    out_path = args.out or os.path.join(args.root, "INDICE.md")
    with open(GT_PATH, "r", encoding="utf-8") as f:
        gt = json.load(f)

    groups = leaf_dirs(args.root) + [("(fuori radice)", label, path)
                                     for path, label in EXTRA_DIRS if os.path.isdir(path)]
    if not groups:
        sys.exit(f"Nessuna cartella di dataset trovata sotto {args.root}")

    rows = []
    all_seen = set()
    t0 = time.monotonic()
    for group, sub, path in groups:
        print(f"  scansione {group}/{sub or ''} ...", flush=True)
        n, labels, sources, orphans, seen, service = scan_dir(path, gt)
        all_seen |= seen
        rows.append(dict(group=group, sub=sub, path=path, n=n, labels=labels,
                         sources=sources, orphans=orphans, service=service))
    elapsed = time.monotonic() - t0

    # label nel manifest il cui file non e' stato trovato in nessuna cartella scansionata
    dangling = [h for h in gt if h not in all_seen and gt[h].get("label") != "unknown"]

    tot = sum(r["n"] for r in rows)
    tot_lab = sum(sum(v for k, v in r["labels"].items() if k != "unknown") for r in rows)

    L = []
    A = L.append
    A("# Indice dei dataset")
    A("")
    A(f"> **Generato automaticamente** da `scripts/make_dataset_index.py` il "
      f"{time.strftime('%d/%m/%Y %H:%M')}. Non modificare a mano: rilancia lo script.")
    A(">")
    A(f"> Radice: `{args.root}` \u00b7 manifest: `{GT_PATH}`")
    A(">")
    A("> L'aggancio fra file su disco e label \u00e8 lo **SHA-256 del contenuto**, non il percorso "
      "n\u00e9 il nome: \u00e8 l'unico identificatore stabile di un campione.")
    A("")
    A(f"**{tot} file** in {len(rows)} cartelle \u00b7 **{tot_lab} etichettati** "
      f"(concorrono alle metriche) \u00b7 scansione in {elapsed:.0f} s")
    A("")
    A("## Riepilogo")
    A("")
    A("| gruppo | cartella | file | label | oracolo | metriche |")
    A("|---|---|---|---|---|---|")
    for r in rows:
        lab = " \u00b7 ".join(f"{v} {k}" for k, v in sorted(r["labels"].items(),
                                                            key=lambda x: -x[1])) or "\u2014"
        src = ", ".join(f"`{k}`" for k, _ in r["sources"].most_common(3)) or "\u2014"
        n_lab = sum(v for k, v in r["labels"].items() if k != "unknown")
        if n_lab == r["n"] and n_lab:
            metr = "\u2705 tutti"
        elif n_lab:
            metr = f"\u26a0\ufe0f {n_lab}/{r['n']}"
        else:
            metr = "\u274c no"
        A(f"| `{r['group']}` | `{r['sub'] or '.'}` | {r['n']} | {lab} | {src} | {metr} |")
    A("")

    A("## Dettaglio per cartella")
    A("")
    for r in rows:
        A(f"### `{r['group']}/{r['sub']}`" if r["sub"] else f"### `{r['group']}`")
        A("")
        A(f"- percorso: `{r['path']}`")
        A(f"- campioni su disco: **{r['n']}**"
          + (f" (più {r['service']} file di servizio: manifest, note)" if r["service"] else ""))
        if r["labels"]:
            A("- label: " + " \u00b7 ".join(f"**{v}** `{k}`" for k, v in
                                            sorted(r["labels"].items(), key=lambda x: -x[1])))
        for src, cnt in r["sources"].most_common():
            A(f"- oracolo `{src}` ({cnt} file): {ORACOLI.get(src, 'non documentato')}")
        n_lab = sum(v for k, v in r["labels"].items() if k != "unknown")
        if n_lab:
            A(f"- **concorre alle metriche** con {n_lab} file su {r['n']}")
        else:
            A("- **non concorre alle metriche**: nessuna label diversa da `unknown`")
        if r["orphans"]:
            A(f"- \u26a0\ufe0f **{r['orphans']} file senza voce nel manifest**: "
              f"nessuna metrica li vedr\u00e0. Registrali con "
              f"`build_ground_truth.py --scan \"{r['path']}\" --dataset <nome>`")
        A("")

    if dangling:
        A("## \u26a0\ufe0f Label senza file su disco")
        A("")
        A(f"{len(dangling)} voci del manifest hanno una label diversa da `unknown` ma il loro file "
          "non \u00e8 stato trovato in nessuna cartella scansionata. Possono essere campioni "
          "spostati fuori dalla radice o cancellati.")
        A("")
        for h in sorted(dangling)[:20]:
            e = gt[h]
            A(f"- `{e.get('filename', h[:16])}` \u2014 {e.get('label')} da `{e.get('source')}` "
              f"(dataset storico: `{e.get('dataset')}`)")
        if len(dangling) > 20:
            A(f"- ... e altre {len(dangling) - 20}")
        A("")

    A("## Come leggere la colonna \"metriche\"")
    A("")
    A("- \u2705 **tutti**: ogni file del gruppo ha una label da un oracolo esterno, quindi entra "
      "nella matrice di confusione.")
    A("- \u26a0\ufe0f **n/N**: solo una parte \u00e8 etichettata; il resto \u00e8 `unknown` ed "
      "\u00e8 **escluso** dalle metriche, non contato come errore.")
    A("- \u274c **no**: gruppo di sola analisi qualitativa. Non pu\u00f2 produrre n\u00e9 falsi "
      "positivi n\u00e9 falsi negativi, perch\u00e9 non esiste una risposta di riferimento.")
    A("")
    A("Regola del progetto: **nessuna scansione automatica pu\u00f2 assegnare `clean`.** "
      "\"Non \u00e8 packed\" richiede un oracolo, non l'assenza di segnalazioni.")

    with open(out_path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(L) + "\n")

    print()
    print(f"  {tot} file, {tot_lab} etichettati")
    orph = sum(r["orphans"] for r in rows)
    if orph:
        print(f"  [!] {orph} file senza voce nel manifest")
    if dangling:
        print(f"  [!] {len(dangling)} label senza file su disco")
    print(f"  indice scritto in {out_path}")


if __name__ == "__main__":
    main()
