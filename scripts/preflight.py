"""
preflight.py
============
Verifica che l'ambiente sia in grado di eseguire la Fase 1, e dice **esattamente
cosa manca e dove correggerlo**.

Perche' serve
-------------
I percorsi degli strumenti esterni sono costanti dentro gli script, non in un file di
configurazione. Su un'altra macchina non combaciano, e senza questo controllo il
fallimento arriva a meta' di un batch con un messaggio oscuro. Qui arriva prima, e
con il nome del file e della costante da modificare.

Uso
---
    python scripts/preflight.py
    python scripts/preflight.py --fase2      # verifica anche lo stack di emulazione
    python scripts/preflight.py --packer     # verifica anche i packer (pack_samples.py)

Esce con codice 0 se la Fase 1 e' eseguibile, 1 altrimenti.
"""
import argparse
import importlib
import json
import os
import signal
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
sys.path.insert(0, SCRIPT_DIR)

OK, WARN, ERR = "  [ok]  ", "  [!!]  ", "  [XX]  "
problemi = []
avvisi = []


def errore(msg, dove=None):
    problemi.append(msg)
    print(ERR + msg)
    if dove:
        print(" " * 8 + "-> " + dove)


def avviso(msg, dove=None):
    avvisi.append(msg)
    print(WARN + msg)
    if dove:
        print(" " * 8 + "-> " + dove)


def buono(msg):
    print(OK + msg)


# ===========================================================================
def check_python():
    print("\n--- Interprete ---")
    v = sys.version_info
    buono(f"Python {v.major}.{v.minor}.{v.micro} ({sys.executable})")
    if v < (3, 9):
        errore(f"Python {v.major}.{v.minor} troppo vecchio: serve almeno 3.9.")
    venv = os.environ.get("VIRTUAL_ENV") or (".venv" in sys.executable.replace("\\", "/"))
    if not venv:
        avviso("Non sembra un ambiente virtuale.",
               "sul progetto originale convivono due interpreti con LIEF di major "
               "diverso e solo quello del .venv funziona: usa un venv dedicato.")


def check_pacchetti(fase2=False):
    print("\n--- Pacchetti Python ---")
    richiesti = [
        ("lief", "lief", True, "parsing PE/ELF"),
        ("yara", "yara-python", True, "motore delle regole YARA"),
    ]
    opzionali = [
        ("capa", "flare-capa", False, "solo per --capa-mode full"),
        ("requests", "requests", False, "solo per scripts/extraction.py"),
        ("pyzipper", "pyzipper", False, "solo per scripts/extraction.py"),
    ]
    if fase2:
        opzionali += [
            ("qiling", "qiling", False, "Fase 2: emulazione"),
            ("unicorn", "unicorn", False, "Fase 2: motore di emulazione"),
            ("pefile", "pefile", False, "Fase 2"),
        ]
    for mod, pkg, obbl, nota in richiesti + opzionali:
        try:
            m = importlib.import_module(mod)
            ver = getattr(m, "__version__", "?")
            buono(f"{pkg:<14} {ver:<12} {nota}")
            if mod == "lief":
                major = str(ver).split(".")[0]
                if major == "0":
                    errore(f"LIEF {ver}: l'API 1.x non e' compatibile con la 0.x, la pipeline non gira.",
                           "python -m pip install lief==1.0.0")
        except ImportError:
            if obbl:
                errore(f"{pkg} NON installato ({nota}).",
                       "python -m pip install -r requirements-fase1.txt")
            else:
                avviso(f"{pkg} non installato ({nota}).", f"python -m pip install {pkg}")


def _kill_tree(proc):
    """Uccide l'INTERO albero del processo.

    Serve perche' la GUI di DIE parte quasi sempre da un wrapper (AppImage, script in
    /usr/bin, launcher della release portable): un proc.kill() secco uccide il wrapper e
    lascia la finestra aperta sullo schermo, che e' esattamente il sintomo che questa
    sonda deve evitare di produrre.
    """
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=15)
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _probe_diec(path, args, timeout=25):
    """Verifica che `path` sia la variante CONSOLE di Detect It Easy, non la grafica.

    Perche' non basta os.path.isfile
    -------------------------------
    DIE distribuisce DUE eseguibili, spesso nella stessa cartella:
      - `diec` / `diec.exe`  -> console: stampa JSON ed esce. E' quella che serve.
      - `die`  / `die.exe`   -> grafica: apre una finestra.
    Puntare DIEC_PATH alla seconda supera il controllo di esistenza, e il guasto emerge
    solo a batch avviato: la GUI riceve "-j" come NOME DEL FILE da aprire, mostra una
    finestra per ogni campione, va in timeout dopo DIE_TIMEOUT secondi e lascia
    Die_Status != "ok" su tutta la run. Il risultato e' che si perde in silenzio la
    fonte di segnale piu' discriminante della Fase 1 (92 % sui packed, 0 % sui clean):
    la pipeline "gira" ma declassa ogni verdetto, e niente lo dichiara.

    Si verifica quindi il COMPORTAMENTO, non il nome del file: si esegue lo stesso
    identico comando della Fase 1 (DIEC_PATH + DIE_ARGS + un binario vero) e si guarda
    se torna JSON in pochi secondi. Il bersaglio e' sys.executable: un PE/ELF reale,
    sempre presente, che non va procurato.

    Ritorna (esito, dettaglio), esito in: "console" | "gui" | "no_json" | "errore".
    """
    try:
        proc = subprocess.Popen([path] + list(args) + [sys.executable],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, encoding="utf-8", errors="replace",
                                # nuova sessione: da' a _kill_tree un process group da
                                # abbattere, cosi' nemmeno il caso peggiore lascia finestre.
                                start_new_session=(os.name != "nt"))
    except FileNotFoundError:
        return "errore", "file presente ma non avviabile (permessi? architettura?)"
    except Exception as e:
        return "errore", f"{type(e).__name__}: {e}"

    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=10)
        except Exception:
            pass
        return "gui", f"nessun output in {timeout}s: resta in attesa, come fa una finestra"

    # La console stampa JSON. Si parsa come in run_die_analysis (dal primo '{'), invece di
    # cercare una chiave fissa: lo schema di DIE cambia tra versioni, il fatto che sia JSON no.
    brace = out.find("{")
    if brace >= 0:
        try:
            json.loads(out[brace:])
            return "console", ""
        except json.JSONDecodeError:
            pass
    if not out.strip():
        # Nessuno stdout. Due casi diversi, che meritano due diagnosi diverse:
        # se ha scritto su stderr si e' lamentato di qualcosa (tipicamente "-j" non
        # riconosciuto) e quel messaggio E' la diagnosi migliore disponibile, quindi
        # va riportato invece di essere sostituito da una supposizione; se e' muto
        # del tutto, ha lanciato una finestra e si e' sganciato.
        if err.strip():
            return "no_json", err.strip().splitlines()[0][:120]
        return "gui", f"uscito subito (rc={proc.returncode}) e in silenzio"
    return "no_json", out.strip().splitlines()[0][:120]


def check_tool_fase1():
    print("\n--- Strumenti esterni della Fase 1 ---")
    try:
        import header_elf_lief as HL
    except Exception as e:
        errore(f"header_elf_lief non importabile: {e}")
        return
    # DIE: obbligatorio, e' una delle fonti di segnale FORTE.
    # Non basta che il file esista: deve essere la variante CONSOLE (vedi _probe_diec).
    if not os.path.isfile(HL.DIEC_PATH):
        errore(f"DIE NON trovato in {HL.DIEC_PATH}",
               "scarica la release portable di Detect It Easy e correggi "
               "DIEC_PATH in scripts/header_elf_lief.py")
    else:
        esito, dettaglio = _probe_diec(HL.DIEC_PATH, HL.DIE_ARGS)
        if esito == "console":
            buono(f"Detect It Easy    {HL.DIEC_PATH}  (console, JSON ok)")
        elif esito == "gui":
            errore(f"DIE: {HL.DIEC_PATH} e' la variante GRAFICA, non la console "
                   f"({dettaglio}).",
                   "DIE ha due eseguibili: 'diec' (console, quella che serve) e 'die' (GUI). "
                   "Con la GUI la Fase 1 apre una finestra per ogni campione, va in timeout e "
                   "lascia Die_Status != 'ok' su tutto il batch, perdendo il segnale piu' forte. "
                   "Punta DIEC_PATH a 'diec' in scripts/header_elf_lief.py, poi rianalizza "
                   "con --reanalyze.")
        elif esito == "no_json":
            errore(f"DIE: {HL.DIEC_PATH} non produce JSON con "
                   f"{' '.join(HL.DIE_ARGS)} ({dettaglio}).",
                   "provalo a mano: <diec> " + " ".join(HL.DIE_ARGS) + " <un binario>. "
                   "Deve stampare JSON e uscire. Se apre una finestra e' la variante grafica.")
        else:
            errore(f"DIE non eseguibile ({dettaglio}).",
                   "DIEC_PATH in scripts/header_elf_lief.py")
    # capa: opzionale
    if os.path.isfile(HL.CAPA_PATH):
        buono(f"capa              {HL.CAPA_PATH}")
    else:
        avviso(f"capa.exe non trovato in {HL.CAPA_PATH} (irrilevante con CAPA_MODE='off')",
               "CAPA_PATH in scripts/header_elf_lief.py")
    # YARA: cache compilata oppure sorgenti
    if os.path.isfile(HL.COMPILED_CACHE):
        mb = os.path.getsize(HL.COMPILED_CACHE) / 1e6
        buono(f"regole YARA       cache compilata, {mb:.0f} MB")
    elif os.path.isdir(HL.RULES_DIR):
        avviso("cache YARA assente ma ci sono i sorgenti: verranno compilati al primo avvio (lento).")
    else:
        errore(f"nessuna regola YARA: manca sia {HL.COMPILED_CACHE} sia {HL.RULES_DIR}",
               "scarica il pacchetto YARA-Forge in config/yara-forge/ "
               "(l'analisi puo' procedere senza, ma perde una fonte di segnale forte)")


def check_tool_packer():
    print("\n--- Packer (servono solo a scripts/pack_samples.py) ---")
    try:
        import pack_samples as P
    except Exception as e:
        errore(f"pack_samples non importabile: {e}")
        return
    tool = [("UPX", P.UPX_PATH), ("MPRESS", P.MPRESS_PATH), ("VMProtect", P.VMPROTECT_PATH),
            ("Themida x86", P.THEMIDA_X86[0]), ("Themida x64", P.THEMIDA_X64[0]),
            ("NSIS", P.MAKENSIS_PATH), ("Inno Setup", P.ISCC_PATH)]
    for nome, path in tool:
        if os.path.isfile(path):
            buono(f"{nome:<14} {path}")
        else:
            avviso(f"{nome} non trovato: {path}",
                   f"costante in scripts/pack_samples.py (serve solo per rigenerare la matrice)")
    for nome, proj in [("progetto Themida x86", P.THEMIDA_X86[1]), ("progetto Themida x64", P.THEMIDA_X64[1])]:
        if not os.path.isfile(proj):
            avviso(f"{nome} .tmd assente: {proj}",
                   "va creato una volta sola dalla GUI di Themida e poi riusato")


def check_dati():
    print("\n--- Dati e artefatti ---")
    try:
        from pipeline_utils import OUTPUT_DIR
    except Exception as e:
        errore(f"pipeline_utils non importabile: {e}")
        return
    buono(f"cartella di output {OUTPUT_DIR}")
    for nome, f, obbl in [("CSV dei risultati", "report_analisi_lief.csv", False),
                          ("ground truth", "ground_truth.json", False)]:
        p = os.path.join(OUTPUT_DIR, f)
        if os.path.isfile(p):
            buono(f"{nome:<18} {os.path.getsize(p) / 1e6:.1f} MB")
        else:
            avviso(f"{nome} assente ({f}): verra' creato al primo run.")

    try:
        import pack_samples as P
        radici = [("sorgenti master", d) for d, _ in P.SOURCES] + \
                 [("master", P.MASTERS_DIR), ("matrice packed", P.OUTPUT_DIR)]
        mancanti = [(n, d) for n, d in radici if not os.path.isdir(d)]
        if not mancanti:
            buono("tutte le cartelle dei dataset esistono")
        else:
            for n, d in mancanti:
                avviso(f"cartella {n} assente: {d}",
                       "i dataset non sono nello zip (troppo grandi): vedi docs/03_setup_e_esecuzione.md")
    except Exception:
        pass


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fase2", action="store_true", help="verifica anche lo stack di emulazione")
    ap.add_argument("--packer", action="store_true", help="verifica anche i packer")
    args = ap.parse_args()

    print("=" * 72)
    print("PREFLIGHT — verifica dell'ambiente per la Fase 1")
    print("=" * 72)
    check_python()
    check_pacchetti(args.fase2)
    check_tool_fase1()
    if args.packer:
        check_tool_packer()
    check_dati()

    print("\n" + "=" * 72)
    if problemi:
        print(f"NON eseguibile: {len(problemi)} problemi bloccanti, {len(avvisi)} avvisi.")
        for p in problemi:
            print("   - " + p)
        print("=" * 72)
        return 1
    print(f"Fase 1 ESEGUIBILE. {len(avvisi)} avvisi (non bloccanti).")
    print("\nProssimo passo:")
    print('   python scripts/parameters_info.py --dir "<cartella>" --phase1-only')
    print("=" * 72)
    return 0


if __name__ == "__main__":
    sys.exit(main())
