"""
pipeline_utils.py
==================
Modulo condiviso da parameters_info.py, header_elf_lief.py e subprocesses.py.

Risolve tre problemi trasversali della pipeline:

1. OSSERVABILITA': un unico logger colorato, con lo stesso formato e lo
   stesso file di log (pipeline.log) per tutti i moduli, cosi' una run
   intera (Fase 1 + Fase 2) e' ricostruibile leggendo un solo file invece
   che rincorrendo print() sparsi e log separati.

2. RESUME: uno stato persistente (pipeline_state.json, ora dentro la
   sottocartella Pipeline_Reports/ invece che sparso nella parent directory)
   condiviso tra Fase 1 e Fase 2, con chiave = hash SHA-256 del contenuto
   del file (non il nome, che puo' ripetersi in cartelle diverse o cambiare
   tra run). Permette di interrompere la pipeline in qualsiasi punto e
   ripartire senza rifare analisi LIEF, tentativi di unpacking gia'
   riusciti, o sessioni IDA gia' concluse.

3. CORRETTEZZA: l'hashing sul contenuto (invece del nome file) elimina le
   collisioni tra campioni omonimi in sottocartelle diverse, che con lo
   storico basato sul solo nome file potevano "coprirsi" a vicenda.
"""
import os
import sys
import json
import re
import time
import threading
import hashlib
import logging
import subprocess
import traceback

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)

# Cartella unica di output della pipeline: raccoglie tutti i report/log/stato
# invece di sparpagliarli direttamente nella parent directory. E' definita
# QUI (fonte unica) e importata da header_elf_lief.py, subprocesses.py e
# header_info.py, cosi' tutti i moduli scrivono sempre nello stesso posto
# senza dover ricalcolare/duplicare lo stesso percorso in ognuno di essi.
OUTPUT_DIR = os.path.join(PARENT_DIR, "Pipeline_Reports")
os.makedirs(OUTPUT_DIR, exist_ok=True)

LOG_PATH = os.path.join(OUTPUT_DIR, "pipeline.log")
STATE_PATH = os.path.join(OUTPUT_DIR, "pipeline_state.json")

# File di servizio, non campioni: vale per chi inventaria e per chi conta.
SERVICE_EXT = {".csv", ".md", ".json", ".txt", ".log", ".yml", ".yaml", ".ini"}


# ==========================================
# LOGGING UNIFICATO
# ==========================================
class ColorFormatter(logging.Formatter):
    GREY = "\x1b[38;20m"
    GREEN = "\x1b[32;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"
    FORMAT = "%(asctime)s - %(name)-12s - %(levelname)-8s - %(message)s"
    DATE_FORMAT = "%H:%M:%S"

    FORMATS = {
        logging.DEBUG: GREY + FORMAT + RESET,
        logging.INFO: GREEN + FORMAT + RESET,
        logging.WARNING: YELLOW + FORMAT + RESET,
        logging.ERROR: RED + FORMAT + RESET,
        logging.CRITICAL: BOLD_RED + FORMAT + RESET,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, self.FORMAT)
        return logging.Formatter(log_fmt, datefmt=self.DATE_FORMAT).format(record)


def setup_logger(name):
    """
    Restituisce un logger condiviso: stessa formattazione a colori su
    console, stesso file pipeline.log in append per tutti i moduli.
    Il parametro 'name' identifica la fase nei log (es. 'Fase1-LIEF',
    'Fase2-Unpack', 'Orchestratore') per poter filtrare/grep facilmente.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        # Il modulo puo' essere importato piu' volte nello stesso processo:
        # evitiamo di duplicare gli handler (altrimenti ogni riga di log
        # verrebbe stampata N volte).
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(ColorFormatter())

    file_handler = logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s - %(name)-12s - %(levelname)-8s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


_state_log = setup_logger("PipelineState")


# ==========================================
# HASHING FILE (chiave stabile cross-run)
# ==========================================
def compute_file_hash(filepath, chunk_size=1024 * 1024):
    """
    SHA-256 del contenuto del file. E' la chiave primaria dello stato della
    pipeline: a differenza del nome file, resta valida anche se il campione
    viene rinominato, spostato o duplicato in sottocartelle diverse.
    Ritorna None se il file non e' leggibile (permessi, file rimosso, ecc.).
    """
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ==========================================
# STATO PERSISTENTE DELLA PIPELINE (RESUME)
# ==========================================
class PipelineState:
    """
    Stato condiviso Fase 1 / Fase 2, salvato in pipeline_state.json dentro
    Pipeline_Reports/ (sottocartella della parent directory). Chiave = sha256 del file.

    Schema indicativo di ogni entry:
    {
      "relpath": str,
      "filename": str,
      "phase1_done": bool,
      "packing_score": int,
      "is_packed": bool,
      "executable_type": str,
      "unpack_attempted": bool,
      "unpack_method": str | None,      # "upx" | "unipacker" | "qiling" | None
      "unpack_success": bool,
      "ghidra_verified": bool,
      "ghidra_func_count": int | None,
      "ida_required": bool,
      "ida_session_done": bool,
      "final_status": str               # "clean" | "unpacked_ok" |
                                         # "unpacked_unverified" | "needs_manual_review"
    }
    """

    # Ogni quanti update si riscrive il file. 1 (il comportamento originale)
    # significa una riscrittura completa per file e una collisione potenziale
    # per file: vedi save().
    SAVE_EVERY = 50
    SAVE_RETRIES = 5

    def __init__(self, path=STATE_PATH):
        self.path = path
        self._data = self._load()
        self._pending = 0

    def _load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                # Stato corrotto: meglio ripartire da zero che bloccare
                # l'intera pipeline con un'eccezione non gestita.
                return {}
        return {}

    def save(self, force=False):
        """Salvataggio BATCHED e NON SOLLEVANTE.

        Due difetti reali, osservati in produzione su un batch da 1.987 file:

        1. `save()` veniva chiamato a ogni `update()`, cioe' una riscrittura
           dell'intero JSON per ogni file: costo O(n^2) sul batch e, soprattutto,
           una finestra di collisione enorme su `os.replace`.
        2. Su Windows `os.replace` fallisce con PermissionError [WinError 5] se
           un altro processo (antivirus, Windows Search, backup) tiene aperto il
           file di destinazione anche solo per un istante. L'eccezione risaliva
           fino al chiamante e **uccideva l'analisi**: la Fase 1 si e' fermata al
           file 945 su 1.987, con exit code 0 e nessun avviso.

        Lo stato e' un ausilio al resume, NON un risultato: un suo fallimento non
        deve mai far perdere l'analisi. Qui si riprova con backoff e, se proprio
        non ci si riesce, si logga e si prosegue.
        """
        self._pending += 1
        if not force and self._pending < self.SAVE_EVERY:
            return True
        tmp_path = f"{self.path}.{os.getpid()}.tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, indent=2, ensure_ascii=False)
        except OSError as e:
            _state_log.warning(f"Stato pipeline non serializzabile su disco: {e}")
            return False

        for attempt in range(self.SAVE_RETRIES):
            try:
                os.replace(tmp_path, self.path)
                self._pending = 0
                return True
            except PermissionError:
                time.sleep(0.15 * (attempt + 1))   # lock transitorio: AV/indexer
            except OSError as e:
                _state_log.warning(f"Salvataggio stato pipeline fallito: {e}")
                break
        _state_log.warning(f"Impossibile aggiornare {os.path.basename(self.path)} dopo "
                           f"{self.SAVE_RETRIES} tentativi: l'analisi prosegue, il resume "
                           f"ripartira' da uno stato meno recente.")
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        return False

    def flush(self):
        """Salvataggio finale forzato: da chiamare a fine batch."""
        return self.save(force=True)

    def get(self, file_hash):
        return self._data.get(file_hash)

    def update(self, file_hash, **fields):
        entry = self._data.setdefault(file_hash, {})
        entry.update(fields)
        self.save()
        return entry

    def all_entries(self):
        return self._data

    def is_fully_resolved(self, file_hash):
        """
        True se il file ha gia' raggiunto un esito definitivo in una run
        precedente (unpacking riuscito e verificato, oppure gia' passato
        manualmente per IDA) e puo' quindi essere saltato in un resume.
        """
        entry = self._data.get(file_hash)
        if not entry:
            return False
        return entry.get("final_status") in ("unpacked_ok", "ida_session_done")


# ==========================================
# LOGGING ESTESO DI ECCEZIONI (diagnostica tool esterni)
# ==========================================
def log_exception_full(logger, prefix, exc, level="warning"):
    """
    Logga un'eccezione con contesto completo invece del solo str(exc).

    Introdotta dopo aver osservato in produzione eccezioni provenienti da
    tool esterni (Qiling/Unicorn, in particolare) il cui str() e' inutile o
    fuorviante per la diagnosi:
      - alcuni errori (es. "UC_ERR_ARG" di Unicorn) non indicano QUALE
        chiamata o QUALE argomento li ha generati;
      - altri hanno come str() un semplice codice numerico grezzo (es.
        "380"), senza alcun contesto leggibile.

    Logga sempre: tipo dell'eccezione (type(exc).__name__, disponibile
    anche quando il messaggio e' vuoto/criptico) al livello indicato
    (default: warning, visibile anche a console), e il traceback completo
    a livello DEBUG (solo su file, per non affollare la console durante un
    batch lungo).

    Centralizzata qui (invece che duplicata in ogni blocco except di
    subprocesses.py) perche' e' esattamente il tipo di funzionalita'
    trasversale che pipeline_utils.py gia' gestisce per il resto della
    pipeline (vedi docstring del modulo, punto 1: OSSERVABILITA').

    Uso tipico:
        try:
            ...
        except Exception as e:
            log_exception_full(log, "Eccezione Qiling", e)
    """
    log_fn = getattr(logger, level, logger.warning)
    log_fn(f"  [!] {prefix} ({type(exc).__name__}): {str(exc)}")
    logger.debug(f"  [DEBUG] Traceback completo ({prefix}):\n{traceback.format_exc()}")


# ==========================================
# ESECUZIONE ROBUSTA DEI TOOL ESTERNI + LOG DIAGNOSTICO PER TOOL
# ==========================================
# Un solo punto di esecuzione per capa/DIE/(e i tool della Fase 2 in seguito): stessa gestione di timeout,
# codifica dell'output e "non trovato", e UNA riga JSON per esecuzione in tool_diagnostics.jsonl (nella stessa
# cartella dei report) con comando, exit code, durata, stato e testa di stdout/stderr. Serve a capire PERCHE' un
# tool ha fallito senza dover rileggere tutto pipeline.log: e' il file da allegare quando qualcosa non torna.
TOOL_DIAG_PATH = os.path.join(OUTPUT_DIR, "tool_diagnostics.jsonl")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def sanitize_tool_text(text):
    """Toglie i codici ANSI e comprime gli spazi: l'output 'rich' di capa va a capo a colonne fisse e spezza le frasi."""
    return re.sub(r"\s+", " ", _ANSI_RE.sub("", text or "")).strip()


def _kill_process_tree(proc):
    """Su Windows capa.exe (launcher pip) genera un python figlio: proc.kill() lascerebbe l'analisi in esecuzione."""
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, timeout=15)
        else:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def run_external(tool, cmd, timeout, target=None, ok_returncodes=(0,), stop_on_stderr=None, probe_timeout=None,
                 stderr_normalizer=None):
    """
    Esegue `cmd` e ritorna un dict: tool, target, cmd, status, rc, duration_s, stdout, stderr (+ first_match_s).
    status: "ok" (rc in ok_returncodes) | "rc_error" | "timeout" | "not_found" | "exception"
            | "stopped_early" | "probe_timeout" (solo con lo streaming, vedi sotto).
    Non solleva mai: il chiamante decide cosa fare in base allo status. Al timeout uccide l'intero albero.
    Output decodificato in UTF-8 con errors='replace' (il default cp1252 di Windows fa fallire il parsing).

    STREAMING (opzionale, per tool lenti che annunciano su stderr il risultato che interessa prima di finire):
      stop_on_stderr : frasi (minuscolo) da cercare nello stderr normalizzato mentre il processo gira; alla prima
                       corrispondenza il processo viene ucciso -> status "stopped_early", first_match_s = quando.
      probe_timeout  : se entro questi secondi non e' comparsa nessuna frase, il processo viene ucciso ->
                       status "probe_timeout" (nessuna evidenza entro la finestra di sondaggio).
      stderr_normalizer : funzione str->str applicata allo stderr prima della ricerca (default sanitize_tool_text).
    """
    res = {"tool": tool, "target": os.path.basename(target) if target else None, "cmd": " ".join(str(c) for c in cmd),
           "status": "exception", "rc": None, "duration_s": 0.0, "stdout": "", "stderr": ""}
    t0 = time.monotonic()
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                encoding="utf-8", errors="replace")
    except FileNotFoundError:
        res["status"] = "not_found"
        res["stderr"] = f"eseguibile non trovato: {cmd[0]}"
        return res
    except Exception as e:
        res["stderr"] = f"{type(e).__name__}: {e}"
        return res

    needles = tuple(n.lower() for n in (stop_on_stderr or ()))
    streaming = bool(needles or probe_timeout)
    try:
        if not streaming:
            try:
                out, err = proc.communicate(timeout=timeout)
                res["status"] = "ok" if proc.returncode in ok_returncodes else "rc_error"
            except subprocess.TimeoutExpired:
                _kill_process_tree(proc)
                try:
                    out, err = proc.communicate(timeout=15)
                except Exception:
                    out, err = "", ""
                res["status"] = "timeout"
        else:
            normalize = stderr_normalizer or sanitize_tool_text
            out_parts, err_parts = [], []

            def _pump(pipe, sink):
                try:
                    for line in iter(pipe.readline, ""):
                        sink.append(line)
                except Exception:
                    pass

            threads = [threading.Thread(target=_pump, args=(proc.stdout, out_parts), daemon=True),
                       threading.Thread(target=_pump, args=(proc.stderr, err_parts), daemon=True)]
            for th in threads:
                th.start()

            checked = 0
            while True:
                elapsed = time.monotonic() - t0
                if proc.poll() is not None:
                    res["status"] = "ok" if proc.returncode in ok_returncodes else "rc_error"
                    break
                if needles and len(err_parts) != checked:
                    checked = len(err_parts)
                    text = normalize("".join(err_parts)).lower()
                    if any(n in text for n in needles):
                        res["status"], res["first_match_s"] = "stopped_early", round(elapsed, 2)
                        _kill_process_tree(proc)
                        break
                if elapsed > timeout:
                    res["status"] = "timeout"
                    _kill_process_tree(proc)
                    break
                if probe_timeout and elapsed > probe_timeout:
                    res["status"] = "probe_timeout"
                    _kill_process_tree(proc)
                    break
                time.sleep(0.2)
            try:
                proc.wait(timeout=15)
            except Exception:
                pass
            for th in threads:
                th.join(timeout=5)
            out, err = "".join(out_parts), "".join(err_parts)
            if res["status"] == "ok" and needles:   # finito da solo: la frase potrebbe essere nell'ultimo blocco
                if any(n in normalize(err).lower() for n in needles):
                    res["first_match_s"] = round(time.monotonic() - t0, 2)
    except Exception as e:
        _kill_process_tree(proc)
        out, err = "", f"{type(e).__name__}: {e}"

    res["rc"] = proc.returncode
    res["duration_s"] = round(time.monotonic() - t0, 2)
    res["stdout"], res["stderr"] = out or "", err or ""
    return res


def write_tool_diag(run, **parsed):
    """Aggiunge a tool_diagnostics.jsonl la riga di UN'esecuzione: dati grezzi di run_external (o un dict con
    tool/target/status) piu' l'interpretazione fatta dal chiamante (**parsed). Non solleva mai."""
    try:
        rec = {"ts": time.strftime("%Y-%m-%d %H:%M:%S")}
        for k in ("tool", "target", "status", "rc", "duration_s", "cmd"):
            if k in run:
                rec[k] = run[k]
        if run.get("stdout"):
            rec["stdout_len"] = len(run["stdout"])
            rec["stdout_head"] = run["stdout"][:200]
        if run.get("stderr"):
            rec["stderr_head"] = sanitize_tool_text(run["stderr"])[:400]
        rec.update(parsed)
        with open(TOOL_DIAG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        pass