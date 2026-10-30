import os
import csv
import yara
import lief
import glob
import subprocess
import json
import shutil
import zipfile
import io
import urllib.request
import re
import sys
import math
import time
from collections import Counter

from pipeline_utils import (setup_logger, compute_file_hash, PipelineState, OUTPUT_DIR, log_exception_full,
                            run_external, write_tool_diag, sanitize_tool_text, TOOL_DIAG_PATH)

# ==========================================
# GESTIONE PERCORSI GLOBALI (Parent Directory)
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)

# ==========================================
# LOGGING UNIFICATO (vedi pipeline_utils.py)
# ==========================================
# Nota: il vecchio file di log dedicato "analisi_lief.log" e' stato
# sostituito da un unico "pipeline.log" condiviso con Fase 2, cosi' una run
# intera e' ricostruibile da un solo posto (osservabilita' end-to-end).
log = setup_logger("Fase1-LIEF")

# ==========================================
# CONFIGURAZIONE SCRIPT E SOGLIE SCORING
# ==========================================
# OUTPUT_DIR e' importato da pipeline_utils.py (fonte unica, condivisa anche
# da subprocesses.py e header_info.py): raccoglie tutti i report della
# pipeline in un'unica sottocartella della parent directory invece di
# sparpagliarli al suo interno.
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "report_analisi_lief.csv")

VALID_EXTENSIONS = {".exe", ".dll", ".elf", ".sys", ".scr", "", ".bin"}
# FIX (falsi positivi): l'elenco originale non conosceva le sezioni normali di MinGW/GCC/MSVC
# (.CRT, .tls, .xdata, .didat, .buildid, /4 /19 = nomi DWARF...). Risultato osservato sul batch
# reale: "nomi sezione non standard" scattava su 32/38 file, quindi non discriminava nulla.
STANDARD_SECTIONS = [
    # PE - comuni
    ".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".idata", ".edata", ".pdata",
    ".crt", ".tls", ".xdata", ".didat", ".buildid", ".gfids", ".giats", ".gehcont", ".00cfg",
    # PE - Delphi/Borland: sono nomi prodotti dal COMPILATORE, non da un packer.
    # Senza di essi un binario Delphi normale prende due deboli ("EP in sezione non
    # standard" + "nomi sezione non standard") che con l'euristica DIE fanno 3.
    # Misurato su un malware Delphi reale (188 import, .text a H 6.43): era un falso
    # positivo. Costo: 53 packed hanno .itext/.didata (sono gli installer Inno, che E'
    # un programma Delphi) ma TUTTI hanno segnali forti, quindi 0 veri positivi persi.
    ".itext", ".didata",
    ".voltbl", ".retplne", ".drectve", ".sxdata", ".ctors", ".dtors", ".eh_fram", ".stab", ".stabstr",
    "code", "text", "data", "bss", ".code",
    # ELF - comuni
    ".rodata", ".symtab", ".strtab", ".shstrtab", ".init", ".fini", ".plt", ".plt.got", ".plt.sec",
    ".got", ".got.plt", ".dynamic", ".dynsym", ".dynstr", ".interp", ".comment", ".eh_frame",
    ".eh_frame_hdr", ".gcc_except_table", ".init_array", ".fini_array", ".tdata", ".tbss",
    ".hash", ".gnu.hash", ".rela.dyn", ".rela.plt", ".data.rel.ro", ".note.gnu.build-id",
    ".note.gnu.property", ".note.ABI-tag", ".gnu.version", ".gnu.version_r",
]
STANDARD_SECTION_PREFIXES = (".debug", ".note", ".gnu", ".rela", ".rel.", ".text.", ".data.", ".rodata.", ".bss.")

# Sezioni dei binari Windows KERNEL-MODE e dei boot loader. Non sono nomi "strani": sono la
# convenzione documentata del kernel, dove la memoria e' divisa per comportamento di paging
# (PAGE* = pagabile, INIT* = scartata dopo l'inizializzazione) invece che per tipo di contenuto.
# Senza questo elenco il segnale "nomi sezione non standard" scattava su 12 binari di sistema
# firmati Microsoft: ntoskrnl, ntdll, winload, winresume, hvax64/hvix64, tcblaunch, i trasporti
# del kernel debugger kd_*, mcupdate. Misurato sui file reali, non dedotto: le famiglie PAGE* e
# INIT* coprono da sole 10 varianti (PAGELK, PAGEKD, PAGEVRFY, PAGEHDLS, PAGEBGFX, PAGEDATA,
# PAGEVRFD, PAGEUPDT, PAGER32C, INITKDBG, INITDATA...).
# Nessuno dei 19 campioni packed del dataset usa questi nomi, quindi l'aggiunta non indebolisce
# il segnale sui packer reali.
KERNEL_SECTION_PREFIXES = ("page", "init")
KERNEL_SECTIONS = [
    "poolcode", "tracesup", "kvascode", "retpol", "miniex", "almostro", "cachealign", "cacheali",
    "cfgro", "protdata", "mcdata", "const", "transit", "rt", "gfids", ".mrdata", "kvasinit",
    "poolmi", "spcode", "erpage", "nonpage",
]
STANDARD_SECTIONS += KERNEL_SECTIONS

# Sezioni tipiche di packer/installer NOMINATI (prefissi lowercase). Un match e' un segnale FORTE,
# con lo stesso ragionamento del match YARA su nome di packer: identifica il packer per nome, ma e'
# banalmente evadibile (basta rinominare la sezione) - va dichiarato come limite in tesi.
PACKER_SECTION_PREFIXES = {
    "upx": "UPX", ".upx": "UPX", ".mpress": "MPRESS", ".aspack": "ASPack", ".adata": "ASPack/ASProtect",
    ".ndata": "NSIS", ".vmp": "VMProtect", ".themida": "Themida", ".winlice": "Themida/WinLicense",
    ".petite": "Petite", ".nsp": "NsPack", ".pec": "PECompact", ".packed": "generico", ".enigma": "Enigma",
    ".perplex": "PELock", ".pelock": "PELock",
}


def read_magic(filepath, n=4):
    """Primi byte del file, per decidere se e' un eseguibile PRIMA di spendere tool su di esso."""
    try:
        with open(filepath, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def is_executable_magic(magic):
    """PE (MZ) o ELF. E' il criterio vero: l'estensione e' solo un filtro rapido."""
    return magic[:2] == b"MZ" or magic[:4] == b"ELF"


def _txt(value):
    """Testo SEMPRE come str. LIEF restituisce `bytes` quando un nome (sezione, import, simbolo) non e' UTF-8 valido,
    tipico dei packer con nomi binari: senza normalizzare, ogni .lower()/.startswith() sollevava TypeError e l'intero
    file veniva scartato dall'analisi - proprio i binari piu' offuscati."""
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value).strip(b"\x00")
        # nome binario (non UTF-8): si rende come ASCII con \xNN, cosi' CSV e log restano leggibili e confrontabili
        value = "".join(chr(b) if 0x20 <= b < 0x7f else f"\\x{b:02x}" for b in raw)
    return (value or "").strip("\x00")


def _sec_name(section):
    return _txt(section.name)


def is_standard_section_name(name):
    if not name:
        return True
    lname = name.lower()
    if lname in STANDARD_SECTIONS or lname.startswith(STANDARD_SECTION_PREFIXES):
        return True
    if lname.startswith(KERNEL_SECTION_PREFIXES):          # PAGE*, INIT* del kernel Windows
        return True
    if re.fullmatch(r"pad\d+", lname):                     # riempitivi di allineamento di ntoskrnl
        return True
    return bool(re.fullmatch(r"/\d+", lname))  # nomi DWARF/COFF lunghi tipo "/4", "/19"


def packer_label_from_section_name(name):
    lname = (name or "").lower()
    for prefix, label in PACKER_SECTION_PREFIXES.items():
        if lname.startswith(prefix):
            return label
    return None


def _section_is_executable(section):
    """PE: IMAGE_SCN_MEM_EXECUTE (0x20000000) o CNT_CODE (0x20). Nel dubbio -> True (comportamento storico)."""
    try:
        ch = int(section.characteristics)
        return bool(ch & 0x20000000 or ch & 0x20)
    except Exception:
        return True


def _has_clr_header(binary):
    """PE: data directory CLR_RUNTIME_HEADER valorizzata = assembly .NET.

    Discrimina meglio dell'import di mscoree.dll (Is_DotNet), che un packer distrugge insieme
    al resto della IAT: il campione VMProtect x64_msvc_3c4de3f013d4 ha 0 import e la directory
    CLR intatta. Serve al ripiego dello stub strutturale in _packing_signals, perche' un
    assembly .NET ha AddressOfEntryPoint = 0 per costruzione (l'EP vero sta nell'header CLR)
    e quindi non ha nessuna "sezione dell'entry point" su cui misurare l'entropia.
    """
    try:
        for d in binary.data_directories:
            if str(d.type).endswith("CLR_RUNTIME_HEADER") and d.rva:
                return True
    except Exception:
        pass
    return False


def shannon_entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def compute_pe_overlay(binary, filepath):
    """(dimensione, entropia) dell'overlay PE = byte dopo l'ultima sezione (esclusa la firma Authenticode).
    Serve per i wrapper tipo NSIS/SFX: il payload compresso sta nell'overlay, non nelle sezioni, quindi
    l'entropia di sezione resta bassa (6.5 sui due file UPX+NSIS del ground truth)."""
    try:
        file_size = os.path.getsize(filepath)
        end = 0
        for s in binary.sections:
            if s.sizeof_raw_data > 0:
                end = max(end, getattr(s, "pointerto_raw_data", s.offset) + s.sizeof_raw_data)
        if end == 0 or end >= file_size:
            return 0, 0.0
        overlay_size = file_size - end
        for dd in binary.data_directories:
            if "CERTIFICATE" in str(dd.type).upper():
                overlay_size -= dd.size
                break
        if overlay_size <= 0:
            return 0, 0.0
        with open(filepath, "rb") as f:
            f.seek(end)
            data = f.read(min(overlay_size, 4 * 1024 * 1024))
        return overlay_size, round(shannon_entropy(data), 2)
    except Exception as e:
        log.debug(f"Calcolo overlay fallito per {os.path.basename(filepath)}: {e}")
        return 0, 0.0
# Sezioni in cui un entry point NON e' sospetto. Oltre a quelle dei compilatori, comprende le
# sezioni di codice del kernel Windows: ntoskrnl ha l'EP in PAGELK e mcupdate in INIT, che sono
# collocazioni normali per un binario kernel-mode, non anomalie.
STANDARD_EXEC_SECTIONS = [".text", "code", "text", ".code", ".plt", ".init", ".fini",
                          "init", "page", "pagelk", "pagekd", "poolcode", "kvascode", "transit"]

PACKING_THRESHOLD = 70

# FIX (falsi positivi): elenco di keyword usate per riconoscere, dal SOLO
# nome della regola YARA, se un match si riferisce a un packer NOMINATO
# (segnale forte, sufficiente da solo per classificare packed) oppure a un
# pattern generico come anti-debug/anti-vm/offuscazione non specificata
# (segnale debole: da solo NON e' prova di packing, un binario legittimo
# con hardening anti-debug lo triggererebbe comunque). Estendi liberamente
# questa lista se il tuo ruleset YARA usa altri nomi di packer noti.
# Solo NOMI di packer, mai parole generiche. Il match e' su TOKEN interi del nome della regola
# (vedi classify_yara_matches), non per sottostringa libera: con la vecchia lista la keyword
# "packer_" promuoveva a segnale FORTE qualunque regola generica chiamata, per esempio,
# SUSP_Packer_Entropy_Generic, che di un packer specifico non dice nulla.
KNOWN_PACKER_KEYWORDS = [
    "upx", "aspack", "pecompact", "mpress", "themida", "vmprotect",
    "petite", "fsg", "mew", "nspack", "packman", "enigma", "obsidium",
    "yoda", "exe32pack", "upack", "kkrunchy", "molebox",
    "armadillo", "pelock", "expressor", "winupack", "asprotect", "nsis",
    "winlicense", "confuser", "dotfuscator", "netreactor", "smartassembly",
]
# Confine di parola: "upx" matcha in "Packer_UPX" e in "SUSP_ELF_LNX_UPX_Compressed", non in
# una parola che lo contiene per caso.
_YARA_PACKER_RE = re.compile(r"\b(" + "|".join(KNOWN_PACKER_KEYWORDS) + r")\b", re.IGNORECASE)

# Quanti segnali DEBOLI concordanti servono per classificare packed un file
# che non ha nessun segnale FORTE diretto. Alzalo se vedi ancora troppi
# falsi positivi, abbassalo (min 2) se inizi a perdere veri packer leggeri.
WEAK_SIGNALS_REQUIRED = 3

# Numero di export oltre il quale si considera che il binario esponga una vera API, e quindi
# che il suo codice sia intatto: un packer distrugge o non ricrea l'export table. Serve a non
# contare "pochi import" su DLL che importano poco ma esportano molto (ntdll: 0 import, 2.433
# export). Soglia volutamente bassa: un forwarder legittimo ne espone comunque una decina.
EXPORTS_REAL_API = 10

# Sezioni ESCLUSE dal calcolo dell'entropia usata come segnale. Le risorse contengono PNG,
# tabelle di messaggi localizzate e manifest, cioe' dati gia' compressi per natura: la loro
# entropia alta non dice nulla sul packing, perche' un packer comprime il CODICE, non le icone.
# Misurato su binari di sistema firmati Microsoft: WinSAT .rsrc 7.42 con .text 6.42, wermgr
# .rsrc 7.33 con .text 6.23, auditpolmsg .rsrc 7.42 con .text 4.04 (e' una DLL di sole risorse).
# Erano 4 falsi positivi su 4 file con codice perfettamente normale.
# Il caso opposto - un packer che nasconde il payload nelle risorse - resta coperto: in quello
# scenario anche la sezione di codice risulta anomala e gli altri segnali scattano comunque.
ENTROPY_EXCLUDED_SECTIONS = (".rsrc",)

# Entropia (Shannon, 0-8) della sezione che contiene l'entry point oltre la quale la si considera compressa/cifrata:
# il codice compilato sta attorno a 5.5-6.5, uno stub di unpacking o dati compressi >= 7.0. Combinata con
# un'anomalia strutturale della stessa sezione (W+X, o dimensioni virtuale/raw sproporzionate) diventa un
# segnale FORTE; da sola e' debole (vedi _packing_signals).
EP_ENTROPY_THRESHOLD = 7.0

# Timeout del match YARA per file (secondi): un file patologico non deve bloccare il batch.
YARA_TIMEOUT = 60

# --- Detect It Easy (DIE) via die-python ---
# https://github.com/horsicq/DIE-engine (bindings Python: `pip install die-python`)
# A differenza di YARA (serve KNOWN_PACKER_KEYWORDS sul NOME della regola per
# distinguere un packer nominato da un match generico) e di capa (serve
# controllare il namespace), DIE classifica nativamente ogni match con un
# campo "type" (es. "Packer", "Protector", "Compiler", "Installer"...): un
# match di tipo Packer/Protector e' gia' di per se' un segnale forte, senza
# bisogno di nessuna lista di keyword da mantenere.
#
# Richiede un DATABASE di firme separato dal pacchetto pip (non incluso):
# scaricalo da github.com/horsicq/Detect-It-Easy (cartella "db/", contiene le
# firme .sg organizzate per tipo) e punta DIE_DB_PATH alla cartella locale.
#
# ATTENZIONE - schema JSON non verificato al 100% sulla versione installata:
# la funzione sotto (run_die_analysis) parsa in modo difensivo e logga
# sempre l'output grezzo a livello DEBUG, cosi' se lo schema reale non
# combacia con quanto assunto qui lo si vede subito nel log invece di un
# fallimento silenzioso (nessun match rilevato per errore di parsing).
DIEC_PATH = r"E:\Tools\die_win64_portable_3.21_x64\die\diec.exe"
DIE_TIMEOUT = 60                                   # secondi (di norma 1-4 s; i file grandi/deep scan possono richiedere di piu')
# JSON + euristiche (tipi "~packer"/"~protection"). NIENTE deep scan (-d): misurato su 46 file, -d non aggiunge nessun
# rilevamento nominato sui packed (0 differenze su 16) ma fa dire "protector: VMProtect [info DS]" a 9 binari benigni
# (MinGW/awk, b2sum...) - falsi positivi puri.
DIE_ARGS = ["-j", "-u"]

# Tipi DIE (prefisso dei file .sg nel database: protector 477, packer 163, installer 87, sfx 59, cryptor 38, cruncher 38...).
# - PACKER: firma NOMINATA di un packer/protector/cryptor/compressore -> segnale FORTE.
# - INSTALLER: installer/SFX (NSIS, Inno, WinRAR SFX...): il payload sta nell'overlay/risorse e va ESTRATTO, non emulato.
#   Restano un segnale forte (il file va comunque trattato in Fase 2) ma il tipo viene registrato a parte (Die_Packer_Type)
#   per instradare la Fase 2 verso un estrattore invece che verso l'emulazione.
# - Le euristiche di DIE (tipo che inizia con "~", es. "~packer: Generic") sono DEBOLI: DIE le assegna anche a binari
#   normali, quindi valgono solo come uno dei segnali deboli concordanti.
DIE_PACKER_TYPES = {"packer", "protector", "cryptor", "cruncher"}
DIE_INSTALLER_TYPES = {"installer", "sfx"}

def classify_yara_matches(rule_names):
    """
    Divide i match YARA grezzi in due liste in base al NOME della regola:
    - forti: il nome suggerisce esplicitamente un packer noto (es. Packer_UPX)
    - deboli: tutto il resto (es. Anti_Debug_API, offuscazione generica) che
      preso da solo e' compatibile anche con software legittimo hardenizzato.
    """
    strong, weak = [], []
    for name in rule_names:
        # I nomi delle regole usano _ . - come separatori: si normalizzano a spazi cosi' il
        # confine di parola \b isola i token veri.
        tokens = re.sub(r"[^A-Za-z0-9]+", " ", name)
        if _YARA_PACKER_RE.search(tokens):
            strong.append(name)
        else:
            weak.append(name)
    return strong, weak


# ==========================================
# CONFIGURAZIONE E CACHE REGOLE YARA
# ==========================================
RULES_DIR = os.path.join(PARENT_DIR, "config", "yara-forge")
COMPILED_CACHE = os.path.join(PARENT_DIR, "config", "yara_forge_compiled.yrc")

def build_and_cache_yara_rules():
    """Compila e salva in cache tutte le regole YARA presenti nella cartella."""
    log.info(f"Ricerca regole YARA in: {RULES_DIR}...")
    
    if not os.path.exists(RULES_DIR):
        log.error(f"Cartella non trovata: {RULES_DIR}.")
        return None

    # Ricerca ricorsiva: troverà anche i file dentro packages/full/
    all_files = glob.glob(f"{RULES_DIR}/**/*.yar*", recursive=True)
    log.info(f"Trovati {len(all_files)} file YARA da elaborare.")

    if not all_files:
        log.warning("Nessuna regola YARA trovata. Assicurati che i file .yar siano presenti.")
        return None

    valid_rule_files = {}
    valid_count = 0

    # Testiamo singolarmente le regole per scartare quelle con errori di sintassi
    for idx, filepath in enumerate(all_files):
        namespace = f"forge_ns_{idx}"
        try:
            yara.compile(filepath=filepath)
            valid_rule_files[namespace] = filepath
            valid_count += 1
            log.debug(f"File YARA validato: {os.path.basename(filepath)}")
        except yara.SyntaxError as e:
            log.warning(f"File scartato per errore di sintassi: {os.path.basename(filepath)} -> {e}")
        except Exception as e:
            log.warning(f"File scartato per errore generico: {os.path.basename(filepath)} -> {e}")

    if not valid_rule_files:
        log.error("Nessun file YARA è risultato valido per la compilazione.")
        return None

    # Compilazione globale e salvataggio cache
    try:
        log.info(f"Avvio compilazione globale di {valid_count} file. Questa operazione potrebbe richiedere alcuni secondi...")
        compiled = yara.compile(filepaths=valid_rule_files)
        compiled.save(COMPILED_CACHE)
        log.info(f"Cache binaria salvata con successo in: {COMPILED_CACHE}")
        return compiled
    except Exception as e:
        log.critical(f"Errore critico durante la compilazione globale: {e}")
        return None

def get_yara_rules():
    """Recupera le regole dalla cache se presente, altrimenti avvia la compilazione."""
    if os.path.exists(COMPILED_CACHE):
        try:
            log.info("Caricamento ultra-rapido delle regole YARA dalla cache...")
            return yara.load(COMPILED_CACHE)
        except Exception as e:
            log.warning(f"Cache YARA corrotta o incompatibile ({e}). Avvio ricompilazione...")
            os.remove(COMPILED_CACHE)

    return build_and_cache_yara_rules()

# ==========================================
# CONFIGURAZIONE E DOWNLOAD REGOLE CAPA (Mandiant/FLARE)
# ==========================================
CAPA_PATH = r"C:\Users\zinit\Desktop\Tirocinio_Malware\.venv\Scripts\capa.exe"  # deve essere raggiungibile da PATH (pip install flare-capa),
                     # in alternativa impostare qui il percorso assoluto a capa.exe
CAPA_RULES_DIR = os.path.join(PARENT_DIR, "config", "capa-rules")
_CAPA_DIAG_LOGGED = 0  # quante volte e' gia' stato loggato l'output grezzo di un fallimento capa
CAPA_SIGS_DIR = os.path.join(PARENT_DIR, "config", "capa-sigs")   # obbligatoria per capa 9.x, puo' essere vuota (vedi ensure_capa_sigs)
CAPA_TIMEOUT = 90    # secondi. Sui file packed capa esce in pochi secondi (limitazione di file); sui file NORMALI fa
                     # un'analisi completa (vivisect) che puo' richiedere minuti: al timeout si uccide l'albero di processi
# MODI DI ESECUZIONE DI CAPA. Default "off": scelta presa sui dati, non per comodita'.
#
# Misura su 189 file (16 malware + 173 benigni, run del 21/09 ore 22:58):
#   - capa ha consumato 1.539 s su 1.599 s di wall clock totale = 96,3% della Fase 1;
#   - ha prodotto 0 segnali FORTI (Capa_Packer_Match = "SI" su 0/189 file) e 24 deboli;
#   - ha cambiato 0 verdetti: togliendolo del tutto, tutte e 189 le classificazioni restano identiche.
# Motivo strutturale: capa scrive il JSON su stdout ALLA FINE, mentre il banner di packing compare
# all'inizio. L'arresto anticipato al banner (che rende capa 4x piu' veloce) impedisce per costruzione
# di ottenere il JSON, e senza JSON non si puo' leggere il namespace "anti-analysis/packer/<nome>":
# resta solo il verdetto generico, cioe' un segnale DEBOLE gia' fornito da DIE in 0,3 s.
#
#   "off"    : capa non viene eseguito (default). Fase 1: ~60 s sui 189 file invece di 1.599 s.
#   "full"   : nessun arresto anticipato, nessuna finestra di sondaggio, timeout alto. Il JSON arriva
#              e Capa_Packer_Match = "SI" torna raggiungibile. E' il modo per il confronto fra tool su
#              un sottoinsieme, non per il triage di un dataset intero.
#   "always" : come "full" ma con arresto al banner e sondaggio (il comportamento storico).
#   "lazy"   : "always" solo dove i tool economici non hanno gia' un segnale forte. Misurato: salta 25
#              file su 189 e risparmia 96 s su 1.539 s (6%), perche' i file che saltano sono proprio i
#              piu' economici (4,6 s di media) mentre quelli che restano sono i piu' cari (17,2 s).
CAPA_MODE = "off"
CAPA_MODES = ("off", "lazy", "always", "full")
CAPA_FULL_TIMEOUT = 600   # secondi, solo in modo "full": senza early-stop serve lasciare finire l'analisi


def set_capa_mode(mode):
    """Impostata dall'orchestratore (parameters_info.py --capa-mode). Ritorna il modo applicato."""
    global CAPA_MODE
    if mode not in CAPA_MODES:
        log.error(f"Modo capa sconosciuto '{mode}', resto su '{CAPA_MODE}'. Validi: {', '.join(CAPA_MODES)}")
        return CAPA_MODE
    CAPA_MODE = mode
    return CAPA_MODE
# Finestra di sondaggio: se entro questi secondi capa non ha ancora annunciato il banner di packing si smette.
# Misurato: il banner compare dopo ~1.4 s per MB di file (0.8-7.8 s fino a 5 MB, 56 s per 42 MB), quindi la finestra
# e' proporzionale alla dimensione (un valore fisso taglierebbe i file grandi), con tetto CAPA_TIMEOUT.
CAPA_PROBE_BASE = 15
CAPA_PROBE_PER_MB = 2.0
CAPA_RC_FILE_LIMITATION = 17   # E_FILE_LIMITATION di capa: campione packed/offuscato
CAPA_PACKED_BANNERS = ("appears to be packed", "packer file limitation")   # testo del banner su stderr (gia' in minuscolo)

def get_capa_version():
    """Interroga 'capa --version' per allineare il download del ruleset alla versione installata."""
    try:
        result = subprocess.run([CAPA_PATH, "--version"], capture_output=True, text=True, timeout=10)
        parts = result.stdout.strip().split()
        return parts[-1] if parts else None
    except Exception as e:
        log.warning(f"Impossibile determinare la versione di capa: {e}")
        return None

def download_capa_rules():
    """
    Scarica il ruleset ufficiale capa-rules (github.com/mandiant/capa-rules) da GitHub.
    Prova prima il tag allineato alla versione di capa installata (evita mismatch di schema),
    poi ricade sul branch master come fallback.
    """
    version = get_capa_version()
    candidate_urls = []
    if version:
        candidate_urls.append(f"https://codeload.github.com/mandiant/capa-rules/zip/refs/tags/v{version}")
    candidate_urls.append("https://codeload.github.com/mandiant/capa-rules/zip/refs/heads/master")

    for url in candidate_urls:
        try:
            log.info(f"Download regole capa da: {url}")
            with urllib.request.urlopen(url, timeout=90) as resp:
                data = resp.read()

            with zipfile.ZipFile(io.BytesIO(data)) as z:
                tmp_extract = CAPA_RULES_DIR + "_tmp"
                if os.path.exists(tmp_extract):
                    shutil.rmtree(tmp_extract)
                z.extractall(tmp_extract)

                # Lo zip di GitHub contiene sempre una singola cartella radice (es. capa-rules-9.4.0/)
                root_entries = os.listdir(tmp_extract)
                if len(root_entries) != 1:
                    raise RuntimeError("Struttura zip inattesa dopo l'estrazione.")

                inner_dir = os.path.join(tmp_extract, root_entries[0])
                if os.path.exists(CAPA_RULES_DIR):
                    shutil.rmtree(CAPA_RULES_DIR)
                shutil.move(inner_dir, CAPA_RULES_DIR)
                shutil.rmtree(tmp_extract, ignore_errors=True)

            log.info(f"Regole capa scaricate correttamente in: {CAPA_RULES_DIR}")
            return True

        except Exception as e:
            log.warning(f"Download regole capa fallito da {url}: {e}")

    return False

def ensure_capa_rules():
    """Verifica la presenza locale del ruleset capa; se assente, avvia il download automatico."""
    if os.path.isdir(CAPA_RULES_DIR) and os.listdir(CAPA_RULES_DIR):
        log.info(f"Ruleset capa trovato in: {CAPA_RULES_DIR}")
        return True

    log.info("Ruleset capa non trovato localmente. Avvio download automatico...")
    return download_capa_rules()

def is_capa_available():
    """Verifica che l'eseguibile capa sia raggiungibile prima di lanciare l'analisi in batch."""
    if shutil.which(CAPA_PATH) is None and not os.path.isfile(CAPA_PATH):
        log.error(f"Eseguibile capa non trovato ('{CAPA_PATH}'). Installa con: pip install flare-capa")
        return False
    return True

def is_die_available():
    """Verifica che diec.exe (DIE da riga di comando) esista, una volta sola prima del batch."""
    if not os.path.isfile(DIEC_PATH):
        log.error(f"Eseguibile DIE non trovato in {DIEC_PATH}. Scarica la release per Windows e imposta DIEC_PATH.")
        return False
    return True


def run_die_analysis(filepath):
    """
    Detect It Easy (diec.exe -j -d -u). Tre categorie di risultato, con peso diverso:
      - packer/protector/cryptor/cruncher NOMINATI -> Die_Packer_Match=SI (segnale FORTE); ha la precedenza;
      - installer/SFX (NSIS, Inno, ...)            -> Die_Packer_Match=SI ma Die_Packer_Type=installer/sfx, cosi' la
                                                      Fase 2 puo' preferire un estrattore all'emulazione;
      - euristiche "~packer"/"~protection"          -> solo Die_Heuristic (segnale DEBOLE: DIE le da' anche a file normali).
    Die_Status: ok | empty | parse_error | timeout | not_found | rc_error | exception.
    """
    result = {"Die_Detections": [], "Die_Packer_Match": "NO", "Die_Packer_Name": "", "Die_Packer_Type": "",
              "Die_All_Packers": "", "Die_Heuristic": "", "Die_Status": "not_run"}

    run = run_external("die", [DIEC_PATH] + DIE_ARGS + [filepath], DIE_TIMEOUT, target=filepath)
    result["Die_Status"] = run["status"]
    packers, installers, heuristics = [], [], []

    out = run["stdout"]
    if run["status"] in ("ok", "rc_error"):
        if not out.strip():
            result["Die_Status"] = "empty"
        else:
            try:
                brace = out.find("{")
                data = json.loads(out[brace:] if brace >= 0 else out)
                for filepart in data.get("detects", []):
                    for value in filepart.get("values", []):
                        type_name = str(value.get("type", "")).strip().lower()
                        name = value.get("name") or value.get("string") or type_name
                        result["Die_Detections"].append(name)
                        base_type = type_name.lstrip("~")
                        if type_name.startswith("~") or str(value.get("info", "")).strip().upper() == "DS":
                            # euristica o firma "deep scan" (DS): confidenza bassa. Si tiene solo se riguarda il packing
                            # (es. "~debug data: Contains" non c'entra e compariva nel 33% dei benigni).
                            if base_type in DIE_PACKER_TYPES or base_type in DIE_INSTALLER_TYPES or base_type == "protection":
                                heuristics.append(f"{base_type}: {name}")
                        elif type_name in DIE_PACKER_TYPES:
                            packers.append((name, type_name))
                        elif type_name in DIE_INSTALLER_TYPES:
                            installers.append((name, type_name))
                result["Die_Status"] = "ok"
            except json.JSONDecodeError as e:
                result["Die_Status"] = "parse_error"
                log.warning(f"DIE: output non JSON per {os.path.basename(filepath)}: {e}")

    # B11: si conserva la lista COMPLETA e ordinata, non solo la prima detection. Su un campione
    # multilayer (UPX+MPRESS: e' il caso del ground truth prodotto da pack_samples.py) DIE puo'
    # riportare piu' firme, e per una tesi sul multilayer packing quella lista e' il dato
    # centrale. Die_Packer_Name resta la prima, per non rompere il contratto con la Fase 2
    # (extract_packed_files in parameters_info.py la usa come hint di instradamento).
    result["Die_All_Packers"] = "; ".join(f"{n} ({t})" for n, t in packers + installers)
    chosen = (packers or installers or [None])[0]
    if chosen:
        result["Die_Packer_Match"] = "SI"
        result["Die_Packer_Name"], result["Die_Packer_Type"] = chosen
        if len(packers) + len(installers) > 1:
            log.warning(f"  [!] DIE riporta {len(packers) + len(installers)} firme su "
                        f"{os.path.basename(filepath)}: {result['Die_All_Packers']}")
        log.warning(f"  [!] DIE identifica un {chosen[1]} su {os.path.basename(filepath)}: {chosen[0]}")
    result["Die_Heuristic"] = "; ".join(heuristics)

    if result["Die_Status"] not in ("ok",):
        log.warning(f"DIE: stato '{result['Die_Status']}' per {os.path.basename(filepath)} "
                    f"(rc={run['rc']}, {run['duration_s']}s, stderr: {sanitize_tool_text(run['stderr'])[:160]})")
    write_tool_diag(run, die_status=result["Die_Status"], packer=result["Die_Packer_Name"],
                    packer_type=result["Die_Packer_Type"], heuristic=result["Die_Heuristic"],
                    n_detections=len(result["Die_Detections"]))
    return result


def ensure_capa_sigs():
    """capa 9.x rifiuta di partire se la cartella firme predefinita non esiste ("Using default signature path, but it
    doesn't exist": 15 file su 15 nel batch reale, capa non ha mai prodotto un risultato). Si passa -s a una cartella
    locale, anche vuota: le firme FLIRT servono solo a riconoscere funzioni di libreria, non al triage di packing."""
    try:
        os.makedirs(CAPA_SIGS_DIR, exist_ok=True)
        return True
    except OSError as e:
        log.error(f"Impossibile creare la cartella firme capa ({CAPA_SIGS_DIR}): {e}")
        return False


_CAPA_LOG_LOCATION_RE = re.compile(r"\b[\w]+\.py:\d+\b")


def _capa_normalize_stderr(text):
    """Lo stderr 'rich' di capa spezza le frasi a colonne fisse e vi inserisce il riferimento di log (es. 'common.py:90')
    tra le parole ("appears to be common.py:90 packed."): si tolgono ANSI, riferimenti e spazi multipli prima di cercare."""
    return sanitize_tool_text(_CAPA_LOG_LOCATION_RE.sub(" ", text or ""))


def run_capa_analysis(filepath, is_pe=None, is_elf=None):
    """
    capa (Mandiant/FLARE) come giudice indipendente. Comportamento reale di capa 9.x, verificato sui dati:
    - sui PACKED stampa presto su stderr il banner "This sample appears to be packed" + "(internal) packer file
      limitation" e poi continua l'analisi completa (o esce con codice 17): il tempo dopo il banner e' sprecato per
      il triage, quindi il processo viene FERMATO al banner (Capa_Status=stopped_at_banner);
    - sui file con molto codice reale fa un'analisi completa con vivisect (scoperta funzioni + estrazione feature +
      match di ~1000 regole per funzione): il tempo cresce col codice analizzabile, non con la dimensione del file
      (un packed con stub piccolo finisce in 2-10 s, un binario pulito da 0.5 MB puo' superare 90 s). Se entro
      CAPA_PROBE_BASE + CAPA_PROBE_PER_MB*MB s non e' comparso nessun banner si smette (Capa_Status=no_banner_probe): nessuna evidenza di
      packing in quella finestra, NON significa "pulito".
    Capa_Status: ok | packed_limitation | stopped_at_banner | no_banner_probe | timeout | not_found | error | rc_error.
    banner_at_s (in tool_diagnostics.jsonl) = dopo quanti secondi e' comparso il banner: serve a tarare il sondaggio.

    is_pe/is_elf (noti da LIEF) forzano --os: su alcuni ELF compressi con UPX l'auto-detect fallisce.
    """
    result = {"Capa_Total_Matches": 0, "Capa_Packer_Match": "NO", "Capa_Anti_Analysis_Match": "NO",
              "Capa_Capabilities": [], "Capa_Status": "error"}

    command = [CAPA_PATH, "-r", CAPA_RULES_DIR, "-s", CAPA_SIGS_DIR, "-j"]
    if is_pe:
        command += ["--os", "windows"]
    elif is_elf:
        command += ["--os", "linux"]
    command.append(filepath)

    try:
        size_mb = os.path.getsize(filepath) / 1e6
    except OSError:
        size_mb = 0.0
    # In modo "full" NON si ferma il processo: il JSON di capa arriva su stdout solo alla fine, e senza
    # JSON il namespace "anti-analysis/packer/<nome>" e' illeggibile, cioe' il packer NOMINATO (segnale
    # forte) e' irraggiungibile. E' il compromesso esplicito fra velocita' e informazione.
    full = CAPA_MODE == "full"
    if full:
        probe = None
        run = run_external("capa", command, CAPA_FULL_TIMEOUT, target=filepath)
    else:
        probe = min(CAPA_TIMEOUT, round(CAPA_PROBE_BASE + CAPA_PROBE_PER_MB * size_mb, 1))
        run = run_external("capa", command, CAPA_TIMEOUT, target=filepath, stop_on_stderr=CAPA_PACKED_BANNERS,
                           probe_timeout=probe, stderr_normalizer=_capa_normalize_stderr)
    stderr_text = _capa_normalize_stderr(run["stderr"]).lower()
    packed_banner = (run["status"] == "stopped_early" or run["rc"] == CAPA_RC_FILE_LIMITATION
                     or any(b in stderr_text for b in CAPA_PACKED_BANNERS))

    out = run["stdout"]
    brace = out.find("{")
    data = None
    if brace >= 0:
        try:
            data = json.loads(out[brace:])
        except json.JSONDecodeError:
            data = None

    generic_packing = False
    if data is not None:
        rules = data.get("rules", {})
        result["Capa_Status"] = "ok"
        result["Capa_Total_Matches"] = len(rules)
        for rule_name, rule_data in rules.items():
            namespace = (rule_data.get("meta", {}) or {}).get("namespace") or ""
            result["Capa_Capabilities"].append(rule_name)
            # "internal/limitation/*" comprende anche limitazioni NON di packing, es. "(internal) .NET file limitation"
            # (5 assembly .NET benigni segnalati come packed): conta solo la limitazione di packer e le regole packer.
            if namespace.startswith("anti-analysis/packer") and not namespace.rstrip("/").endswith("/generic"):
                result["Capa_Packer_Match"] = "SI"          # packer NOMINATO (es. packed with UPX)
            elif (namespace.startswith("anti-analysis/packer") or "packer file limitation" in rule_name.lower()):
                generic_packing = True                       # verdetto euristico ("packed with generic packer")
            elif namespace.startswith("anti-analysis"):
                result["Capa_Anti_Analysis_Match"] = "SI"
    elif run["status"] == "stopped_early":
        result["Capa_Status"] = "stopped_at_banner"
    elif packed_banner and run["status"] != "timeout":
        result["Capa_Status"] = "packed_limitation"
    elif run["status"] in ("timeout", "not_found", "exception"):
        result["Capa_Status"] = run["status"]
    elif run["status"] == "probe_timeout":
        result["Capa_Status"] = "no_banner_probe"
    else:
        result["Capa_Status"] = "rc_error" if run["status"] == "rc_error" else "error"

    # Il banner "appears to be packed" e la regola "packed with generic packer" sono verdetti EURISTICI di capa, non
    # firme di un packer: valgono come segnale debole ("GENERICO"). Su 27 benigni e 16 packed: il verdetto generico
    # ha dato 1 falso positivo (l'unico segnale) e nei packed non e' mai stato l'unica fonte forte.
    if (packed_banner or generic_packing) and result["Capa_Packer_Match"] != "SI":
        result["Capa_Packer_Match"] = "GENERICO"

    name = os.path.basename(filepath)
    if result["Capa_Packer_Match"] in ("SI", "GENERICO"):
        log.warning(f"  [!] capa segnala PACKING {'nominato' if result['Capa_Packer_Match'] == 'SI' else 'generico'} "
                    f"su {name} (stato: {result['Capa_Status']}, {run['duration_s']}s)")
    elif result["Capa_Anti_Analysis_Match"] == "SI":
        log.info(f"  [i] capa rileva capability anti-analysis (anti-debug/anti-vm) su {name}")
    if result["Capa_Status"] in ("timeout", "not_found", "exception", "error", "rc_error"):
        log.warning(f"capa: stato '{result['Capa_Status']}' per {name} (rc={run['rc']}, {run['duration_s']}s, "
                    f"stderr: {_capa_normalize_stderr(run['stderr'])[:200]})")
    elif result["Capa_Status"] == "no_banner_probe":
        log.info(f"  [i] capa: nessun banner di packing entro {probe}s su {name} (analisi interrotta)")
    write_tool_diag(run, capa_status=result["Capa_Status"], packed_banner=packed_banner,
                    banner_at_s=run.get("first_match_s"), probe_s=probe, size_mb=round(size_mb, 2), n_rules=result["Capa_Total_Matches"],
                    packer_match=result["Capa_Packer_Match"])
    return result


# ==========================================
# FUNZIONI DI SUPPORTO E STORICO
# ==========================================
def load_analysis_history(csv_path):
    """
    Ritorna l'insieme degli SHA-256 gia' analizzati.

    Prima la chiave era il path relativo alla cartella target, ma OUTPUT_CSV e'
    UNICO per tutti i dataset: due campioni con lo stesso nome relativo in
    cartelle diverse si coprivano a vicenda e il secondo non veniva mai
    analizzato. Misurato: tutti e 15 i file di TEST_SAMPLES collidevano con gli
    omonimi di TEST_BIN_PULITI, che pero' hanno contenuto diverso (uno packato,
    uno pulito). Con l'hash la chiave e' il contenuto, quindi:
      - un file rinominato o spostato non viene rianalizzato inutilmente;
      - un file MODIFICATO allo stesso path viene correttamente rianalizzato.
    """
    analyzed = set()
    if os.path.exists(csv_path):
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    file_hash = (row.get('SHA256') or '').strip().lower()
                    if file_hash:
                        analyzed.add(file_hash)
            log.info(f"Caricati {len(analyzed)} file gia' analizzati (per SHA-256) da: {csv_path}")
        except Exception as e:
            log.error(f"Errore nella lettura dello storico CSV: {str(e)}")
    return analyzed

def _empty_results(relpath, file_hash="", dataset=""):
    """Schema UNICO dei risultati (e delle colonne del CSV).

    SHA256 e Dataset non sono decorazioni: la colonna `File` e' un path RELATIVO alla
    cartella analizzata, quindi NON identifica un campione. Misurato su questo progetto:
    TEST_SAMPLES/awk_6DAD...exe (268.800 B) e TEST_BIN_PULITI/awk_6DAD...exe (627.466 B)
    hanno lo stesso nome e contenuto diverso. Poiche' OUTPUT_CSV e' unico e globale per
    tutti i dataset, senza l'hash due campioni omonimi si coprono a vicenda nello storico
    e il CSV non e' agganciabile a una ground truth."""
    return {
        "File": relpath,
        "SHA256": file_hash,
        "Dataset": dataset,
        "Analyzed_At": "",
        "Executable_Type": "UNKNOWN",
        "Total_Raw_Size": 0,
        "Total_Virtual_Size": 0,
        "Size_Difference": 0,
        "Total_Sections": 0,
        "Sections_Stripped": "NO",
        "Suspicious_Sections": [],
        "High_Entropy_Sections": 0,
        "Max_Section_Entropy": 0.0,     # su TUTTE le sezioni: resta come dato informativo
        "Max_Entropy_No_Rsrc": 0.0,     # escluse le risorse: e' QUESTA che alimenta il segnale
        "Overlay_Size": 0,
        "Overlay_Entropy": 0.0,
        "Total_Imports": 0,
        "Total_Exports": 0,            # un packer distrugge o non crea l'export table: vedi _packing_signals
        "Subsystem": "",               # NATIVE / WINDOWS_BOOT_APPLICATION = kernel-mode, importa dal kernel
        "Imported_APIs": [],
        "Suspicious_IAT": "NO",
        "EP_Section": "UNKNOWN",
        "Anomalous_Size_Sections": [],
        "YARA_Matches": [],
        "Capa_Mode": CAPA_MODE,         # con quale modo e' stata prodotta questa riga (vedi CAPA_MODE)
        "Capa_Status": "not_run",
        "Capa_Total_Matches": 0,
        "Capa_Packer_Match": "NO",
        "Capa_Anti_Analysis_Match": "NO",
        "Capa_Capabilities": [],
        "Die_Detections": [],
        "Die_Packer_Match": "NO",
        "Die_Packer_Name": "",
        "Die_Packer_Type": "",          # packer/protector/cryptor/cruncher | installer/sfx (da estrarre, non emulare)
        "Die_All_Packers": "",          # TUTTE le firme DIE, ordinate: sui multilayer la prima non basta
        "Die_Heuristic": "",            # euristiche DIE "~packer"/"~protection": segnale debole
        "Die_Status": "not_run",
        "Yara_Status": "not_run",
        "Parse_Status": "not_run",      # ok | lief_none | lief_error:<Tipo> | not_executable: il file NON viene piu' scartato se LIEF fallisce
        "Is_DotNet": "NO",              # assembly .NET (importa solo mscoree): pochi import e' normale
        "Info_Signals": "",             # segnali registrati ma NON contati (discriminano poco: vedi _packing_signals)
        "EP_Section_Entropy": 0.0,
        "EP_Section_WX": "NO",          # entry point in una sezione scrivibile+eseguibile
        "EP_Outside_Sections": "NO",    # EP con RVA non nullo che non cade in NESSUNA sezione
        "Has_CLR_Header": "NO",         # data directory CLR presente: assembly .NET, AddressOfEntryPoint = 0 per costruzione
        "Exec_High_Entropy_Sections": [],   # sezioni ESEGUIBILI a entropia >= EP_ENTROPY_THRESHOLD: vedi _packing_signals
        "Packing_Score_%": 0,
        "Is_Packed_Label": 0,
        "Packing_Evidence": "none",     # named (packer nominato) | structural (segnale forte senza nome) | weak_only | none
        "Strong_Signals": "",
        "Weak_Signals": "",
    }


CSV_FIELDNAMES = list(_empty_results("").keys())


def _as_list(value):
    """I campi lista vengono trasformati in stringhe " | " per il CSV: questo li riporta a lista, cosi' i segnali si
    possono ricalcolare anche su un risultato gia' formattato (percorso di errore)."""
    if isinstance(value, list):
        return value
    return [v for v in str(value or "").split(" | ") if v]


def _maybe_run_capa(results, filepath, is_pe, is_elf, capa_ready, packer_sections):
    """capa e' il tool piu' lento (96,3% del wall clock misurato): vedi CAPA_MODE per i modi e il perche'
    del default "off". Il modo usato viene registrato per riga, cosi' un CSV dice sempre come e' nato."""
    results["Capa_Mode"] = CAPA_MODE
    if not capa_ready or CAPA_MODE == "off":
        results["Capa_Status"] = "disabled" if CAPA_MODE == "off" else "unavailable"
        return
    if CAPA_MODE == "lazy":
        yara_strong, _ = classify_yara_matches(_as_list(results["YARA_Matches"]))
        if packer_sections or yara_strong or results["Die_Packer_Match"] == "SI":
            results["Capa_Status"] = "skipped_lazy"
            return
    results.update(run_capa_analysis(filepath, is_pe=is_pe, is_elf=is_elf))


def _packing_signals(results, filepath, packer_sections, is_pe, lief_ok):
    """
    Segnali FORTI (uno basta) e DEBOLI (ne servono WEAK_SIGNALS_REQUIRED). Ogni segnale e' una proprieta' generica
    del binario o l'output di un tool, non una regola costruita su campioni specifici.
      FORTI : sezione con nome di packer noto; YARA su packer nominato; capa (banner/regola di packing);
              DIE packer/protector/cryptor/installer nominato; IAT minimale; stub strutturale (EP in sezione
              cifrata/compressa E anomala: W+X o dimensioni virtuale/raw sproporzionate), con ripiego per gli
              assembly .NET, che non hanno una sezione di EP su cui misurare.
      DEBOLI: entropia alta, sezioni/nomi anomali, EP in sezione non standard / ad alta entropia / W+X, overlay
              grande e compresso, pochi import, YARA generico, capa anti-analysis, euristica DIE, header non parsabile.
    """
    yara_strong, yara_weak = classify_yara_matches(_as_list(results["YARA_Matches"]))
    anomalous = _as_list(results["Anomalous_Size_Sections"])
    suspicious = _as_list(results["Suspicious_Sections"])

    strong = []
    if packer_sections:
        strong.append(f"sezione tipica di packer: {', '.join(packer_sections)}")
    if yara_strong:
        strong.append(f"YARA packer specifico: {', '.join(yara_strong)}")
    if results["Capa_Packer_Match"] == "SI":
        strong.append(f"capa: packer nominato riconosciuto (stato {results['Capa_Status']})")
    if results["Die_Packer_Match"] == "SI":
        strong.append(f"DIE: {results['Die_Packer_Type'] or 'packer'} identificato ({results['Die_Packer_Name']})")
    # "IAT minimale" da sola NON basta come segnale forte: un malware che importa solo
    # LoadLibrary+GetProcAddress per risolvere il resto a runtime fa RISOLUZIONE DINAMICA
    # DEGLI IMPORT, che e' evasione, non compressione. Misurato su 2 malware reali con
    # .text a entropia 5.45 e 6.20 (codice in chiaro) e sezioni regolari: erano falsi
    # positivi. Serve la corroborazione di una compressione osservata.
    # E' la correzione condizionale che B8 indicava come giusta e che allora non era
    # verificabile per mancanza di campioni. Costo misurato: 0 veri positivi persi, perche'
    # "IAT minimale" non e' MAI l'unico segnale forte sui 378 packed etichettati.
    iat_corroborata = results["Max_Entropy_No_Rsrc"] >= 7.2 or len(anomalous) > 0
    iat_non_corroborata = results["Suspicious_IAT"] == "SI" and not iat_corroborata
    if results["Suspicious_IAT"] == "SI" and iat_corroborata:
        strong.append("IAT minimale sospetta (solo LoadLibrary/GetProcAddress o dlopen/dlsym) "
                      "con compressione osservata")

    ep_entropy = results["EP_Section_Entropy"]
    ep_high = lief_ok and ep_entropy >= EP_ENTROPY_THRESHOLD
    # Layout tipico di uno stub che decomprime: l'EP e' in una sezione compressa/cifrata (H alta) mentre almeno un'altra
    # sezione eseguibile e' vuota/sproporzionata (spazio riservato dove verra' scritto il codice originale), oppure la
    # sezione dell'EP e' scrivibile+eseguibile. Vale per qualunque packer, nominato o sconosciuto.
    ep_anomalous = results["EP_Section_WX"] == "SI" or len(anomalous) > 0
    structural = ep_high and ep_anomalous
    # RIPIEGO PER GLI ASSEMBLY .NET. Un assembly .NET ha AddressOfEntryPoint = 0 per costruzione
    # (l'entry point vero sta nell'header CLR), quindi ep_compare e' 0, nessuna sezione contiene
    # l'EP e EP_Section_Entropy resta 0.0: il segnale sopra NON puo' scattare su un file .NET,
    # quali che siano le sue sezioni. Misurato sul campione a label certa
    # x64_msvc_3c4de3f013d4_VMProtect.exe: .text e .kA^ eseguibili e svuotate (raw 0), .7lh a
    # entropia 7.16 - layout di stub da manuale - eppure classificato con i soli segnali deboli.
    # Il ripiego cerca la STESSA proprieta' senza ancorarla all'EP: una sezione eseguibile
    # compressa piu' un'ALTRA sezione eseguibile svuotata. Le due devono essere sezioni distinte,
    # altrimenti si conterebbe due volte la stessa evidenza (di qui la differenza fra insiemi:
    # nomi ambigui o assenti fanno ricadere sul caso conservativo, cioe' nessun segnale forte).
    exec_high = set(_as_list(results["Exec_High_Entropy_Sections"])) - set(anomalous)
    managed_stub = (lief_ok and not structural
                    and results["Has_CLR_Header"] == "SI"
                    and results["EP_Section"] == "UNKNOWN"
                    and bool(exec_high) and bool(anomalous))
    if structural:
        strong.append(f"stub strutturale: EP in sezione ad alta entropia (H={ep_entropy}) e "
                      f"{'sezione EP W+X' if results['EP_Section_WX'] == 'SI' else 'sezioni eseguibili svuotate/sproporzionate'}")
    elif managed_stub:
        structural = True
        strong.append(f"stub strutturale (assembly .NET, nessuna sezione di EP): sezione eseguibile "
                      f"compressa {', '.join(sorted(exec_high))} e sezioni eseguibili "
                      f"svuotate/sproporzionate ({', '.join(anomalous)})")

    weak, info = [], []
    if not lief_ok:
        weak.append(f"header non parsabile da LIEF ({results['Parse_Status']}): possibile malformazione voluta")
    if results["Max_Entropy_No_Rsrc"] >= 7.2:      # risorse escluse: vedi ENTROPY_EXCLUDED_SECTIONS
        weak.append("entropia sezione >= 7.2")
    if len(anomalous) > 0:
        weak.append("sezioni con dimensione anomala")
    # RIMOSSO: "differenza size virtuale/raw elevata" (era: Size_Difference > 200000).
    # Misurato su 26 packed e 2.041 clean: 0% sui packed, 1% sui clean (12 file). Non scattava
    # MAI su un campione packato e scattava solo su binari legittimi - rumore puro, con lift -1.
    # Il caso che voleva intercettare (sezione virtuale molto piu' grande della raw) e' gia'
    # coperto, e meglio, da "sezioni con dimensione anomala", che guarda le singole sezioni
    # ESEGUIBILI invece della somma su tutto il file.
    if results["EP_Section"].lower() not in STANDARD_EXEC_SECTIONS and results["EP_Section"] != "UNKNOWN":
        weak.append(f"entry point in sezione non standard ({results['EP_Section']})")
        log.warning(f"  [!] Entry Point agganciato a sezione sospetta: {results['EP_Section']}")
    if not structural:
        if ep_high:
            weak.append(f"entry point in sezione ad alta entropia (H={ep_entropy})")
        if results["EP_Section_WX"] == "SI":
            weak.append("entry point in sezione scrivibile+eseguibile")
    if results["EP_Outside_Sections"] == "SI":
        weak.append("entry point fuori da ogni sezione")
    if results["Sections_Stripped"] == "SI":
        weak.append("sezioni stripped")
    try:
        fsize = os.path.getsize(filepath)
    except OSError:
        fsize = 0
    if results["Overlay_Size"] >= max(65536, 0.5 * fsize) and results["Overlay_Entropy"] >= 7.2:
        weak.append(f"overlay grande ad alta entropia ({results['Overlay_Size']//1024} KB, H={results['Overlay_Entropy']})")
    if suspicious:
        weak.append("nomi sezione non standard")
    # "Pochi import" e' sospetto solo se pochi import sono ANOMALI per quel tipo di binario.
    # Tre eccezioni, ognuna con una ragione strutturale e non legata a un campione specifico:
    #  - .NET: un assembly importa il solo mscoree (erano 5 falsi positivi su 30 benigni);
    #  - kernel-mode e boot loader: linkano contro il kernel, non contro DLL user-mode. ntdll,
    #    winload, winresume, tcblaunch e i trasporti kd_* hanno ZERO import per costruzione;
    #  - export table consistente: un packer distrugge o non ricrea gli export, quindi un binario
    #    che espone centinaia di simboli ha il codice intatto. Misurato: ntdll 2.433 export,
    #    ntoskrnl 3.091, tcblaunch 408, winload 388 - tutti con 0 o pochissimi import.
    kernel_mode = results["Subsystem"] in ("NATIVE", "WINDOWS_BOOT_APPLICATION")
    exports_api = results["Total_Exports"] >= EXPORTS_REAL_API
    if (lief_ok and results["Is_DotNet"] != "SI" and results["Total_Imports"] < 20
            and not kernel_mode and not exports_api):
        weak.append("numero import basso (<20)")
    if iat_non_corroborata:
        # Declassata, non scartata: l'informazione resta leggibile nel CSV.
        weak.append("IAT minimale senza compressione: possibile risoluzione dinamica degli import")
    if results["Die_Heuristic"]:
        weak.append(f"DIE euristica: {results['Die_Heuristic']}")
    if results["Capa_Packer_Match"] == "GENERICO":
        weak.append(f"capa: packing generico (banner/regola generic packer, stato {results['Capa_Status']})")
    # INFORMATIVI, non contati: su 27 benigni e 16 packed discriminano poco (capa anti-analysis 26% vs 31%, YARA
    # generico 15% vs 25%) perche' anti-debug e hardening sono comuni nel software legittimo.
    if yara_weak:
        info.append(f"YARA generico/anti-analysis: {', '.join(yara_weak)}")
    if results["Capa_Anti_Analysis_Match"] == "SI":
        info.append("capa: anti-analysis (anti-debug/anti-vm)")
    return strong, weak, info


def _classify_packing(strong, weak):
    """(score, is_packed): un segnale forte basta; altrimenti servono WEAK_SIGNALS_REQUIRED segnali deboli."""
    if strong:
        return 100, True
    if len(weak) >= WEAK_SIGNALS_REQUIRED:
        return min(100, 40 + 15 * len(weak)), True     # sempre sopra PACKING_THRESHOLD
    return min(PACKING_THRESHOLD - 1, 15 * len(weak)), False


def _record_classification(results, filename, strong, weak, info=()):
    score, is_packed = _classify_packing(strong, weak)
    results["Packing_Score_%"] = score
    results["Is_Packed_Label"] = 1 if is_packed else 0
    # Quanto e' solida l'evidenza: la Fase 2 puo' spendere meno tempo (es. Qiling) su un "weak_only".
    # B6: capa va incluso fra le fonti che identificano un packer PER NOME. Senza, un file
    # riconosciuto dalla sola capa finiva in "structural" e la Fase 2 riceveva un instradamento
    # sbagliato (emulazione invece di unpacker dedicato).
    named = any(k in x for x in strong
                for k in ("sezione tipica", "YARA packer", "DIE:", "capa: packer nominato"))
    results["Packing_Evidence"] = ("named" if named else "structural" if strong else "weak_only" if is_packed else "none")
    results["Strong_Signals"] = " | ".join(strong)
    results["Weak_Signals"] = " | ".join(weak)
    results["Info_Signals"] = " | ".join(info)
    if is_packed:
        log.warning(f"[!] {filename} ({results['Executable_Type']}) classificato PACCHETTIZZATO (Score: {score}%)")
    else:
        log.info(f"[i] {filename} ({results['Executable_Type']}) classificato PULITO (Score: {score}%)")


def _format_for_csv(results):
    """Liste -> stringhe " | " (le liste lunghe vengono troncate a 10 elementi)."""
    for key in ("Suspicious_Sections", "Anomalous_Size_Sections", "Exec_High_Entropy_Sections", "YARA_Matches"):
        results[key] = " | ".join(_as_list(results[key]))
    for key in ("Imported_APIs", "Capa_Capabilities", "Die_Detections"):
        items = _as_list(results[key])
        results[key] = " | ".join(items[:10]) + (f" ... (+{len(items) - 10})" if len(items) > 10 else "")


def _finish_without_lief(results, filepath, filename, capa_ready, die_ready,
                         packer_sections=(), lief_ok=False):
    """Percorso quando LIEF non riesce a parsare (o l'analisi lancia un'eccezione): il file NON viene scartato.
    Si usano i soli tool esterni (DIE, capa, YARA gia' eseguito) piu' il segnale "header non parsabile"."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
    except OSError:
        magic = b""
    if magic[:2] != b"MZ" and magic != b"\x7fELF":
        # Ne' PE ne' ELF (es. patch/delta di Windows Update "PA30" con estensione .exe, archivi, dati): non e' un
        # eseguibile, quindi non ha senso ne' DIE/capa ne' un tentativo di unpacking.
        results["Executable_Type"] = f"NON_EXECUTABLE (magic {magic.hex() or 'illeggibile'})"
        results["Parse_Status"] = "not_executable"
        _record_classification(results, filename, [], [], [])
        _format_for_csv(results)
        log.info(f"[i] {filename}: non e' un eseguibile PE/ELF (magic {magic.hex()}): escluso dal triage")
        return results
    if results["Executable_Type"] == "UNKNOWN":
        results["Executable_Type"] = "PE (Windows, non parsabile)" if magic[:2] == b"MZ" else "ELF (Linux, non parsabile)"
    if die_ready and results["Die_Status"] == "not_run":
        results.update(run_die_analysis(filepath))
    if results["Capa_Status"] == "not_run":
        _maybe_run_capa(results, filepath, None, None, capa_ready, [])
    # B5: i segnali gia' calcolati NON vanno buttati. Se l'eccezione e' arrivata DOPO
    # l'analisi delle sezioni, packer_sections puo' contenere gia' un segnale FORTE
    # (es. UPX0/.themida) e lief_ok vale True: passarli permette di conservarlo invece
    # di sostituirlo con il debole spurio "header non parsabile".
    strong, weak, info = _packing_signals(results, filepath, list(packer_sections),
                                          results["Executable_Type"].startswith("PE"),
                                          lief_ok=lief_ok)
    _record_classification(results, filename, strong, weak, info)
    _format_for_csv(results)
    return results


def analyze_with_lief(relpath, filepath, compiled_rules, capa_ready=False, die_ready=False,
                      file_hash="", dataset=""):
    filename = os.path.basename(filepath)
    log.debug(f"Inizio analisi LIEF per: {relpath}")

    results = _empty_results(relpath, file_hash, dataset)
    results["Analyzed_At"] = time.strftime("%Y-%m-%d %H:%M:%S")
    # Inizializzati QUI, fuori dal try: se un'eccezione arriva a meta' analisi devono essere
    # comunque leggibili dal gestore, con quello che si era gia' riusciti a raccogliere.
    packer_sections = []
    lief_parsed = False

    try:
        # B13: il magic number si legge PRIMA di qualunque tool. Un file non eseguibile non ha
        # bisogno di YARA, DIE o capa: e' spreco puro. Misurato sul set benigno reale, 30 file
        # su 155 (19%) erano delta di Windows Update con estensione .exe e magic 'DCS', e
        # venivano comunque passati a YARA prima di essere scartati.
        magic = read_magic(filepath)
        if not is_executable_magic(magic):
            results["Executable_Type"] = f"NON_EXECUTABLE (magic {magic.hex() or 'illeggibile'})"
            results["Parse_Status"] = "not_executable"
            _record_classification(results, filename, [], [], [])
            _format_for_csv(results)
            log.info(f"[i] {filename}: non e' un eseguibile PE/ELF (magic {magic.hex()}): escluso dal triage")
            return results

        # Analisi YARA grezza: con timeout (un file patologico non deve bloccare il batch) e stato registrato
        if compiled_rules:
            t_yara = time.monotonic()
            try:
                matches = compiled_rules.match(filepath, timeout=YARA_TIMEOUT)
                results["YARA_Matches"] = [match.rule for match in matches]
                results["Yara_Status"] = "ok"
                if results["YARA_Matches"]:
                    log.warning(f"Match YARA rilevati su {filename}: {', '.join(results['YARA_Matches'])}")
            except yara.TimeoutError:
                results["Yara_Status"] = "timeout"
                log.warning(f"YARA: timeout ({YARA_TIMEOUT}s) su {filename}")
            except Exception as e:
                results["Yara_Status"] = f"error:{type(e).__name__}"
                log.warning(f"YARA: errore su {filename}: {type(e).__name__}: {e}")
            write_tool_diag({"tool": "yara", "target": filename, "status": results["Yara_Status"],
                             "duration_s": round(time.monotonic() - t_yara, 2)}, n_matches=len(results["YARA_Matches"]))
        else:
            results["Yara_Status"] = "unavailable"

        # Parsing Universale con LIEF. Se fallisce il file NON viene scartato (prima un'eccezione o un parse
        # nullo lo eliminavano in silenzio dal CSV e dalla Fase 2): si classifica comunque con YARA/DIE/capa.
        binary, parse_status = None, "lief_none"
        try:
            binary = lief.parse(filepath)
        except Exception as e:
            parse_status = f"lief_error:{type(e).__name__}"
            log_exception_full(log, f"LIEF non riesce a parsare {filename}", e)
        if not binary:
            results["Parse_Status"] = parse_status
            return _finish_without_lief(results, filepath, filename, capa_ready, die_ready)
        results["Parse_Status"] = "ok"
        lief_parsed = True

        is_pe = isinstance(binary, lief.PE.Binary)
        is_elf = isinstance(binary, lief.ELF.Binary)

        if is_pe:
            results["Executable_Type"] = "PE (Windows)"
            # Sottosistema ed export servono a distinguere un binario con IAT legittimamente
            # povera (kernel-mode, o DLL che espone una vera API) da uno con IAT distrutta.
            try:
                results["Subsystem"] = str(binary.optional_header.subsystem).replace("SUBSYSTEM.", "")
            except Exception as e:
                log.debug(f"Sottosistema non leggibile per {filename}: {e}")
            try:
                if binary.has_exports:
                    results["Total_Exports"] = len(list(binary.get_export().entries))
            except Exception as e:
                log.debug(f"Export non leggibili per {filename}: {e}")
        elif is_elf:
            results["Executable_Type"] = "ELF (Linux)"
        else:
            results["Executable_Type"] = "OTHER"

        # Analisi DIE (Detect It Easy): economico (1-4 s), classifica nativamente Packer/Protector/Installer.
        # capa gira DOPO l'analisi delle sezioni (serve a decidere il modo "lazy" e usa is_pe/is_elf per --os).
        if die_ready:
            results.update(run_die_analysis(filepath))

        # ENTRY POINT
        ep = binary.entrypoint
        if is_pe:
            ep_compare = ep - binary.optional_header.imagebase
            if _has_clr_header(binary):
                results["Has_CLR_Header"] = "SI"
        else:
            ep_compare = ep

        # 1. Analisi delle Sezioni
        results["Total_Sections"] = len(binary.sections)
        max_entropy = 0.0
        max_entropy_no_rsrc = 0.0
        ep_section_obj = None

        for section in binary.sections:
            sec_name = _sec_name(section)
            virtual_address = section.virtual_address

            if is_pe:
                virtual_size = section.virtual_size
                raw_size = section.sizeof_raw_data

                # FIX: solo sezioni ESEGUIBILI. .bss/.data con raw_size 0 o virtual > raw sono normali
                # (30/38 file del batch reale erano "anomali" per questo); UPX0/.MPRESS* sono eseguibili
                # e continuano a essere rilevate.
                if _section_is_executable(section):
                    if raw_size == 0 and virtual_size > 0:
                        results["Anomalous_Size_Sections"].append(sec_name if sec_name else "Unnamed_Section")
                    elif raw_size > 0 and (virtual_size > raw_size * 2.5):
                        results["Anomalous_Size_Sections"].append(sec_name if sec_name else "Unnamed_Section")

            elif is_elf:
                virtual_size = section.size
                raw_size = section.size
            else:
                virtual_size = 0
                raw_size = 0

            results["Total_Virtual_Size"] += virtual_size
            results["Total_Raw_Size"] += raw_size

            # Identificazione sezione Entry Point
            if virtual_size > 0 or raw_size > 0:
                sz_bound = max(virtual_size, raw_size)
                if virtual_address <= ep_compare < (virtual_address + sz_bound):
                    results["EP_Section"] = sec_name if sec_name != "" else "Unnamed_Section"
                    ep_section_obj = section

            if not sec_name.strip():
                # sezione ESEGUIBILE senza nome: non e' prodotta dai compilatori, e' tipica di packer/protector
                if is_pe and _section_is_executable(section):
                    results["Suspicious_Sections"].append("(senza nome)")
            elif not is_standard_section_name(sec_name):
                results["Suspicious_Sections"].append(sec_name)

            _plabel = packer_label_from_section_name(sec_name)
            if _plabel:
                packer_sections.append(f"{sec_name}->{_plabel}")

            entropy = section.entropy
            if entropy > max_entropy:
                max_entropy = entropy
            # Le risorse restano nel dato riportato ma non alimentano il segnale: vedi
            # ENTROPY_EXCLUDED_SECTIONS.
            if sec_name.lower() not in ENTROPY_EXCLUDED_SECTIONS and entropy > max_entropy_no_rsrc:
                max_entropy_no_rsrc = entropy

            if entropy > 7.2:
                results["High_Entropy_Sections"] += 1

            # Sezioni ESEGUIBILI compresse/cifrate, registrate per nome: sono l'ingrediente del
            # ripiego .NET dello stub strutturale (_packing_signals), che non puo' usare la
            # sezione dell'entry point perche' un assembly .NET non ne ha una.
            if is_pe and _section_is_executable(section) and entropy >= EP_ENTROPY_THRESHOLD:
                results["Exec_High_Entropy_Sections"].append(sec_name if sec_name else "Unnamed_Section")

        # ELF packed senza Section Header Table (es. UPX): non ci sono sezioni e l'entropia risultava 0.0.
        # Si ricade sui segmenti PT_LOAD, che ci sono sempre perche' servono al loader.
        if is_elf and results["Total_Sections"] == 0:
            try:
                for segment in binary.segments:
                    if "LOAD" in str(segment.type):
                        content = bytes(segment.content)
                        if content:
                            seg_entropy = shannon_entropy(content[:4 * 1024 * 1024])
                            max_entropy = max(max_entropy, seg_entropy)
                            max_entropy_no_rsrc = max(max_entropy_no_rsrc, seg_entropy)
                            if seg_entropy > 7.2:
                                results["High_Entropy_Sections"] += 1
            except Exception as e:
                log.debug(f"Entropia dei segmenti ELF non calcolabile per {filename}: {e}")

        results["Max_Section_Entropy"] = round(max_entropy, 2)
        results["Max_Entropy_No_Rsrc"] = round(max_entropy_no_rsrc, 2)

        # Sezione dell'entry point: entropia e W+X sono segnali piu' specifici dell'entropia massima globale
        # (che scatta anche per risorse/dati compressi in un file normale).
        # B7: un entry point che non cade in nessuna sezione e' un'anomalia forte, ma va
        # distinta dal caso NORMALE della DLL senza entry point (AddressOfEntryPoint = 0),
        # che produce lo stesso EP_Section "UNKNOWN". Senza questa distinzione il segnale
        # scatterebbe su ogni DLL di sistema.
        if ep_section_obj is None and ep_compare != 0:
            results["EP_Outside_Sections"] = "SI"
            log.warning(f"  [!] {filename}: entry point RVA {ep_compare:#x} fuori da ogni sezione")

        if ep_section_obj is not None:
            try:
                results["EP_Section_Entropy"] = round(ep_section_obj.entropy, 2)
                if is_pe:
                    _ch = int(ep_section_obj.characteristics)
                    if (_ch & 0x20000000) and (_ch & 0x80000000):    # EXECUTE + WRITE
                        results["EP_Section_WX"] = "SI"
            except Exception as e:
                log.debug(f"Metriche della sezione EP non calcolabili per {filename}: {e}")

        if is_pe:
            results["Overlay_Size"], results["Overlay_Entropy"] = compute_pe_overlay(binary, filepath)
        results["Size_Difference"] = results["Total_Virtual_Size"] - results["Total_Raw_Size"]

        # CASO SPECIALE ELF: Section Header Table assente
        if is_elf and results["Total_Sections"] == 0:
            results["Sections_Stripped"] = "SI"
            results["Suspicious_Sections"].append("NO_SECTION_HEADERS(stripped)")
            log.warning(f"  [!] {filename}: nessuna sezione ELF trovata (probabile packer che rimuove la SHT)")

        # ANALISI LOCALE DEI SEGMENTI ELF
        if is_elf:
            for idx, segment in enumerate(binary.segments):
                _flags = getattr(segment.flags, "value", segment.flags)
                if "LOAD" in str(segment.type) and (int(_flags) & 1):  # solo PT_LOAD eseguibili (il .bss dei RW e' normale)
                    p_size = segment.physical_size
                    v_size = segment.virtual_size

                    if p_size > 0 and (v_size > p_size * 2.0):
                        results["Anomalous_Size_Sections"].append(f"PT_LOAD_Seg_{idx}")
                    elif p_size == 0 and v_size > 0:
                        results["Anomalous_Size_Sections"].append(f"PT_LOAD_Seg_{idx}")

        # 2. Analisi Imports Cross-Platform
        has_loadlibrary = False
        has_getprocaddress = False
        has_linux_dynamic = False

        if is_pe:
            for imported_lib in binary.imports:
                for entry in imported_lib.entries:
                    results["Total_Imports"] += 1
                    func_name = _txt(entry.name)
                    results["Imported_APIs"].append(func_name)

                    if func_name.startswith("LoadLibrary"):
                        has_loadlibrary = True
                    if func_name == "GetProcAddress":
                        has_getprocaddress = True

            if any(_txt(lib.name).lower() == "mscoree.dll" for lib in binary.imports):
                results["Is_DotNet"] = "SI"
            elif has_loadlibrary and has_getprocaddress and results["Total_Imports"] <= 10:
                results["Suspicious_IAT"] = "SI"

        elif is_elf:
            for symbol in binary.dynamic_symbols:
                if symbol.imported:
                    results["Total_Imports"] += 1
                    func_name = _txt(symbol.name)
                    results["Imported_APIs"].append(func_name)

                    if func_name in ["dlopen", "dlsym"]:
                        has_linux_dynamic = True

            if has_linux_dynamic and results["Total_Imports"] <= 15:
                results["Suspicious_IAT"] = "SI"

        # capa dopo i tool economici e l'analisi delle sezioni: in modo "lazy" puo' essere saltato
        _maybe_run_capa(results, filepath, is_pe, is_elf, capa_ready, packer_sections)

        # ==========================================
        # CALCOLO SCORE DI PACKING (a due livelli: segnali FORTI / DEBOLI, vedi _packing_signals)
        # ==========================================
        strong_signals, weak_signals, info_signals = _packing_signals(results, filepath, packer_sections, is_pe, lief_ok=True)
        _record_classification(results, filename, strong_signals, weak_signals, info_signals)
        _format_for_csv(results)

    except Exception as e:
        # Prima: log.critical + return None = il file spariva dal CSV e dalla Fase 2. Ora si classifica comunque.
        log_exception_full(log, f"Errore inatteso nell'analisi di {filename}", e, level="error")
        results["Parse_Status"] = f"analysis_error:{type(e).__name__}"
        return _finish_without_lief(results, filepath, filename, capa_ready, die_ready,
                                    packer_sections=packer_sections, lief_ok=lief_parsed)

    return results

# ==========================================
# MAIN EXECUTION
# ==========================================
def _archive_csv_if_schema_changed(csv_path):
    """Se il CSV esistente ha colonne diverse da CSV_FIELDNAMES (nuove colonne aggiunte al codice),
    lo archivia come .bak_<timestamp>: appendere righe con colonne diverse a un CSV vecchio lo
    corromperebbe. I file verranno quindi rianalizzati con la logica di scoring aggiornata."""
    if not os.path.exists(csv_path):
        return
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            header = next(csv.reader(f), [])
        if header != CSV_FIELDNAMES:
            bak = f"{csv_path}.bak_{time.strftime('%Y%m%d_%H%M%S')}"
            shutil.move(csv_path, bak)
            log.warning(f"Schema CSV cambiato: vecchio report archiviato in {bak}. Tutti i file verranno rianalizzati.")
    except Exception as e:
        log.error(f"Controllo schema CSV fallito: {e}")


def _tool_versions():
    """Versioni di TUTTO cio' che influenza un risultato, registrate nel report.

    Senza queste, un CSV non e' riproducibile: due run identici su macchine diverse
    possono differire per la versione di DIE, del ruleset capa o della cache YARA, e
    non ci sarebbe modo di accorgersene. Include anche l'interprete, perche' in questo
    progetto convivono due installazioni con LIEF di major diverso (0.17.6 di sistema,
    1.0.0 nel .venv) e solo il .venv puo' eseguire la pipeline."""
    versions = {"python": sys.version.split()[0], "python_exe": sys.executable}
    try:
        versions["lief"] = lief.__version__
    except Exception:
        pass
    try:
        versions["yara"] = yara.__version__
    except Exception:
        pass
    versions["capa"] = get_capa_version() or "sconosciuta"
    try:
        run = run_external("die_version", [DIEC_PATH, "--version"], 15)
        versions["die"] = sanitize_tool_text(run["stdout"])[:60] or "sconosciuta"
    except Exception:
        versions["die"] = "sconosciuta"
    for label, path in (("yara_cache", COMPILED_CACHE), ("capa_rules", CAPA_RULES_DIR)):
        try:
            versions[label + "_mtime"] = time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(path)))
        except OSError:
            versions[label + "_mtime"] = "assente"
    return versions


def _log_phase1_summary(rows, elapsed):
    """Riepilogo di Fase 1 (a log e in tool_diagnostics.jsonl): classificazione, stato di ogni tool, quanti segnali
    forti vengono da UNA sola fonte (fragilita' del triage) e file per cui un tool non ha prodotto risultato."""
    if not rows:
        return
    packed = [r for r in rows if r["Is_Packed_Label"] == 1]
    log.info("=" * 50)
    log.info("RIEPILOGO FASE 1")
    log.info(f"  File analizzati: {len(rows)} in {elapsed:.0f}s | pacchettizzati: {len(packed)} | puliti: {len(rows) - len(packed)}")
    status_cols = ("Parse_Status", "Yara_Status", "Die_Status", "Capa_Status")
    status_summary = {}
    for col in status_cols:
        counts = Counter(str(r[col]) for r in rows)
        status_summary[col] = dict(counts)
        log.info(f"  {col:13s}: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

    sources = {"sezione": "sezione tipica", "YARA": "YARA packer", "capa": "capa:", "DIE": "DIE:",
               "IAT": "IAT minimale", "strutturale": "stub strutturale"}
    per_source = Counter()
    single_source = 0
    for r in packed:
        found = [name for name, key in sources.items() if key in r["Strong_Signals"]]
        per_source.update(found)
        if len(found) == 1:
            single_source += 1
    if packed:
        log.info("  Segnali forti per fonte: " + ", ".join(f"{k}={per_source.get(k, 0)}" for k in sources))
        log.info(f"  Packed con UNA sola fonte forte: {single_source}/{len(packed)} | solo segnali deboli: "
                 f"{sum(1 for r in packed if not r['Strong_Signals'])}")
    names = Counter(r["Die_Packer_Name"] for r in packed if r["Die_Packer_Name"])
    if names:
        log.info("  Packer identificati da DIE: " + ", ".join(f"{k} x{v}" for k, v in names.most_common()))
    non_exec = [r["File"] for r in rows if r["Parse_Status"] == "not_executable"]
    if non_exec:
        log.info(f"  File non eseguibili PE/ELF (esclusi dal triage): {len(non_exec)}")
    problems = [r["File"] for r in rows if r["Parse_Status"] not in ("ok", "not_executable")]
    if problems:
        log.warning(f"  File con parsing LIEF non riuscito (classificati comunque): {', '.join(problems)}")
    log.info(f"  Diagnostica per tool: {TOOL_DIAG_PATH}")
    log.info("=" * 50)
    write_tool_diag({"tool": "phase1_summary", "status": "ok", "duration_s": round(elapsed, 1)},
                    files=len(rows), packed=len(packed), status_summary=status_summary,
                    strong_by_source=dict(per_source), packed_single_source=single_source)


def main(target_dir: str):
    log.info("Inizializzazione dello script di Analisi di Tesi con LIEF Engine")
    _archive_csv_if_schema_changed(OUTPUT_CSV)
    analyzed_history = load_analysis_history(OUTPUT_CSV)

    # Inizializza YARA tramite il nuovo sistema
    compiled_rules = get_yara_rules()
    if not compiled_rules:
        log.error("Regole YARA non disponibili. L'analisi procederà senza il match delle firme.")

    # Inizializza capa: verifica l'eseguibile e scarica/aggiorna il ruleset una sola volta per il batch
    capa_ready = is_capa_available() and ensure_capa_rules() and ensure_capa_sigs()
    if not capa_ready:
        log.error("capa non disponibile (eseguibile o regole mancanti). L'analisi procederà senza capability detection.")

    # Inizializza DIE: verifica diec.exe una sola volta per il batch (stesso schema di capa_ready sopra).
    die_ready = is_die_available()
    if not die_ready:
        log.error("DIE non disponibile (diec.exe non trovato). L'analisi procederà senza DIE.")

    if not os.path.isdir(target_dir):
        log.error(f"Directory non esistente: {target_dir}")
        return

    new_results = []
    files_to_process = []
    tot_files = 0
    dataset = os.path.basename(os.path.normpath(target_dir))

    for root, dirs, files in os.walk(target_dir):
        for filename in files:
            estensione = os.path.splitext(filename)[1].lower()
            filepath_probe = os.path.join(root, filename)
            # L'estensione e' un filtro RAPIDO, non il criterio: i campioni reali arrivano
            # spesso rinominati (.vir, .dat, .bin_) o senza estensione. Se l'estensione non
            # e' fra quelle attese si leggono 4 byte e si decide sul magic number.
            if estensione in VALID_EXTENSIONS or is_executable_magic(read_magic(filepath_probe)):
                tot_files += 1
                filepath = os.path.join(root, filename)
                relpath = os.path.relpath(filepath, target_dir)
                # L'hash si calcola QUI, una volta sola, e diventa sia la chiave dello
                # storico sia una colonna del CSV: e' l'unico identificatore stabile del
                # campione (vedi load_analysis_history).
                file_hash = compute_file_hash(filepath)
                if not file_hash:
                    log.warning(f"Hash non calcolabile per {relpath}: file analizzato ma non tracciabile.")
                if not file_hash or file_hash not in analyzed_history:
                    files_to_process.append((relpath, filepath, file_hash or ""))

    log.info(f"Trovati {tot_files} file candidati. Di cui {len(files_to_process)} nuovi per LIEF Engine.")

    if len(files_to_process) == 0:
        log.info("Nessun nuovo file da analizzare per LIEF. Uscita.")
        return

    # Stato condiviso con la Fase 2: ogni file candidato viene registrato
    # (hash sha256 come chiave) cosi' subprocesses.py puo' capire, in un
    # resume, quali file ha gia' visto e con quale esito.
    state = PipelineState()

    t_phase1 = time.monotonic()
    # Riga di inizio run in tool_diagnostics.jsonl: la configurazione con cui sono stati prodotti i risultati che seguono
    write_tool_diag({"tool": "phase1_start", "status": "ok"}, files=len(files_to_process), capa_ready=capa_ready,
                    die_ready=die_ready, yara_ready=bool(compiled_rules), capa_mode=CAPA_MODE, capa_timeout=CAPA_TIMEOUT,
                    die_args=DIE_ARGS, die_timeout=DIE_TIMEOUT, yara_timeout=YARA_TIMEOUT,
                    capa_probe=[CAPA_PROBE_BASE, CAPA_PROBE_PER_MB], dataset=dataset,
                    weak_required=WEAK_SIGNALS_REQUIRED, ep_entropy_threshold=EP_ENTROPY_THRESHOLD,
                    versions=_tool_versions())
    # Scrittura INCREMENTALE: una riga per file, con flush immediato. Prima il CSV
    # veniva scritto solo a fine batch, quindi un'interruzione a 400 file su 500
    # perdeva tutto (il resume legge il CSV, non lo stato JSON): il "resume"
    # dichiarato in pipeline_utils non valeva per la Fase 1.
    file_exists = os.path.exists(OUTPUT_CSV)
    try:
        output_file = open(OUTPUT_CSV, 'a', newline='', encoding='utf-8')
    except OSError as e:
        log.critical(f"Impossibile aprire il CSV in scrittura ({OUTPUT_CSV}): {e}")
        return
    try:
        dict_writer = csv.DictWriter(output_file, fieldnames=CSV_FIELDNAMES)
        if not file_exists:
            dict_writer.writeheader()
            output_file.flush()

        for relpath, filepath, file_hash in files_to_process:
            t_file = time.monotonic()
            file_data = analyze_with_lief(relpath, filepath, compiled_rules, capa_ready, die_ready,
                                          file_hash=file_hash, dataset=dataset)
            log.debug(f"Fase 1: {relpath} analizzato in {time.monotonic() - t_file:.1f}s")
            if not file_data:
                continue
            new_results.append(file_data)
            try:
                dict_writer.writerow(file_data)
                output_file.flush()
            except Exception as e:
                log.error(f"Errore scrittura della riga CSV per {relpath}: {e}")

            if file_hash:
                # Lo stato e' un ausilio al resume, non un risultato: un suo
                # fallimento non deve mai interrompere l'analisi. Un
                # PermissionError su os.replace (antivirus che tiene il file
                # aperto) ha gia' troncato in silenzio un batch al 47%.
                try:
                    state.update(
                        file_hash,
                        relpath=relpath,
                        dataset=dataset,
                        filename=os.path.basename(filepath),
                        phase1_done=True,
                        packing_score=file_data["Packing_Score_%"],
                        is_packed=bool(file_data["Is_Packed_Label"]),
                        executable_type=file_data["Executable_Type"],
                        final_status="clean" if not file_data["Is_Packed_Label"] else "needs_manual_review",
                    )
                except Exception as e:
                    log_exception_full(log, f"Stato pipeline non aggiornato per {relpath}", e)
    finally:
        output_file.close()
        state.flush()

    log.info(f"Salvati {len(new_results)} risultati in: {OUTPUT_CSV}")
    # Controllo di completezza: se il numero di righe scritte non corrisponde ai
    # candidati, il batch si e' interrotto. Senza questo avviso un run troncato
    # produce un CSV parziale che sembra valido, e le metriche calcolate sopra
    # sarebbero silenziosamente sbagliate.
    if len(new_results) != len(files_to_process):
        log.error(f"BATCH INCOMPLETO: {len(new_results)} righe scritte su "
                  f"{len(files_to_process)} file candidati ({len(files_to_process) - len(new_results)} mancanti). "
                  f"Non usare questo CSV per le metriche finche' il batch non e' completo.")
    _log_phase1_summary(new_results, time.monotonic() - t_phase1)

if __name__ == "__main__":
    print("Avvia questo script tramite il main per testarlo su una cartella.")