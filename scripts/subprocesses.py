import subprocess
import os
import sys
import time
import threading
import collections
import pathlib
import shutil
import json
import glob
import lief
import pefile
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_INTERCEPT, QL_HOOK_BLOCK

from unicorn.unicorn_const import UC_HOOK_BLOCK, UC_HOOK_CODE

from pipeline_utils import (setup_logger, compute_file_hash, PipelineState, OUTPUT_DIR,
                            log_exception_full, write_tool_diag)

log = setup_logger("Fase2-Unpack")


# ==========================================
# MONKEYPATCH QILING: IAT MANCANTE
# ==========================================
# Qiling, in Process.init_imports, itera `pe.DIRECTORY_ENTRY_IMPORT`: pefile non crea l'attributo se la
# import directory e' assente o non parsabile (tipico di un dump di memoria), e il caricamento muore con
# "'PE' object has no attribute 'DIRECTORY_ENTRY_IMPORT'". Lo si imposta a [] prima della init originale.
# (La classe che definisce init_imports e' Process; QlLoaderPE la eredita e la chiama con super().)
def _patch_qiling_init_imports():
    import qiling.loader.pe as _ql_pe

    if getattr(_ql_pe.Process, "_patched_iat", False):
        return   # gia' applicato: evita di annidare il wrapper se il modulo viene reimportato

    _orig_init_imports = _ql_pe.Process.init_imports

    def _safe_init_imports(self, pe, is_driver):
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            pe.DIRECTORY_ENTRY_IMPORT = []
        return _orig_init_imports(self, pe, is_driver)

    _ql_pe.Process.init_imports = _safe_init_imports
    _ql_pe.Process._patched_iat = True


_patch_qiling_init_imports()

# ==========================================
# CONFIGURAZIONE TOOL ESTERNI LOCALI
# ==========================================
UPX_PATH = r"E:\Tools\upx\upx-5.1.1-win64\upx.exe"
IDA_PATH = r"C:\Program Files\IDA Free 9.4\ida.exe"

# --- AspackDie (unpacker statico dedicato per ASPack, versioni 2000-2.12) ---
# https://www.aldeid.com/wiki/AspackDie
# Solo Windows PE/DLL. A differenza di UPX (che accetta -o per l'output
# path), il comportamento DOCUMENTATO di AspackDie e' generare un file
# "unpacked.exe" nella STESSA cartella del file di input, non un path
# configurabile via CLI - unpack_with_aspackdie() si adatta a questo invece
# di assumere un flag -o inventato. ASPACKDIE_ARGS e' lasciato vuoto perche'
# la sintassi esatta degli switch (es. per saltare i messaggi utente) non e'
# documentata in modo affidabile pubblicamente: verificare con
# `AspackDie.exe /?` sulla copia installata prima di un batch grande, e
# aggiungere qui eventuali flag di silenziamento trovate.
ASPACKDIE_PATH = r"E:\Tools\UniExtract\UniExtract\bin\AspackDIE.exe"
ASPACKDIE_ARGS = []
# NOTA (confermato empiricamente): nessuno switch CLI silenzioso trovato
# (help non disponibile). Su un file non-ASPack il tool mostra un popup
# GUI bloccante ("Compressor error: RVA convertion failed") che non si
# chiude da solo. subprocess.run(..., timeout=...) lo termina comunque
# (kill del processo, popup compreso), ma il popup compare quasi subito -
# non ha senso aspettare 20s prima di ammazzarlo, si spreca solo tempo su
# ogni file dove UPX fallisce (non necessariamente ASPack).
ASPACKDIE_TIMEOUT = 8

# --- InnoUnp (unpacker statico dedicato Inno Setup) ---
# Bundle Universal Extractor, stessa cartella di AspackDie. Sintassi basata
# sulla documentazione ufficiale (jrsoftware.org/isinfo.php / pagina innounp):
# -x = extract, -d<dir> = cartella di output (SENZA spazio dopo -d), -y =
# assume yes a tutte le richieste. Verifica comunque con `innounp.exe /?`
# se il nome file bundlato in UniExtract differisce.
INNOUNP_PATH = r"E:\Tools\UniExtract\UniExtract\bin\innounp.exe"
INNOUNP_TIMEOUT = 60

# --- 7-Zip (estrattore di installer e archivi autoestraenti) ---
# Copre NSIS, SFX, CAB, ZIP e altri contenitori. Verificato su un campione NSIS della
# matrice: il payload estratto e' IDENTICO all'originale byte per byte. Nella misura di
# partenza i 97 campioni NSIS/UPX+NSIS erano tutti a zero perche' nessuno strumento li
# toccava.
SEVENZIP_PATH = r"C:\Program Files\7-Zip\7z.exe"
SEVENZIP_TIMEOUT = 120

# --- mal_unpack (PE-sieve dinamico, hasherezade) ---
# https://github.com/hasherezade/mal_unpack
MAL_UNPACK_PATH = r"E:\Tools\mal_unpack\mal_unpack.exe"

# ATTENZIONE - A differenza di UPX/Unipacker/Qiling (statico o emulato),
# mal_unpack DEPLOYA ED ESEGUE DAVVERO il campione come processo reale sulla
# macchina, ne scansiona la memoria a runtime con PE-sieve per individuare i
# payload sbucciati, poi termina il processo. Copre anche packer/loader
# custom sconosciuti agli altri tool (non serve riconoscerne la firma), ma
# e' l'UNICO metodo della cascata che comporta esecuzione reale di codice
# malevolo. USARE SOLO IN UNA VM ISOLATA:
#   - rete disattivata o host-only (niente C2/propagazione durante il run);
#   - snapshot pulito da ripristinare almeno tra una batch e l'altra;
#   - /noresp A (sotto) blocca la ri-esecuzione del campione/dei file
#     rilasciati dopo la sessione, ma non sostituisce l'isolamento della VM.
# Per questo motivo e' disattivato di default: va abilitato esplicitamente
# solo dopo aver verificato l'isolamento dell'ambiente.
MAL_UNPACK_ENABLED = False
MAL_UNPACK_TIMEOUT_MS = 15000       # ms di esecuzione concessi al campione prima di essere terminato
MAL_UNPACK_TIMEOUT_MARGIN_SEC = 30  # margine extra sul subprocess.run oltre al timeout del campione stesso

# --- Unipacker (emulazione di PE a 32 bit, pacchetto pip) ---
# L'eseguibile sta in Scripts/ del venv, che NON e' nel PATH quando la pipeline viene
# lanciata invocando direttamente il python del venv: nella baseline del 29/09/2026,
# 50 tentativi su 50 sono finiti in "[WinError 2] file non trovato" in 0,0 s - cioe'
# Unipacker non era MAI stato eseguito. Si ricava dall'interprete in uso, come per gli
# altri tool si usa un percorso assoluto.
UNIPACKER_PATH = os.path.join(os.path.dirname(sys.executable), "unipacker.exe")
if not os.path.exists(UNIPACKER_PATH):
    UNIPACKER_PATH = "unipacker"          # ripiego: installazione di sistema gia' nel PATH
# Misurato su un MPRESS a 32 bit: ~100 s. I 30 s di prima tagliavano l'emulazione a meta'.
UNIPACKER_TIMEOUT = 300

# --- Ghidra Headless ---
GHIDRA_HEADLESS_PATH = r"C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_12.0.4_PUBLIC\support\analyzeHeadless.bat"
GHIDRA_PROJECT_NAME = "thesis_batch"

# IDA e' l'unico step che blocca il processo in attesa di un umano: su un batch di
# centinaia di file la run non finisce mai, quindi non esiste nessun numero aggregato.
# Con DEFER_IDA il file resta in stato needs_manual_review (la coda e' gia'
# pipeline_state.json) e la run prosegue. Impostato da parameters_info.py --defer-ida.
DEFER_IDA = False
MIN_FUNCTIONS_THRESHOLD = 5

# Spazio libero minimo per proseguire un batch. Il 1 ottobre 2026 una misura su 75 campioni e'
# morta a meta' con "No space left on device": lo stato non e' stato salvato e un dump e' stato
# scritto vuoto, finendo poi letto come risultato. Una misura troncata e' recuperabile (il resume
# riparte da dove si era fermata); una misura CONTAMINATA no, perche' non si distingue dai dati
# buoni. Quindi si preferisce fermarsi prima.
MIN_FREE_DISK_MB = 500

# --- Ciclo di unpacking multilayer ---
# Nel riepilogo di una run precedente (report_riepilogo_unpacking.json) su 22
# file, upx risolveva il primo layer 21 volte ma ida_fallback restava a 22/22
# e ghidra_ok a 0: sintomo tipico di packing multi-layer, dove UPX (o gli
# altri tool) rimuovono solo il layer esterno lasciando un secondo packer
# (spesso custom/offuscato) attivo sul dump risultante. Ghidra allora non
# trova funzioni valide sul file "sbucciato solo a meta'" e la pipeline
# finisce sempre e comunque su IDA, indipendentemente da quanto sia
# realmente complesso il campione.
# MULTILAYER_MAX_LAYERS: numero massimo di round di cascata (upx ->
# unipacker/qiling) ripetuti sullo STESSO file, passando l'output di un
# round come input al successivo. Il ciclo si interrompe PRIMA del limite
# non appena un round non rimuove piu' nulla o il file non mostra piu'
# segnali di packing, quindi 5 e' un tetto di sicurezza, non un numero di
# passate fisso da eseguire sempre.
MULTILAYER_MAX_LAYERS = 5
# Soglia di entropia usata per capire se, dopo un round di unpacking, il
# file mostra ancora segnali di un ulteriore layer di packing (stessa soglia
# usata in Fase 1 - header_elf_lief.py - per le sezioni ad alta entropia).
MULTILAYER_ENTROPY_THRESHOLD = 7.2

# Nomi (prefissi, lowercase) di sezioni tipiche di packer noti: usati da
# looks_still_packed() al posto della vecchia regola "raw_size 0 & virtual_size > 0",
# che scattava anche sui normali .bss dei binari MinGW/GCC (falso positivo
# osservato su b2sum dopo UPX: entropia 6.23 ma "ulteriore layer: SI").
PACKER_SECTION_PREFIXES = (
    "upx", ".upx", ".mpress", ".aspack", ".adata", ".vmp", ".themida",
    ".petite", ".nsp", ".mew", ".fsg", ".yp", ".ndata",
)

# --- Parametri Qiling (v. unpack_with_qiling) ---
QILING_MAX_INSTRUCTIONS = 0            # 0 = nessun tetto di istruzioni (resta QILING_EMU_TIMEOUT_SEC). Con gli hook globali
                                       # localizzati lo stub gira a ~50 M istr/s: il vecchio tetto di 300 M fermava ae8b dopo 6 s
QILING_EMU_TIMEOUT_SEC = 600           # tetto in tempo reale
QILING_HEARTBEAT_SEC = 15              # riga [HEARTBEAT] ogni N secondi (l'emulazione del layer 0 non ha callback Python)
QILING_POLL_SEC = 2.0                  # dopo un layer: ogni N secondi confronta l'immagine con lo snapshot
# --- Euristica OEP "scrivi-poi-esegui", parametri espliciti ---
# Un candidato OEP e' valido solo se e' il primo indirizzo eseguito in una pagina
# PRECEDENTEMENTE SCRITTA a runtime dal processo. Due filtri contro i falsi positivi:
QILING_OEP_WARMUP_BLOCKS = 200         # blocchi ignorati all'avvio (setup del runtime). Gli hook sono
                                       # PER BLOCCO, non per istruzione, quindi 200 blocchi coprono
                                       # abbondantemente le 200 istruzioni di warmup richieste.
QILING_MIN_WRITTEN_BYTES = 4096        # byte scritti minimi perche' sia un payload e non una fixup
QILING_MIN_CHANGED_PAGES = max(1, QILING_MIN_WRITTEN_BYTES // 0x1000)
QILING_MAX_LAYERS = 4                  # transizioni write->execute successive registrate in UNA emulazione
QILING_POST_LAYER_SECONDS = 45         # dopo un layer: se per N secondi l'immagine non cambia piu' -> stop
QILING_RDTSC_BYPASS = False            # hook per-istruzione: molto costoso, attivalo solo se lo stub usa RDTSC
# API che lo stub del layer 1+ tipicamente chiama: loggate (nome + primi argomenti) in un ring buffer che
# viene stampato a fine emulazione ([END]). Serve a capire PERCHE' un'emulazione finisce presto.
QILING_TRACE_APIS = (
    "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
    "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExW", "VirtualProtect", "VirtualAlloc",
    "VirtualFree", "ExitProcess", "TerminateProcess", "NtTerminateProcess", "ZwTerminateProcess", "RtlExitUserProcess",
    "ZwRaiseHardError", "NtRaiseHardError", "FatalExit",   # uscite volontarie di uno stub anti-analisi (visto su 197d802c...)
    "GetCommandLineA", "GetCommandLineW", "GetStartupInfoA", "GetStartupInfoW", "exit", "_exit", "abort",
)
QILING_USE_RAW_UC_HOOKS = True         # hook a blocchi direttamente su Unicorn (il wrapper di Qiling costa molto di piu')
MIN_VALID_DUMP_ENTROPY = 1.0           # dump con entropia max sezioni < 1.0 = sezioni vuote/a zero -> invalido

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
CONFIG_DIR = os.path.join(PARENT_DIR, "config", "rootfs-master")

QILING_ROOTFS_WIN64 = os.path.join(CONFIG_DIR, "x8664_windows")
QILING_ROOTFS_LINUX64 = os.path.join(CONFIG_DIR, "x8664_linux")

GHIDRA_SCRIPTS_DIR = os.path.join(SCRIPT_DIR, "ghidra_scripts")

# OUTPUT_DIR (report CSV/JSON della pipeline) e' importato da
# pipeline_utils.py: fonte unica condivisa anche da header_elf_lief.py e
# header_info.py. UNPACKED_SAMPLES/ e GHIDRA_PROJECTS/ restano invece dove
# erano gia' (PARENT_DIR), su richiesta esplicita: non vengono spostate qui.
GHIDRA_PROJECTS_DIR = os.path.join(PARENT_DIR, "GHIDRA_PROJECTS")

SUMMARY_REPORT_PATH = os.path.join(OUTPUT_DIR, "report_riepilogo_unpacking.json")


def _sweep_qiling_temp():
    """Svuota le cartelle Temp delle rootfs di Qiling.

    unpack_with_qiling copia il campione in <rootfs>/Windows/Temp e lo rimuove nel finally,
    ma se il processo muore prima (timeout esterno, kill, disco pieno) la copia resta. Misurato
    il 1 ottobre 2026: 227 MB in 39 file residui. Una passata a inizio batch basta: e' l'unico
    punto che scrive li' dentro."""
    removed = 0
    for rootfs in (QILING_ROOTFS_WIN64, QILING_ROOTFS_LINUX64):
        temp_dir = os.path.join(rootfs, "Windows", "Temp")
        if not os.path.isdir(temp_dir):
            continue
        for name in os.listdir(temp_dir):
            try:
                path = os.path.join(temp_dir, name)
                shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
                removed += 1
            except OSError:
                pass
    if removed:
        log.info(f"[i] Rimossi {removed} file residui dalle Temp delle rootfs di Qiling.")


def check_tool_paths():
    """Verifica che i path configurati esistano realmente sul sistema."""
    log.debug("--- CONTROLLO TOOL ESTERNI ---")
    _sweep_qiling_temp()
    if os.path.exists(UPX_PATH):
        log.debug(f"[+] UPX trovato: {UPX_PATH}")
    else:
        log.error(f"UPX NON trovato in {UPX_PATH}")

    if os.path.exists(IDA_PATH):
        log.debug(f"[+] IDA trovato: {IDA_PATH}")
    else:
        log.error(f"IDA NON trovato in {IDA_PATH}")

    if os.path.exists(ASPACKDIE_PATH):
        log.debug(f"[+] AspackDie trovato: {ASPACKDIE_PATH}")
    else:
        log.warning(f"AspackDie non trovato in {ASPACKDIE_PATH} (step 1bis opzionale, verra' saltato).")

    if os.path.exists(INNOUNP_PATH):
        log.debug(f"[+] InnoUnp trovato: {INNOUNP_PATH}")
    else:
        log.warning(f"InnoUnp non trovato in {INNOUNP_PATH} (step 1bis opzionale, verra' saltato).")

    if os.path.exists(SEVENZIP_PATH):
        log.debug(f"[+] 7-Zip trovato: {SEVENZIP_PATH}")
    else:
        log.warning(f"7-Zip non trovato in {SEVENZIP_PATH}: gli installer NSIS non verranno estratti.")

    if MAL_UNPACK_ENABLED:
        if os.path.exists(MAL_UNPACK_PATH):
            log.debug(f"[+] mal_unpack trovato: {MAL_UNPACK_PATH}")
        else:
            log.error(f"mal_unpack NON trovato in {MAL_UNPACK_PATH}")
    else:
        log.info("[i] mal_unpack disattivato (MAL_UNPACK_ENABLED=False): verificare l'isolamento della VM prima di attivarlo.")

    if UNIPACKER_PATH == "unipacker" or os.path.exists(UNIPACKER_PATH):
        log.debug(f"[+] Unipacker: {UNIPACKER_PATH}")
    else:
        log.error(f"Unipacker NON trovato in {UNIPACKER_PATH} (ramo 32 bit disattivato).")

    if os.path.exists(GHIDRA_HEADLESS_PATH):
        log.debug(f"[+] Ghidra trovato: {GHIDRA_HEADLESS_PATH}")
    else:
        log.error(f"Ghidra NON trovato in {GHIDRA_HEADLESS_PATH}")

    if not os.path.isdir(GHIDRA_SCRIPTS_DIR):
        log.error(f"Cartella script Ghidra non trovata: {GHIDRA_SCRIPTS_DIR}")

    if os.path.exists(QILING_ROOTFS_WIN64) or os.path.exists(QILING_ROOTFS_LINUX64):
        log.debug("[+] Rootfs per Qiling trovate.")
    else:
        log.warning("Rootfs Qiling mancanti. Qiling fallirà se chiamato.")


def get_binary_info(filepath):
    """
    (is_windows, is_64bit) se il file e' un PE, altrimenti None.

    FUORI PERIMETRO: l'ELF e' rinviato a sviluppo futuro. Il vecchio fallback
    conservativo (True, True) non scartava i non-PE, li faceva passare per PE a
    64 bit: finivano in Qiling a bruciare fino a 600 s per poi fallire. Ora il
    chiamante li salta registrandone il motivo.
    """
    try:
        parsed = lief.parse(filepath)
    except Exception as e:
        log.warning(f"LIEF non ha potuto parsare {os.path.basename(filepath)}: {e}")
        return None

    if not isinstance(parsed, lief.PE.Binary):
        return None

    return True, parsed.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64


def unpack_with_upx(filepath, output_dir, is_windows):
    """
    Tenta l'unpacking nativo con UPX, con due tentativi in cascata:
    1. Decompressione standard.
    2. Decompressione forzata (--force): recupera i casi, frequenti in
       campioni reali, in cui l'header UPX è stato leggermente alterato
       (o proviene da una versione diversa) apposta per rompere `upx -d`
       "pulito" pur restando comunque decomprimibile. Prima di questo fix
       questi casi finivano quasi sempre nella cascata di emulazione o
       dritti su IDA, anche se UPX da solo li avrebbe gestiti.

    Bug corretto: prima l'estensione di output era sempre ".exe" anche per
    campioni ELF (Linux); ora segue il tipo reale del binario.
    """
    filename = os.path.basename(filepath)
    ext = ".exe" if is_windows else ""
    unpacked_path = os.path.join(output_dir, f"{filename}_upx_unpacked{ext}")

    attempts = [
        ("standard", ["-d", filepath, "-o", unpacked_path]),
        ("forzato (--force)", ["-d", "--force", filepath, "-o", unpacked_path]),
    ]

    for label, args in attempts:
        command = [UPX_PATH] + args
        log.info(f"  [>] Tentativo UPX ({label}) su {filename}...")

        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
            full_output = (result.stdout + result.stderr).lower()

            if "unpacked 1 file" in full_output:
                log.info(f"  [+] UPX ha avuto successo ({label})!")
                return unpacked_path
            else:
                log.debug(f"  [-] UPX ({label}) terminato senza successo. Output: {result.stdout.strip()}")

        except subprocess.TimeoutExpired:
            log.warning(f"  [!] Timeout: UPX ({label}) ha superato i 15 secondi.")
        except Exception as e:
            log.warning(f"  [!] Eccezione Python in UPX ({label}): {str(e)}")

    return None


def unpack_with_aspackdie(filepath, output_dir, is_windows):
    """
    Tenta l'unpacking statico dedicato tramite AspackDie
    (https://www.aldeid.com/wiki/AspackDie), che copre le versioni ASPack
    dal 2000 alla 2.12. E' un tentativo "Tecnica 1bis": statico, deterministico,
    zero rischio, va provato PRIMA di scomodare Unipacker/Qiling - stessa
    filosofia static-first gia' applicata a UPX nella cascata.

    Solo Windows (PE/DLL): su ELF ritorna None immediatamente.

    A differenza di UPX/Unipacker (che accettano un output path via CLI),
    il comportamento documentato di AspackDie e' generare un file
    "unpacked.exe" nella STESSA cartella del file di input. Questa funzione
    ripulisce eventuali residui di un tentativo precedente, lancia il tool,
    e se "unpacked.exe" compare lo sposta nella output_dir standard della
    pipeline con la naming convention coerente con gli altri unpacker.
    """
    if not is_windows:
        return None

    if not os.path.exists(ASPACKDIE_PATH):
        log.debug("  [-] AspackDie non configurato/trovato. Salto lo step 1bis.")
        return None

    filename = os.path.basename(filepath)
    input_dir = os.path.dirname(filepath)

    # Nome di output fisso e non configurabile (comportamento documentato):
    # rimuoviamo un eventuale residuo stantio prima di lanciare, altrimenti
    # un vecchio "unpacked.exe" già presente sarebbe letto come falso successo.
    default_output = os.path.join(input_dir, "unpacked.exe")
    if os.path.exists(default_output):
        try:
            os.remove(default_output)
        except OSError:
            pass

    command = [ASPACKDIE_PATH] + ASPACKDIE_ARGS + [filepath]
    log.info(f"  [>] Tentativo 1bis: AspackDie (statico, dedicato ASPack) su {filename}...")

    try:
        subprocess.run(command, capture_output=True, text=True, timeout=ASPACKDIE_TIMEOUT)

        if os.path.exists(default_output) and os.path.getsize(default_output) > 0:
            final_path = os.path.join(output_dir, f"{filename}_aspackdie_unpacked.exe")
            shutil.move(default_output, final_path)
            log.info("  [+] AspackDie ha avuto successo!")
            return final_path

        log.debug("  [-] AspackDie non ha generato 'unpacked.exe' "
                   "(file non protetto con ASPack, o versione non supportata dal tool).")

    except subprocess.TimeoutExpired:
        log.warning(f"  [!] Timeout: AspackDie ha superato i {ASPACKDIE_TIMEOUT} secondi.")
    except Exception as e:
        log.warning(f"  [!] Eccezione Python in AspackDie: {str(e)}")

    return None


def _pick_payload(extract_dir, output_dir, filename, tool, suffix):
    """Sceglie il payload da un albero estratto da un CONTENITORE (installer, archivio).

    Euristica esplicita, condivisa da InnoUnp e 7-Zip: fra gli .exe estratti si prende il
    piu' grande, escludendo i disinstallatori generati automaticamente (`unins*`). L'albero
    completo resta su disco per la revisione manuale nei casi dubbi, perche' qui l'euristica
    puo' sbagliare.

    Ritorna il path del payload copiato in output_dir, o None se non c'e' nessun .exe.
    """
    candidates = [
        p for p in glob.glob(os.path.join(extract_dir, "**", "*.exe"), recursive=True)
        if not os.path.basename(p).lower().startswith("unins")
    ]
    if not candidates:
        return None

    payload = max(candidates, key=os.path.getsize)
    final_path = os.path.join(output_dir, f"{filename}{suffix}")
    shutil.copy2(payload, final_path)

    if len(candidates) > 1:
        log.info(f"  [i] {tool} ha estratto {len(candidates)} eseguibili: scelto il piu' grande "
                 f"({os.path.basename(payload)}). Albero completo in {extract_dir}.")
    log.info(f"  [+] {tool} ha avuto successo!")
    return final_path


def unpack_with_innounp(filepath, output_dir, is_windows):
    """
    Estrae staticamente un installer Inno Setup tramite InnoUnp
    (innounp.exe, bundle Universal Extractor). A differenza degli altri
    unpacker della cascata (1 file in -> 1 file out), Inno Setup e' un
    CONTENITORE: l'estrazione produce un intero albero di file installati,
    non un singolo eseguibile.

    Strategia di selezione del payload (euristica esplicita, da verificare
    a mano nei casi dubbi tramite Ghidra/IDA come il resto della pipeline):
    - si escludono i disinstallatori generati automaticamente da Inno Setup
      (pattern di nome standard "unins*.exe");
    - tra gli .exe rimanenti si sceglie il piu' grande per dimensione,
      assumendo sia il payload principale (eventuali tool ausiliari
      bundlati nell'installer sono in genere molto piu' piccoli).

    L'albero estratto completo viene conservato (non ripulito) in
    "<output_dir>/<filename>_innounp_extract/" per revisione manuale se ci
    sono piu' candidati - utile perche' qui l'euristica puo' sbagliare.

    Ritorna il path del payload scelto (copiato in output_dir con naming
    coerente col resto della cascata), o None.
    """
    if not is_windows:
        return None

    if not os.path.exists(INNOUNP_PATH):
        log.debug("  [-] InnoUnp non configurato/trovato. Salto lo step 1bis.")
        return None

    filename = os.path.basename(filepath)
    extract_dir = os.path.join(output_dir, f"{filename}_innounp_extract")
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir, ignore_errors=True)
    os.makedirs(extract_dir, exist_ok=True)

    command = [INNOUNP_PATH, "-x", f"-d{extract_dir}", "-b", "-y", filepath]
    log.info(f"  [>] Tentativo 1bis: InnoUnp (statico, dedicato Inno Setup) su {filename}...")

    try:
        proc = subprocess.run(command, capture_output=True, text=True, timeout=INNOUNP_TIMEOUT)

        payload = _pick_payload(extract_dir, output_dir, filename, "InnoUnp",
                                "_innounp_unpacked.exe")
        if payload:
            return payload
        log.debug(f"  [-] InnoUnp: nessun payload .exe trovato dopo l'estrazione "
                  f"(non era un installer Inno Setup, o solo DLL/dati). "
                  f"stdout: {proc.stdout.strip()[:200]}")
        shutil.rmtree(extract_dir, ignore_errors=True)   # come 7-Zip: niente alberi vuoti in giro
        return None

    except subprocess.TimeoutExpired:
        log.warning(f"  [!] Timeout: InnoUnp ha superato i {INNOUNP_TIMEOUT} secondi.")
    except Exception as e:
        log.warning(f"  [!] Eccezione Python in InnoUnp: {str(e)}")

    return None


def unpack_with_7zip(filepath, output_dir, is_windows):
    """
    Estrae un installer o un archivio autoestraente con 7-Zip: NSIS, SFX, CAB, ZIP.

    Come InnoUnp, e a differenza degli unpacker 1-a-1 della cascata, produce un ALBERO di
    file, non un singolo eseguibile. La selezione del payload usa la stessa euristica
    esplicita di InnoUnp: fra gli .exe estratti si prende il piu' grande, escludendo i
    disinstallatori generati automaticamente. L'albero completo resta su disco per la
    revisione manuale nei casi dubbi.

    Verificato sulla matrice: su un NSIS il payload estratto ($PLUGINSDIR/payload.exe) ha
    lo stesso SHA-256 dell'originale pulito.
    """
    if not is_windows:
        return None

    if not os.path.exists(SEVENZIP_PATH):
        log.debug("  [-] 7-Zip non trovato. Salto l'estrazione.")
        return None

    filename = os.path.basename(filepath)
    extract_dir = os.path.join(output_dir, f"{filename}_7z_extract")
    shutil.rmtree(extract_dir, ignore_errors=True)
    os.makedirs(extract_dir, exist_ok=True)

    log.info(f"  [>] Tentativo 1bis: 7-Zip (estrazione installer/archivio) su {filename}...")

    try:
        proc = subprocess.run([SEVENZIP_PATH, "x", filepath, f"-o{extract_dir}", "-y"],
                              capture_output=True, text=True, timeout=SEVENZIP_TIMEOUT)

        payload = _pick_payload(extract_dir, output_dir, filename, "7-Zip",
                                "_7z_unpacked.exe")
        if payload:
            return payload
        log.debug(f"  [-] 7-Zip: nessun eseguibile estratto (non era un contenitore, o "
                  f"conteneva solo dati). stdout: {proc.stdout.strip()[:200]}")
        shutil.rmtree(extract_dir, ignore_errors=True)
        return None

    except subprocess.TimeoutExpired:
        log.warning(f"  [!] Timeout: 7-Zip ha superato i {SEVENZIP_TIMEOUT} secondi.")
    except Exception as e:
        log.warning(f"  [!] Eccezione Python in 7-Zip: {e}")

    return None


def _timed(method, fn, *args):
    """Esegue un tentativo di unpacking misurandolo, e ne scrive una riga in
    tool_diagnostics.jsonl (stesso file e stesso schema della Fase 1).

    Senza questo non si sa dove va il tempo: nel batch storico l'86% del wall
    clock stava in Qiling e il 51% in timeout senza risultato, ma il dato e'
    emerso solo a posteriori rileggendo il log a mano."""
    t0 = time.monotonic()
    try:
        result = fn(*args)
        status = "ok" if result else "no_output"
    except Exception as e:
        log_exception_full(log, f"Eccezione non gestita in {method}", e)
        result, status = None, "exception"
    write_tool_diag(
        {"tool": method, "target": os.path.basename(args[0]), "status": status,
         "duration_s": round(time.monotonic() - t0, 2)},
        phase="fase2", output=os.path.basename(result) if result else None)
    return result


def unpack_with_unipacker(filepath, output_dir):
    """Unpacking emulato con Unipacker (solo PE a 32 bit).

    CONTRATTO DI UNIPACKER, verificato in `unipacker/io_handler.py` della copia installata:
    `-d` e' una CARTELLA, e il file prodotto si chiama `unpacked_<nome originale>` al suo
    interno. Prima gli si passava un percorso di FILE: Unipacker lo trattava come cartella,
    la creava, ci scriveva dentro il risultato, e il nostro controllo su quel percorso
    falliva sempre - anche quando l'unpacking era riuscito.

    Il file prodotto viene poi spostato con il nome che usa il resto della cascata, cosi'
    UNPACKED_SAMPLES/ resta piatta come con gli altri tool.
    """
    filename = os.path.basename(filepath)

    # Un dump di un round precedente non e' ri-emulabile: l'entry point cade in mezzo al
    # codice gia' scompattato e l'emulazione gira fino al timeout senza produrre nulla.
    # Misurato sulla baseline a 32 bit: 300 s buttati per ogni MPRESS riuscito al round 1.
    # Qiling ha gia' la stessa guardia sui propri dump.
    if filename.endswith("_unipacker_unpacked.exe"):
        log.info(f"  [-] Unipacker saltato: {filename} e' gia' un suo dump di un round precedente.")
        return None

    work_dir = os.path.join(output_dir, f"{filename}_unipacker_out")
    produced = os.path.join(work_dir, f"unpacked_{filename}")
    final_path = os.path.join(output_dir, f"{filename}_unipacker_unpacked.exe")

    # Un residuo di una run precedente verrebbe scambiato per un successo di questa.
    shutil.rmtree(work_dir, ignore_errors=True)

    log.info(f"  [>] Tentativo 2a: Unipacker (x86 32-bit) su {filename}...")
    try:
        subprocess.run([UNIPACKER_PATH, filepath, "-d", work_dir],
                       capture_output=True, text=True, timeout=UNIPACKER_TIMEOUT)

        if os.path.exists(produced) and os.path.getsize(produced) > 0:
            os.replace(produced, final_path)
            shutil.rmtree(work_dir, ignore_errors=True)
            log.info("  [+] Unipacker ha avuto successo! (payload estratto con emulazione CPU)")
            return final_path

        log.debug(f"  [-] Unipacker terminato senza produrre {os.path.basename(produced)}.")

    except subprocess.TimeoutExpired:
        log.warning(f"  [-] Timeout: Unipacker ha superato i {UNIPACKER_TIMEOUT} s.")
    except Exception as e:
        log.warning(f"  [!] Eccezione Python in Unipacker: {e}")

    shutil.rmtree(work_dir, ignore_errors=True)
    return None


def unpack_with_mal_unpack(filepath, output_dir, is_windows, timeout_ms=MAL_UNPACK_TIMEOUT_MS):
    """
    Tenta l'unpacking dinamico "reale" tramite mal_unpack (PE-sieve, hasherezade):
    https://github.com/hasherezade/mal_unpack

    A differenza di Qiling (emulato in sandbox), mal_unpack DEPLOYA ED ESEGUE
    DAVVERO il campione, ne scansiona la memoria a runtime per individuare i
    payload sbucciati (PE implantati/hollowed, senza bisogno di riconoscere
    il packer specifico) e termina il processo. E' quindi il fallback con la
    copertura piu' ampia prima di Ghidra/IDA, al prezzo di eseguire codice
    potenzialmente malevolo reale: vedi il blocco di commenti sopra
    MAL_UNPACK_ENABLED per i requisiti di isolamento.

    Disattivato di default (MAL_UNPACK_ENABLED=False) e comunque applicabile
    solo a campioni Windows (PE-sieve e' nativo Win32/Win64: su ELF/Linux
    questa funzione ritorna subito None).
    """
    if not MAL_UNPACK_ENABLED:
        log.debug("  [-] mal_unpack disattivato (MAL_UNPACK_ENABLED=False). Salto.")
        return None

    if not is_windows:
        log.debug("  [-] mal_unpack saltato: supporta solo campioni Windows (PE-sieve e' nativo Win32/Win64).")
        return None

    if not os.path.exists(MAL_UNPACK_PATH):
        log.error(f"  [!] mal_unpack non trovato in {MAL_UNPACK_PATH}. Salto.")
        return None

    filename = os.path.basename(filepath)
    # Sottocartella dedicata per campione: mal_unpack/PE-sieve annidano gia'
    # al loro interno una sotto-sottocartella per PID, quindi qui basta
    # isolare per nome file per evitare che run su campioni diversi si
    # mescolino nello stesso posto.
    mal_out_dir = os.path.join(output_dir, f"{filename}_mal_unpack_out")
    os.makedirs(mal_out_dir, exist_ok=True)

    command = [
        MAL_UNPACK_PATH,
        "/exe", filepath,
        "/timeout", str(timeout_ms),
        "/out_dir", mal_out_dir,
        "/noresp", "A",  # blocca la ri-esecuzione del campione/dei file rilasciati dopo la sessione
    ]

    log.warning(f"  [>] Tentativo mal_unpack su {filename}: IL CAMPIONE VERRA' ESEGUITO DAVVERO "
                f"per {timeout_ms} ms. Verificare di essere in una VM isolata prima di procedere.")

    try:
        subprocess.run(
            command,
            capture_output=True, text=True,
            timeout=(timeout_ms / 1000) + MAL_UNPACK_TIMEOUT_MARGIN_SEC,
        )
    except subprocess.TimeoutExpired:
        log.warning("  [!] mal_unpack: superato anche il margine di sicurezza Python "
                    "(processo forse non terminato correttamente).")
        return None
    except FileNotFoundError:
        log.error(f"Eseguibile mal_unpack non trovato ('{MAL_UNPACK_PATH}').")
        return None
    except Exception as e:
        log.warning(f"  [!] Eccezione Python in mal_unpack: {str(e)}")
        return None

    # mal_unpack/PE-sieve ricostruisce gia' i PE dumped (header e sezioni
    # riallineati): a differenza di Qiling non serve un fixup LIEF a parte.
    # Non ci affidiamo pero' al naming esatto dei file dumped (puo' variare
    # tra versioni di PE-sieve): cerchiamo ricorsivamente nella cartella di
    # output tutto cio' che LIEF riconosce come PE valido, e teniamo il piu'
    # grande come payload principale piu' plausibile (i dump di hook/patch
    # minori sono in genere molto piu' piccoli del payload completo).
    best_candidate = None
    best_size = -1
    for root, _dirs, files in os.walk(mal_out_dir):
        for fname in files:
            if fname.lower().endswith((".json", ".tag")):
                continue
            candidate_path = os.path.join(root, fname)
            try:
                binary = lief.parse(candidate_path)
                if binary and isinstance(binary, lief.PE.Binary):
                    size = os.path.getsize(candidate_path)
                    if size > best_size:
                        best_candidate = candidate_path
                        best_size = size
            except Exception:
                continue

    if best_candidate:
        log.info(f"  [+] mal_unpack ha prodotto un dump PE valido: "
                 f"{os.path.basename(best_candidate)} ({best_size} byte).")
        return best_candidate

    log.debug(f"  [-] mal_unpack non ha prodotto dump PE validi in {mal_out_dir}.")
    return None


# ==========================================
# FUNZIONE LIEF PER RICOSTRUZIONE OFFLINE
# ==========================================
def _dump_sanity(path):
    """Ritorna (entropia_max_sezioni, frazione_byte_non_zero) del PE in `path`.
    Serve a non dichiarare "successo" su un dump con sezioni vuote."""
    pe = pefile.PE(path, fast_load=True)
    try:
        max_ent, nz, tot = 0.0, 0, 0
        for s in pe.sections:
            data = s.get_data()
            if not data:
                continue
            max_ent = max(max_ent, s.get_entropy())
            nz += len(data) - data.count(b"\x00")
            tot += len(data)
        return round(max_ent, 2), (nz / tot if tot else 0.0)
    finally:
        pe.close()


def rebuild_pe_offline_with_lief(dumped_path, oep_address, is_windows, image_base=None):
    """
    Converte il dump di memoria (layout VIRTUALE: byte a offset = RVA) in un PE
    caricabile da Ghidra/IDA.

    FIX: la versione precedente faceva lief.parse(dump) + binary.write(). Ma
    LIEF legge il contenuto delle sezioni dai pointerto_raw_data dell'header
    ORIGINALE (layout su disco dello stub), che nel dump non corrispondono piu':
    le sezioni con raw_size 0 (UPX0, .MPRESS*) risultavano vuote e il file
    scritto aveva entropia max 0.0 (Ghidra: 1 funzione). Ora si patcha
    l'header IN PLACE con pefile, lasciando i byte del dump intatti:
    PointerToRawData = VirtualAddress, SizeOfRawData = dimensione in memoria.

    image_base: base REALE a cui Qiling ha caricato l'immagine (puo' differire
    dall'ImageBase dell'header); se assente si usa quella dell'header.
    Ritorna il path del PE ricostruito, o dumped_path se non ricostruibile.
    """
    if not is_windows:
        log.info("  [i] Ricostruzione offline attualmente supportata solo per PE (Windows).")
        return dumped_path

    log.info(f"  [>] Ricostruzione offline dell'header PE (pefile, patch in place) su {os.path.basename(dumped_path)}...")
    pe = None
    try:
        pe = pefile.PE(dumped_path, fast_load=True)
        dump_size = os.path.getsize(dumped_path)
        hdr_base = pe.OPTIONAL_HEADER.ImageBase
        real_base = image_base if image_base else hdr_base
        if real_base != hdr_base:
            log.debug(f"  [DEBUG] Base reale {hex(real_base)} != ImageBase header {hex(hdr_base)}: uso la base reale.")

        pe.OPTIONAL_HEADER.ImageBase = real_base
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = oep_address - real_base
        # Disabilita ASLR (DYNAMIC_BASE): gli indirizzi nel dump sono gia' rilocati alla base reale
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~0x0040

        file_align = pe.OPTIONAL_HEADER.FileAlignment or 0x200
        for s in pe.sections:
            size = max(s.Misc_VirtualSize, s.SizeOfRawData)
            size = (size + file_align - 1) // file_align * file_align
            size = min(size, max(dump_size - s.VirtualAddress, 0))  # mai oltre la fine del dump
            s.PointerToRawData = s.VirtualAddress
            s.SizeOfRawData = size

        fixed_path = dumped_path.replace("_qiling_unpacked.bin", "_lief_fixed.exe")  # nome invariato: compat. downstream
        pe.write(filename=fixed_path)
        pe.close()
        pe = None

        max_ent, nz_ratio = _dump_sanity(fixed_path)
        log.info(f"  [i] Dump ricostruito: entropia max sezioni={max_ent}, byte non-zero={nz_ratio:.1%}.")
        if max_ent < MIN_VALID_DUMP_ENTROPY:
            log.warning("  [-] Dump non valido (sezioni vuote/a zero): scarto il risultato.")
            os.remove(fixed_path)
            return None

        log.info(f"  [+] Eseguibile PE ricostruito con successo in: {os.path.basename(fixed_path)} "
                 "(nota: import directory dello stub, IAT non ricostruita)")
        os.remove(dumped_path)
        return fixed_path

    except Exception as e:
        log_exception_full(log, "Eccezione durante la ricostruzione PE", e)
        return dumped_path
    finally:
        if pe is not None:
            pe.close()


def _has_other_packer_sections(filepath):
    """True se i nomi sezione indicano UPX/MPRESS/NSIS: in quel caso AspackDie/InnoUnp sono inutili
    (AspackDie e' un tool GUI: sui file non ASPack va in timeout e costa ~8 s ogni volta)."""
    try:
        pe = pefile.PE(filepath, fast_load=True)
        try:
            names = [s.Name.rstrip(b"\x00").decode(errors="ignore").lower() for s in pe.sections]
        finally:
            pe.close()
        return any(n.startswith(("upx", ".upx", ".mpress", ".ndata")) for n in names)
    except Exception:
        return False


def _pe_info(filepath):
    """(is_dll, (lo, hi) RVA della sezione che contiene l'EP o None) - letto dall'header, senza emulare."""
    pe = pefile.PE(filepath, fast_load=True)
    try:
        is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_range = None
        for s in pe.sections:
            lo = s.VirtualAddress
            hi = lo + max(s.Misc_VirtualSize, s.SizeOfRawData)
            if lo <= ep < hi:
                ep_range = (lo, hi)
                break
        return is_dll, ep_range
    finally:
        pe.close()


def _install_qiling_compat_hooks(ql):
    """
    Implementa le API Windows che Qiling 1.4.x NON implementa e che gli stub dei packer usano davvero.

    Qiling, per un'API non implementata, logga "api X is not implemented" e lascia eseguire il codice
    reale della DLL nella rootfs: l'emulazione prosegue ma con valori di ritorno sbagliati. Caso reale
    (197d802c..., 9fed8bc8...): lo stub chiama ZwOpenSection + ZwMapViewOfSection per mappare una copia
    "pulita" di ntdll, la base mappata resta 0 e la prima lettura ([rax+...] con rax=0) da'
    UC_ERR_READ_UNMAPPED dopo minuti di emulazione.

    ATTENZIONE: su Windows un handler passato a set_api(..., QL_INTERCEPT.CALL) viene invocato come
    handler(ql, address, api_name) e deve essere decorato con @winsdkapi, altrimenti il valore di
    ritorno viene ignorato e lo stack non viene ripulito.
    """
    from qiling.os.const import POINTER, HANDLE, DWORD
    from qiling.os.windows.fncc import winsdkapi, STDCALL
    from qiling.os.windows.handle import Handle

    psize = ql.arch.pointersize
    STATUS_SUCCESS = 0

    def _object_name(ql_, object_attributes):
        """Nome dall'OBJECT_ATTRIBUTES -> UNICODE_STRING (Length@0, Buffer@pointersize)."""
        try:
            us_ptr = ql_.mem.read_ptr(object_attributes + 2 * psize)
            length = ql_.mem.read_ptr(us_ptr, 2)
            buf = ql_.mem.read_ptr(us_ptr + psize)
            return bytes(ql_.mem.read(buf, length)).decode("utf-16le", errors="ignore")
        except Exception:
            return ""

    @winsdkapi(cc=STDCALL, params={'SectionHandle': POINTER, 'DesiredAccess': DWORD, 'ObjectAttributes': POINTER})
    def hook_ZwOpenSection(ql_, address, params):
        handle = Handle(name=_object_name(ql_, params['ObjectAttributes']))
        ql_.os.handle_manager.append(handle)
        ql_.mem.write_ptr(params['SectionHandle'], handle.id)
        return STATUS_SUCCESS

    @winsdkapi(cc=STDCALL, params={
        'FileHandle': POINTER, 'DesiredAccess': DWORD, 'ObjectAttributes': POINTER,
        'IoStatusBlock': POINTER, 'ShareAccess': DWORD, 'OpenOptions': DWORD,
    })
    def hook_ZwOpenFile(ql_, address, params):
        # Stessa idea di ZwOpenSection: si registra un handle che PORTA IL NOME dell'oggetto,
        # cosi' ZwMapViewOfSection piu' sotto sa quale immagine gia' caricata deve copiare.
        handle = Handle(name=_object_name(ql_, params['ObjectAttributes']))
        ql_.os.handle_manager.append(handle)
        ql_.mem.write_ptr(params['FileHandle'], handle.id)
        log.debug(f"  [DEBUG] ZwOpenFile -> {handle.name!r}")
        return STATUS_SUCCESS

    @winsdkapi(cc=STDCALL, params={
        'SectionHandle': POINTER, 'DesiredAccess': DWORD, 'ObjectAttributes': POINTER,
        'MaximumSize': POINTER, 'SectionPageProtection': DWORD, 'AllocationAttributes': DWORD,
        'FileHandle': HANDLE,
    })
    def hook_ZwCreateSection(ql_, address, params):
        # Propaga il nome dal file handle alla sezione: e' quel nome che ZwMapViewOfSection usa
        # per ritrovare l'immagine. Senza, la sezione sarebbe anonima e la vista verrebbe mappata
        # a zeri.
        src = ql_.os.handle_manager.get(params['FileHandle'])
        handle = Handle(name=(src.name if src else ""))
        ql_.os.handle_manager.append(handle)
        ql_.mem.write_ptr(params['SectionHandle'], handle.id)
        return STATUS_SUCCESS

    @winsdkapi(cc=STDCALL, params={
        'SectionHandle': HANDLE, 'ProcessHandle': HANDLE, 'BaseAddress': POINTER, 'ZeroBits': POINTER,
        'CommitSize': POINTER, 'SectionOffset': POINTER, 'ViewSize': POINTER,
        'InheritDisposition': DWORD, 'AllocationType': DWORD, 'Win32Protect': DWORD,
    })
    def hook_ZwMapViewOfSection(ql_, address, params):
        # Sezione "\KnownDlls\ntdll.dll" & co.: si mappa una COPIA dell'immagine gia' caricata
        # (stesso contenuto, relocata alla base originale: basta per parsare export/syscall stub).
        handle = ql_.os.handle_manager.get(params['SectionHandle'])
        dll_name = os.path.basename((handle.name or "").replace("\\", "/")).lower() if handle else ""
        image = next((i for i in ql_.loader.images if os.path.basename(i.path).lower() == dll_name), None) if dll_name else None

        requested = ql_.mem.read_ptr(params['ViewSize']) if params['ViewSize'] else 0
        size = (image.end - image.base) if image else (requested or 0x10000)
        view = ql_.mem.map_anywhere(size)
        if image:
            ql_.mem.write(view, bytes(ql_.mem.read(image.base, size)))

        ql_.mem.write_ptr(params['BaseAddress'], view)
        if params['ViewSize']:
            ql_.mem.write_ptr(params['ViewSize'], size)
        return STATUS_SUCCESS

    @winsdkapi(cc=STDCALL, params={'ProcessHandle': HANDLE, 'BaseAddress': POINTER})
    def hook_ZwUnmapViewOfSection(ql_, address, params):
        return STATUS_SUCCESS   # la vista resta mappata: innocuo, e si evita di liberare memoria ancora referenziata

    @winsdkapi(cc=STDCALL, params={})
    def hook_IsDebuggerPresent(ql_, address, params):
        return 0        # FALSE: nessun debugger

    @winsdkapi(cc=STDCALL, params={'hProcess': HANDLE, 'pbDebuggerPresent': POINTER})
    def hook_CheckRemoteDebuggerPresent(ql_, address, params):
        if params['pbDebuggerPresent']:
            ql_.mem.write_ptr(params['pbDebuggerPresent'], 0, 4)   # BOOL = FALSE
        return 1        # TRUE: la chiamata e' riuscita, il risultato e' "no debugger"

    @winsdkapi(cc=STDCALL, params={'Ptr': POINTER})
    def hook_EncodePointer(ql_, address, params):
        return params['Ptr']    # encode/decode sono simmetrici: l'identita' e' semanticamente equivalente

    @winsdkapi(cc=STDCALL, params={'dwErrCode': DWORD})
    def hook_RestoreLastError(ql_, address, params):
        ql_.os.last_error = params['dwErrCode']

    for _names, _hook in (
        (("ZwOpenSection", "NtOpenSection"), hook_ZwOpenSection),
        # VMProtect non si difende dall'emulatore: apre un file, ne crea una sezione e la mappa.
        # Queste due non sono implementate in Qiling 1.4.11, quindi l'handle restava memoria di
        # stack non inizializzata (0x2020202020202020 = spazi ASCII), ZwClose rispondeva
        # STATUS_INVALID_HANDLE e lo stub si suicidava con FatalExit(0xdeadc0de) dopo 0,2 s,
        # senza aver mai decompresso il payload. Misurato il 1 ottobre 2026 su 5 campioni su 5.
        (("ZwOpenFile", "NtOpenFile"), hook_ZwOpenFile),
        (("ZwCreateSection", "NtCreateSection"), hook_ZwCreateSection),
        (("ZwMapViewOfSection", "NtMapViewOfSection"), hook_ZwMapViewOfSection),
        (("ZwUnmapViewOfSection", "NtUnmapViewOfSection"), hook_ZwUnmapViewOfSection),
        (("EncodePointer", "DecodePointer", "RtlEncodePointer", "RtlDecodePointer",
          "EncodeSystemPointer", "DecodeSystemPointer", "RtlEncodeSystemPointer", "RtlDecodeSystemPointer"),
         hook_EncodePointer),
        (("RestoreLastError", "RtlRestoreLastWin32Error"), hook_RestoreLastError),
        # Anti-debug: Qiling ha gia' implementazioni native che rispondono "nessun debugger",
        # ma i vecchi hook del progetto erano funzioni NUDE passate a set_api(CALL) - su Windows
        # Qiling le chiama come handler(ql, address, api_name), ignora il ritorno e non ripulisce
        # lo stack: erano no-op che per di piu' sostituivano le native. Questi sono decorati con
        # @winsdkapi, quindi sono hook veri.
        (("IsDebuggerPresent",), hook_IsDebuggerPresent),
        (("CheckRemoteDebuggerPresent",), hook_CheckRemoteDebuggerPresent),
    ):
        for _name in _names:
            ql.os.set_api(_name, _hook, QL_INTERCEPT.CALL)


def _localize_qiling_code_hooks(ql, img_lo, img_hi):
    """
    Porta lo stub del packer a velocita' nativa togliendo i hook per-istruzione GLOBALI di Qiling.

    Su Windows Qiling registra due hook di codice senza range (begin=1, end=0): lo scheduler dei thread
    (QlWindowsThreadManagement.__thread_scheduler) e QlOsWindows.hook_winapi. Qiling li aggancia a UN
    solo hook Unicorn il cui dispatcher e' Python: OGNI istruzione emulata, anche i milioni di istruzioni
    della decompressione dello stub, paga una callback Python (misurato: ~220.000 istruzioni/s, ~15 KB/s
    di output su uno stub Themida). Entrambi servono solo fuori dall'immagine principale (gli export
    delle DLL, l'heap, lo stack dei thread), quindi si sostituiscono con UN hook Unicorn raw limitato ai
    range esterni a [img_lo, img_hi], che li chiama nello stesso ordine e con la stessa semantica di
    blocco (QL_HOOK_BLOCK) del dispatcher originale.

    NB: sostituire SOLO hook_winapi lasciando lo scheduler globale non funziona (le API non venivano piu'
    intercettate e lo stub finiva in codice nativo di ntdll): vanno rimossi entrambi.
    Confronto misurato: 197d802c... primo HeapAlloc dopo ~45 s di emulazione -> ~0,4 s; stub .boot di
    ae8b3bae... fermo a EP+0xc6 per 600 s -> completato in pochi secondi.

    Limite: un thread che gira solo dentro l'immagine principale non viene piu' interrotto dallo scheduler.
    Ritorna True se gli hook sono stati sostituiti.
    """
    from qiling.core_hooks_types import HookRet

    global_hooks = [h for h in ql._hook.get(UC_HOOK_CODE, []) if h.end < h.begin]   # begin=1,end=0 = tutto lo spazio
    if not global_hooks:
        return False
    callbacks = [h.callback for h in global_hooks]
    for h in global_hooks:
        ql.hook_del(HookRet(ql, UC_HOOK_CODE, h))

    def _dispatch(uc_, address, size, user_data):
        try:
            for cb in callbacks:
                ret = cb(ql, address, size)
                if type(ret) is int and ret & QL_HOOK_BLOCK:
                    break
        except (KeyboardInterrupt, Exception) as ex:   # come hookcallback() di Qiling: ferma e rilancia da run()
            ql.stop()
            ql._internal_exception = ex

    for begin, end in ((1, img_lo - 1), (img_hi + 1, 0xFFFFFFFFFFFFFFFF)):
        if begin <= end:
            ql.uc.hook_add(UC_HOOK_CODE, _dispatch, None, begin, end)
    return True


def unpack_with_qiling(filepath, output_dir, is_windows, is_64bit):
    def bypass_rdtsc(ql, address, size):
        try:
            # Legge 2 byte all'indirizzo corrente
            buf = ql.mem.read(address, 2)
            # Controlla se l'istruzione è RDTSC (0x0F 0x31)
            if buf == b'\x0f\x31':
                # Falsa i registri di output del tempo (RAX e RDX) con valori fissi
                ql.arch.regs.rax = 0x1337
                ql.arch.regs.rdx = 0x0
                # Salta l'istruzione muovendo in avanti l'instruction pointer (RIP) di 2 byte
                ql.arch.regs.rip += 2
                log.debug(f"  [DEBUG] Neutralizzata istruzione RDTSC all'indirizzo {hex(address)}")
        except Exception as e:
                log_exception_full(log, "Errore in hook bypass_rdtsc", e, level="debug")

    """Tenta l'unpacking emulato tramite OS Sandbox di Qiling (64-bit) integrando difese Anti-VM/Debug."""
    filename = os.path.basename(filepath)
    unpacked_path = os.path.join(output_dir, f"{filename}_qiling_unpacked.bin")

    log.info(f"  [>] Tentativo 2b: Qiling Framework (x64 64-bit) su {filename}...")

    if is_windows and is_64bit:
        rootfs = QILING_ROOTFS_WIN64
    elif not is_windows and is_64bit:
        rootfs = QILING_ROOTFS_LINUX64
    else:
        log.debug("  [-] Qiling saltato: configurazione rootfs/architettura non corrispondente.")
        return None

    if not os.path.exists(rootfs):
        log.error(f"  [!] Cartella rootfs mancante in {rootfs}.")
        return None

    # Un dump di memoria prodotto da un round precedente (_lief_fixed.exe) non e' ri-emulabile: la sua
    # import directory e' quella dello stub (nel dump e' distrutta/non parsabile -> Qiling muore con
    # "'PE' object has no attribute 'DIRECTORY_ENTRY_IMPORT'" dopo ~60 s di caricamento rootfs), l'IAT
    # contiene indirizzi dell'emulazione precedente e l'entry point cade in mezzo al codice del layer.
    # I layer successivi sono gia' catturati in UNA emulazione (QILING_MAX_LAYERS): non si ripete.
    if filename.endswith(("_lief_fixed.exe", "_qiling_unpacked.bin")):
        log.info(f"  [-] Qiling saltato: {filename} e' un dump di memoria di un round precedente (non ri-emulabile).")
        return None

    # FIX: le DLL non vanno emulate come se fossero EXE (l'entry point e' DllMain
    # e richiede hinstDLL/reason/reserved): nel batch reale ogni DLL bruciava
    # 30-60s di caricamento rootfs per poi fallire con UC_ERR_*.
    # Un dump rimasto da una run precedente fallita verrebbe scambiato per un successo di QUESTA run.
    for _stale in (unpacked_path, unpacked_path + ".meta"):
        if os.path.exists(_stale):
            try:
                os.remove(_stale)
            except OSError:
                pass

    ep_range = None
    if is_windows:
        try:
            _is_dll, ep_range = _pe_info(filepath)
            if _is_dll:
                log.info(f"  [-] Qiling saltato: {filename} e' una DLL (emulazione EXE non applicabile).")
                return None
        except Exception as e:
            log_exception_full(log, "Impossibile leggere l'header PE per Qiling", e, level="debug")

    # ==========================================
    # EURISTICA OEP: "WRITE-THEN-EXECUTE"
    # ==========================================
    # LA VERSIONE PRECEDENTE dichiarava "OEP trovato" alla PRIMA istruzione
    # eseguita al di fuori dei confini del modulo principale (images[0]).
    # Questo trigger scatta quasi sempre troppo presto: qualunque chiamata
    # a una API di sistema (kernel32, ntdll, ...) punta a un indirizzo fuori
    # da images[0] fin dalla primissima istruzione del loader/stub, ben
    # prima che il payload sia stato effettivamente decompresso. Il dump
    # risultante non era quasi mai codice valido -> Ghidra trovava 0
    # funzioni -> la pipeline finiva sempre e comunque su IDA, indipenden-
    # temente da quanto fosse "semplice" il packer.
    #
    # La tecnica standard (usata da unpacker generici come Universal PE
    # Unpacker / OllyBonE) e' invece "write-then-execute": un packer, per
    # definizione, DEVE scrivere il payload decompresso in memoria prima di
    # poterci saltare dentro. Quindi: si tracciano le pagine scritte a
    # runtime dal processo stesso, e si considera OEP il primo indirizzo
    # ESEGUITO che ricade in una pagina PRECEDENTEMENTE SCRITTA (non nel
    # codice originale caricato dal loader, e non nelle DLL di sistema, che
    # normalmente non vengono riscritte dal processo).
    #
    # Due filtri aggiuntivi riducono ulteriormente i falsi positivi:
    # - warmup: si ignorano le prime istruzioni (setup runtime iniziale);
    # - soglia minima di byte scritti: un singolo patch di 4-8 byte (es.
    #   una fixup di rilocazione) non basta a far scattare il trigger,
    #   serve che sia stato scritto un payload di dimensioni plausibili.
    # RILEVAZIONE "WRITE-THEN-EXECUTE" SENZA HOOK DI SCRITTURA (fix di performance).
    # Il batch ha mostrato che anche il solo hook_mem_write (una callback Python per OGNI byte scritto
    # dalla decompressione) porta `awk` a >3 minuti con ~1M scritture ancora a layer 0: il costo per
    # callback di Qiling e' di ordini di grandezza sopra quello nativo. Ora non si osservano piu' le
    # scritture: si tiene uno SNAPSHOT dell'immagine e un blocco e' un "salto in codice scritto a
    # runtime" se i suoi byte DIFFERISCONO dallo snapshot (e almeno QILING_MIN_CHANGED_PAGES pagine
    # sono cambiate). Lo snapshot iniziale e' l'immagine appena caricata; a ogni layer diventa il dump.
    # Nel layer 0 non gira NESSUNA callback Python (velocita' nativa di Unicorn).
    #
    # MULTI-LAYER IN UNA SOLA EMULAZIONE: a ogni transizione si fa il dump, lo snapshot viene
    # aggiornato (lo stub del layer corrente, gia' nello snapshot, non e' piu' una transizione) e si
    # prosegue. Si ferma quando l'immagine non cambia piu' per QILING_POST_LAYER_SECONDS, al
    # timeout/cap o a QILING_MAX_LAYERS. Il file salvato e' l'ULTIMO layer.
    state_counters = {
        "blocks": 0, "image_base": None, "image_size": None, "snap": None,
        "ok_blocks": set(),      # indirizzi di blocchi gia' verificati uguali allo snapshot (fast path)
        "ep_range": ep_range,    # (lo, hi) RVA della sezione dello stub del layer 0
        "layer": 0, "layer_oeps": [],
        "deadline": None, "last_poll": 0.0, "last_changed_pages": 0, "last_failed_eval": 0.0,
        "failed_addrs": set(), "failed_evals": 0,   # candidati scartati (poche pagine modificate)
        "t0": time.monotonic(),
    }

    def read_image_bytes(ql):
        base, size = state_counters["image_base"], state_counters["image_size"]
        out = bytearray()
        failed = 0
        for offset in range(0, size, 0x1000):
            try:
                out += ql.mem.read(base + offset, 0x1000)
            except Exception:
                failed += 1
                out += b'\x00' * 0x1000
        return bytes(out[:size]), failed

    def count_changed_pages(cur, snap):
        return sum(1 for off in range(0, len(cur), 0x1000) if cur[off:off + 0x1000] != snap[off:off + 0x1000])

    def dump_image(ql, address, data, failed_pages):
        """Salva l'immagine (sovrascrive il layer precedente) + metadati."""
        if failed_pages:
            log.warning(f"  [!] {failed_pages} pagine non leggibili durante il dump "
                        f"(riempite a zero) - il file ricostruito potrebbe avere buchi.")
        with open(unpacked_path, "wb") as f:
            f.write(data)
        with open(unpacked_path + ".meta", "w") as mf:
            mf.write(f"load_address=0x{address:x}\n")
            mf.write(f"image_base=0x{state_counters['image_base']:x}\n")
            mf.write(f"layers={state_counters['layer']}\n")
            mf.write(f"layer_oeps={','.join(hex(a) for a in state_counters['layer_oeps'])}\n")
            mf.write(f"is_windows={is_windows}\n")
            mf.write(f"is_64bit={is_64bit}\n")

    def poll_progress(ql):
        """Dopo almeno un layer: se l'immagine non cambia piu' da QILING_POST_LAYER_SECONDS il payload
        sta girando -> stop. Ritorna True se ha fermato l'emulazione."""
        st = state_counters
        now = time.monotonic()
        if now - st["last_poll"] < QILING_POLL_SEC:
            return False
        st["last_poll"] = now
        cur, _ = read_image_bytes(ql)
        pages = count_changed_pages(cur, st["snap"])
        if pages - st["last_changed_pages"] >= 4:       # sta ancora scrivendo (decompressione in corso)
            st["last_changed_pages"] = pages
            st["deadline"] = now + QILING_POST_LAYER_SECONDS
        elif st["deadline"] is not None and now > st["deadline"]:
            log.debug(f"  [DEBUG] Immagine invariata da {QILING_POST_LAYER_SECONDS}s: "
                      f"stop (layer registrati: {st['layer']}).")
            ql.stop()
            return True
        return False

    def check_block(address):
        """Logica per ogni blocco agganciato (solo FUORI dallo stub del layer 0)."""
        st = state_counters
        st["blocks"] += 1
        if st["blocks"] < QILING_OEP_WARMUP_BLOCKS:
            return          # warmup: l'avvio del runtime non e' un salto nel payload
        try:
            if st["layer"] > 0 and (st["blocks"] & 0x3FFF) == 0:
                if poll_progress(ql):
                    return
            if address in st["ok_blocks"]:
                return  # fast path: blocco gia' visto uguale allo snapshot (es. loop dello stub)

            rel = address - st["image_base"]
            if not (0 <= rel < st["image_size"] - 16):
                return
            probe = bytes(ql.mem.read(address, 16))
            if probe == st["snap"][rel:rel + 16]:
                st["ok_blocks"].add(address)
                return
            if probe == b'\x00' * 16:
                return  # byte tutti a zero: dato riservato, non payload

            # Candidato: il codice a `address` e' diverso da quando e' stato caricato/snapshottato.
            # Throttle PER INDIRIZZO (non a tempo): un candidato scartato non deve mascherare la vera
            # transizione che arriva subito dopo (altro indirizzo). Dopo 50 scarti si passa a 1 s.
            if address in st["failed_addrs"]:
                return
            now = time.monotonic()
            if st["failed_evals"] >= 50 and now - st["last_failed_eval"] < 1.0:
                return
            cur, failed = read_image_bytes(ql)
            changed = count_changed_pages(cur, st["snap"])
            if changed < QILING_MIN_CHANGED_PAGES:
                st["failed_addrs"].add(address)   # es. singola patch/thunk dello stub: non e' un layer
                st["failed_evals"] += 1
                st["last_failed_eval"] = now
                if st["failed_evals"] <= 10:
                    log.debug(f"  [CAND] candidato a {hex(address)} (rva={hex(rel)}) scartato: "
                              f"pagine modificate={changed} < {QILING_MIN_CHANGED_PAGES}.")
                return

            # ---- nuova transizione write->execute = nuovo layer ----
            st["layer"] += 1
            st["layer_oeps"].append(address)
            try:
                dump_image(ql, address, cur, failed)
            except OSError as e:
                # Senza questo rollback lo stato restava invariato e lo STESSO blocco si riattivava a ogni
                # istruzione: decine di migliaia di "layer" fasulli, log da decine di MB e un falso successo.
                st["layer"] -= 1
                st["layer_oeps"].pop()
                st["failed_addrs"].add(address)
                log_exception_full(log, f"Dump del layer a {hex(address)} non riuscito (layer non conteggiato)", e, level="error")
                return
            log.info(f"  [+] Layer {st['layer']} (Qiling): salto in codice scritto a runtime, "
                     f"entry={hex(address)} (rva={hex(rel)}, pagine modificate={changed}, "
                     f"t={now - st['t0']:.0f}s).")

            st["snap"] = cur                       # lo stub del layer corrente non e' piu' una transizione
            st["ok_blocks"] = set()
            st["failed_addrs"] = set()
            st["failed_evals"] = 0
            st["last_changed_pages"] = 0
            st["last_poll"] = now
            st["deadline"] = now + QILING_POST_LAYER_SECONDS

            if st["layer"] >= QILING_MAX_LAYERS:
                log.debug(f"  [DEBUG] Raggiunto QILING_MAX_LAYERS={QILING_MAX_LAYERS}: stop.")
                ql.stop()
        except Exception as e:
            log_exception_full(log, "Errore nel rilevamento layer/dump", e, level="error")

    temp_target_dir = os.path.join(rootfs, "Windows", "Temp")
    os.makedirs(temp_target_dir, exist_ok=True)
    temp_filepath = os.path.join(temp_target_dir, filename)

    try:
        shutil.copy2(filepath, temp_filepath)

        # QL_VERBOSE.DISABLED e non DEFAULT: con DEFAULT, Qiling scrive su stdout una riga per
        # ogni chiamata API emulata. Misurato il 1 ottobre 2026: 203 MB di log per 13 campioni,
        # con uno stub finito in un ciclo di ZwEnumerateKey - abbastanza da riempire il disco e
        # far fallire la run con "No space left on device". La diagnostica che usiamo davvero
        # (ring buffer api_trace, riga [END], tool_diagnostics.jsonl) e' nostra e resta.
        ql = Qiling([temp_filepath], rootfs=rootfs, verbose=QL_VERBOSE.DISABLED, console=False)

        # Auto-mapping della memoria non mappata: invece di UC_ERR_*_UNMAPPED si mappano 0x2000 byte
        # (a zeri) attorno all'indirizzo e si riprova l'accesso.
        def _auto_map_unmapped(ql_, access, address, size, value):
            try:
                base_addr = address & ~0xFFF
                ql_.mem.map(base_addr, 0x2000)
                log.debug(f"  [DEBUG] Memoria non mappata: mappati 0x2000 byte a {hex(base_addr)} "
                          f"(accesso={access}, indirizzo={hex(address)}, size={size}, pc={hex(ql_.arch.regs.arch_pc)}).")
                return True
            except Exception as e:
                log.debug(f"  [DEBUG] Auto-mapping fallito a {hex(address)}: {e!r}")
                return False

        ql.hook_mem_unmapped(_auto_map_unmapped)
        # NOTA (fix): la riga rimossa qui sotto -
        #   ql.os.path._rootfs_path = pathlib.Path(rootfs).resolve()
        # - sovrascriveva un attributo interno/privato di Qiling con un path
        # assoluto, rompendo la risoluzione relativa dei path delle DLL di
        # sistema (kernel32, comctl32, bcrypt, ecc.) e causando l'eccezione
        # "'...\\System32\\XXX.dll' is not in the subpath of '.'" ad ogni
        # round 2+ della cascata multilayer sui campioni a 64-bit. Qiling
        # gestisce gia' correttamente la rootfs internamente tramite il
        # parametro rootfs=rootfs passato al costruttore: non serve alcun
        # intervento manuale su ql.os.path.

        # Popola la bitmap byte-per-byte per il tracciamento write-then-
        # execute, ora che ql.loader.images e' disponibile (non lo era
        # quando le funzioni interne sono state definite sopra).
        _main_image = ql.loader.images[0]
        state_counters["image_base"] = _main_image.base
        state_counters["image_size"] = _main_image.end - _main_image.base
        state_counters["snap"], _ = read_image_bytes(ql)   # snapshot dell'immagine appena caricata

        # ==========================================
        # API WINDOWS MANCANTI IN QILING
        # ==========================================
        # FIX: i vecchi hook IsDebuggerPresent/CheckRemoteDebuggerPresent erano funzioni "nude" passate a
        # set_api(CALL): su Windows Qiling le chiama come handler(ql, address, api_name) SENZA usare il
        # ritorno ne' ripulire lo stack, e in piu' sostituivano le implementazioni native di Qiling (che
        # gia' rispondono "nessun debugger"). Erano quindi solo dannosi: rimossi.
        if is_windows:
            try:
                _install_qiling_compat_hooks(ql)
            except Exception as e:
                log_exception_full(log, "Hook di compatibilita' Qiling non applicabili", e, level="warning")

        # ==========================================
        # 🛡️ HOOK ANTI-VIRTUAL MACHINE (Timing)
        # ==========================================
        # PERFORMANCE: nessun hook dentro la sezione dello stub del layer 0 (li' girano decine di milioni
        # di istruzioni di decompressione) e nessun hook di scrittura. Gli hook a blocchi sono solo sui
        # range dell'immagine FUORI dallo stub.
        _img_lo = state_counters["image_base"]
        _img_hi = _img_lo + state_counters["image_size"] - 1
        if is_windows:
            try:
                if _localize_qiling_code_hooks(ql, _img_lo, _img_hi):
                    log.debug("  [DEBUG] Hook globali di Qiling (scheduler + API) limitati ai range fuori dall'immagine principale.")
                else:
                    log.warning("  [!] Nessun hook globale di Qiling da localizzare: lo stub potrebbe girare lentamente.")
            except Exception as e:
                log_exception_full(log, "Impossibile localizzare gli hook globali di Qiling", e, level="warning")
        hook_ranges = []
        if ep_range:
            _stub_lo = _img_lo + ep_range[0]
            _stub_hi = _img_lo + ep_range[1]
            if _stub_lo > _img_lo:
                hook_ranges.append((_img_lo, _stub_lo - 1))
            if _stub_hi <= _img_hi:
                hook_ranges.append((_stub_hi, _img_hi))
        else:
            hook_ranges.append((_img_lo, _img_hi))

        registered_raw = False
        if not hook_ranges:
            # Nessun range fuori dallo stub (lo stub copre tutta l'immagine): senza hook non si aggancia
            # nessun blocco e il layer non puo' mai essere rilevato ("blocchi agganciati=0").
            hook_ranges.append((_img_lo, _img_hi))
            log.debug(f"  [DEBUG] hook_ranges vuoto: fallback sull'intera immagine ({hex(_img_lo)}-{hex(_img_hi)}).")
        if QILING_USE_RAW_UC_HOOKS:
            try:
                _uc = getattr(ql, "uc", None) or ql.arch.uc

                def raw_block_cb(uc_, address, size, user_data):
                    check_block(address)

                for _b, _e in hook_ranges:
                    _uc.hook_add(UC_HOOK_BLOCK, raw_block_cb, None, _b, _e)
                registered_raw = True
            except Exception as e:
                log_exception_full(log, "Hook raw Unicorn non applicabile, uso hook_block di Qiling", e, level="debug")
        if not registered_raw:
            for _b, _e in hook_ranges:
                ql.hook_block(lambda ql_, address, size: check_block(address), begin=_b, end=_e)
        if QILING_RDTSC_BYPASS:
            for _b, _e in hook_ranges:
                ql.hook_code(bypass_rdtsc, begin=_b, end=_e)

        log.info(f"  [+] Hook a blocchi ({'raw Unicorn' if registered_raw else 'Qiling'}) su {len(hook_ranges)} range "
                 f"fuori dallo stub{' + RDTSC bypass' if QILING_RDTSC_BYPASS else ''}; nessun hook di scrittura "
                 f"(stub layer 0: {'rva ' + hex(ep_range[0]) + '-' + hex(ep_range[1]) if ep_range else 'sconosciuto'}).")

        # Ring buffer delle ultime chiamate API (hook ENTER: non alterano il comportamento).
        api_trace = collections.deque(maxlen=40)

        def _make_api_logger(api_name):
            def _cb(ql_, address, params):
                try:
                    args = ", ".join(f"{k}={v:#x}" if isinstance(v, int) else f"{k}={v!r}"
                                     for k, v in list(params.items())[:4])
                except Exception:
                    args = "?"
                api_trace.append(f"[{time.monotonic() - state_counters['t0']:.1f}s L{state_counters['layer']}] "
                                 f"{api_name}({args[:110]})")
            return _cb

        if is_windows:
            for _api in QILING_TRACE_APIS:
                try:
                    ql.os.set_api(_api, _make_api_logger(_api), QL_INTERCEPT.ENTER)
                except Exception:
                    pass

        # Il layer 0 non ha callback Python: un thread di heartbeat evita che il log resti muto.
        _hb_stop = threading.Event()

        def _heartbeat():
            while not _hb_stop.wait(QILING_HEARTBEAT_SEC):
                log.debug(f"  [HEARTBEAT] {time.monotonic() - state_counters['t0']:.0f}s "
                          f"layer={state_counters['layer']} blocchi_agganciati={state_counters['blocks']}")

        threading.Thread(target=_heartbeat, daemon=True).start()
        state_counters["t0"] = time.monotonic()
        try:
            ql.run(count=QILING_MAX_INSTRUCTIONS, timeout=QILING_EMU_TIMEOUT_SEC * 1_000_000)  # timeout in microsecondi
        except Exception as run_err:
            # Un'API non implementata da Qiling (es. advapi32.CheckTokenMembership -> NotImplementedError ->
            # QlErrorSyscallError) o un crash dopo che il payload ha gia' girato non deve buttare i layer gia'
            # dumpati: l'ultimo dump su disco e' il risultato. Senza layer registrati l'errore resta un fallimento.
            # NB: niente repr() dell'eccezione: con il contesto ciclico di QlErrorSyscallError solleva RecursionError.
            _cause = type(run_err.__context__).__name__ if run_err.__context__ else "-"
            if state_counters["layer"] >= 1 and os.path.exists(unpacked_path):
                log.warning(f"  [!] Emulazione interrotta da {type(run_err).__name__} (causa: {_cause}) dopo "
                            f"{state_counters['layer']} layer registrati: si usa l'ultimo dump.")
            else:
                # Qui prima si RILANCIAVA l'eccezione. Ma e' esattamente il caso dei VMProtect:
                # l'emulazione muore senza aver registrato nessuna transizione, il controllo
                # saltava direttamente all'except esterno, e il dump di ripiego a fine emulazione
                # - che sta subito sotto - non veniva MAI raggiunto. Misurato il 1 ottobre 2026:
                # 5 VMProtect su 5, zero dump di ripiego tentati. Ora si logga e si prosegue: se
                # il payload in memoria c'e', il ripiego lo salva comunque.
                log_exception_full(log, f"Emulazione interrotta senza layer registrati (causa: {_cause})",
                                   run_err)
        finally:
            _hb_stop.set()
            try:
                _pc = ql.arch.regs.arch_pc
                _rel = _pc - state_counters["image_base"]
                _where = f"rva={hex(_rel)}" if 0 <= _rel < state_counters["image_size"] else "FUORI dall'immagine"
                log.debug(f"  [END] pc={hex(_pc)} ({_where}); ultime API: "
                          f"{' | '.join(list(api_trace)[-15:]) if api_trace else 'nessuna tra quelle tracciate'}")
            except Exception as e:
                log.debug(f"  [END] diagnostica finale non disponibile: {e!r}")
        log.debug(f"  [DEBUG] Emulazione terminata in {time.monotonic() - state_counters['t0']:.0f}s: "
                  f"layer registrati={state_counters['layer']}, blocchi agganciati={state_counters['blocks']}.")

        if not os.path.exists(unpacked_path):
            # Distingue DUE cause diverse di "OEP non trovato", per capire se
            # il problema e' il filtro dell'euristica o il tempo/istruzioni
            # a disposizione: il conteggio istruzioni della pipeline
            # (state_counters) e' indipendente dal contatore interno di
            # Qiling, quindi se e' molto vicino al limite di 50 milioni e'
            # probabile che l'emulazione sia stata troncata prima di
            # arrivare al vero OEP, non che l'euristica l'abbia scartato.
            log.debug(f"  [DEBUG] Nessun layer rilevato: blocchi agganciati={state_counters['blocks']} "
                      f"(cap: {QILING_MAX_INSTRUCTIONS or 'nessun tetto'} istruzioni / {QILING_EMU_TIMEOUT_SEC}s; vedi [HEARTBEAT]).")

            # DUMP DI RIPIEGO A FINE EMULAZIONE.
            # L'euristica scrivi-poi-esegui vede solo le transizioni che passano per un blocco
            # agganciato: se lo stub decomprime il payload ma non ci salta dentro entro il tempo
            # concesso (o ci salta da un indirizzo fuori dai range con hook), non si registra
            # nessun layer e il dump non viene mai scritto - anche quando in memoria il payload
            # c'e'. Qui si guarda l'immagine UNA VOLTA alla fine: se e' cambiata quanto basta la
            # si salva comunque, usando come OEP il pc finale.
            # Richiede che il pc sia DENTRO l'immagine: rebuild_pe_offline_with_lief calcola
            # AddressOfEntryPoint = oep - base, quindi un pc fuori darebbe un header invalido.
            try:
                _cur, _failed = read_image_bytes(ql)
                _changed = count_changed_pages(_cur, state_counters["snap"])
                _pc = ql.arch.regs.arch_pc
                _rel = _pc - state_counters["image_base"]
                _inside = 0 <= _rel < state_counters["image_size"]
                if _changed >= QILING_MIN_CHANGED_PAGES and _inside:
                    state_counters["layer"] = 1
                    state_counters["layer_oeps"].append(_pc)
                    dump_image(ql, _pc, _cur, _failed)
                    log.info(f"  [+] Dump di ripiego a fine emulazione: nessuna transizione "
                             f"rilevata, ma l'immagine e' cambiata di {_changed} pagine. "
                             f"OEP = pc finale {hex(_pc)} (rva={hex(_rel)}).")
                else:
                    log.debug(f"  [DEBUG] Nessun dump di ripiego: pagine modificate={_changed} "
                              f"(soglia {QILING_MIN_CHANGED_PAGES}), pc "
                              f"{'dentro' if _inside else 'FUORI'} dall'immagine.")
            except Exception as e:
                log_exception_full(log, "Dump di ripiego non riuscito", e, level="debug")

        if os.path.exists(unpacked_path) and os.path.getsize(unpacked_path) > 0:
            log.info(f"  [+] Qiling ha avuto successo! ({state_counters['layer']} layer registrati; dump dell'ultimo)")
            
            # Leggi i metadati salvati dal dumper
            meta_path = unpacked_path + ".meta"
            oep_address = 0
            real_base = None
            if os.path.exists(meta_path):
                with open(meta_path, "r") as mf:
                    for line in mf:
                        if line.startswith("load_address="):
                            oep_address = int(line.strip().split("=")[1], 16)
                        elif line.startswith("image_base="):
                            real_base = int(line.strip().split("=")[1], 16)

            if not oep_address:
                # Senza OEP l'header non e' ricostruibile (AddressOfEntryPoint = oep - base darebbe un
                # valore negativo e pefile fallirebbe con "'I' format requires 0 <= number ...").
                log.warning(f"  [-] Metadati del dump mancanti o incompleti ({os.path.basename(meta_path)}): "
                            "OEP sconosciuto, ricostruzione PE impossibile. Scarto il dump.")
                return None

            # Ricostruzione PE (pefile, patch in place). None = dump invalido (sezioni vuote).
            fixed_unpacked_path = rebuild_pe_offline_with_lief(unpacked_path, oep_address, is_windows, real_base)
            if fixed_unpacked_path is None:
                return None
            return fixed_unpacked_path
        else:
            log.debug("  [-] Qiling ha concluso l'emulazione senza individuare un salto OEP.")

    except Exception as e:
        # FIX: logging esteso ora centralizzato in pipeline_utils.py
        # (log_exception_full) invece che duplicato qui inline. Prima si
        # loggava solo str(e), inutile/fuorviante per molte eccezioni
        # Unicorn/Qiling (es. "UC_ERR_ARG" non dice quale chiamata l'ha
        # generato; certe UcError hanno come str() un codice numerico
        # grezzo come "380", senza contesto). La funzione condivisa logga
        # sempre tipo eccezione + messaggio a WARNING e il traceback
        # completo a DEBUG.
        log_exception_full(log, "Eccezione Qiling", e)

    finally:
        if os.path.exists(temp_filepath):
            try:
                os.remove(temp_filepath)
            except OSError:
                pass

    return None


def parse_ghidra_func_count(report_path):
    """Legge il report di basic_info_report.py ed estrae il numero di funzioni."""
    if not report_path or not os.path.exists(report_path):
        return None
    try:
        with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith("Numero funzioni identificate:"):
                    return int(line.split(":", 1)[1].strip())
    except (ValueError, OSError):
        pass
    return None


def analyze_with_ghidra_headless(filepath, is_windows=True, is_64bit=True):
    """VERIFICA AUTOMATICA (batch, headless, zero click) del file scompattato."""
    filepath = os.path.normpath(filepath)
    filename = os.path.basename(filepath)

    os.makedirs(GHIDRA_PROJECTS_DIR, exist_ok=True)

    report_path = os.path.join(
        os.path.dirname(filepath),
        os.path.splitext(filename)[0] + "_ghidra_report.txt"
    )

    command = [GHIDRA_HEADLESS_PATH, GHIDRA_PROJECTS_DIR, GHIDRA_PROJECT_NAME, "-import", filepath]

    # Se la ricostruzione LIEF è fallita ed è rimasto un binario grezzo
    is_raw_dump = filepath.endswith("_qiling_unpacked.bin")
    if is_raw_dump:
        processor = "x86:LE:64:default" if is_64bit else "x86:LE:32:default"
        load_addr = "0x0"

        meta_path = filepath + ".meta"
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r") as mf:
                    for line in mf:
                        # FIX: BinaryLoader vuole la BASE dell'immagine, non l'OEP
                        # (load_address = OEP nel .meta). Si preferisce image_base.
                        if line.startswith("image_base="):
                            load_addr = line.strip().split("=", 1)[1]
                        elif line.startswith("load_address=") and load_addr == "0x0":
                            load_addr = line.strip().split("=", 1)[1]
            except OSError:
                pass

        command += ["-processor", processor, "-loader", "BinaryLoader", "-loader-baseAddr", load_addr]
        log.debug(f"Import come Raw Binary: processor={processor} baseAddr={load_addr}")

    # FIX (VM): alzati da 240/120 a 600/480. In VM (CPU/IO condivisi con
    # l'host) l'auto-analisi di Ghidra su binari medio-grandi puo' superare
    # comodamente i 120s di prima, facendo scattare -analysisTimeoutPerFile
    # PRIMA che l'analisi sia completa (report parziale o mai scritto) o
    # facendo scattare il timeout Python (240s) mentre Ghidra sta ancora
    # lavorando legittimamente. Il timeout esterno (subprocess.run) resta
    # sempre un margine abbondante sopra -analysisTimeoutPerFile, per dare
    # tempo al postScript di girare dopo la fine dell'auto-analisi.
    GHIDRA_ANALYSIS_TIMEOUT_PER_FILE = 480  # secondi, limite auto-analisi Ghidra per singolo file
    GHIDRA_TIMEOUT = 600  # secondi, timeout del subprocess Python (margine sopra il valore qui sopra)

    command += [
        "-scriptPath", GHIDRA_SCRIPTS_DIR,
        "-postScript", "basic_info_report.py", report_path,
        "-analysisTimeoutPerFile", str(GHIDRA_ANALYSIS_TIMEOUT_PER_FILE),
        "-deleteProject", "-overwrite",
    ]

    log.info(f"  [>] Verifica automatica con Ghidra su: {filename}...")

    # FIX (diagnostica): logghiamo sempre il comando esatto che stiamo per
    # lanciare. Serve per poterlo copiare e rilanciare a mano da cmd.exe se
    # il report non viene generato, per vedere l'errore reale di Ghidra
    # senza dover ripassare da Python.
    log.debug("  [DEBUG] Comando Ghidra: " + " ".join(f'"{c}"' if " " in c else c for c in command))

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=GHIDRA_TIMEOUT)

        if os.path.exists(report_path):
            log.info(f"  [+] Report Ghidra generato: {report_path}")
            return True, report_path
        else:
            # FIX (diagnostica): prima qui stdout/stderr venivano catturati
            # e MAI loggati, rendendo impossibile capire perche' il report
            # non veniva scritto (era il motivo per cui Ghidra falliva
            # sistematicamente su tutti i file e la pipeline finiva sempre
            # su IDA). Ora li scriviamo sempre nel file di log.
            log.warning("  [-] Ghidra ha terminato ma il report non e' stato generato.")
            log.warning(f"  [DEBUG] Ghidra return code: {result.returncode}")
            if result.stdout.strip():
                log.warning("  [DEBUG] Ghidra STDOUT (ultimi 3000 caratteri):\n" + result.stdout[-3000:])
            if result.stderr.strip():
                log.warning("  [DEBUG] Ghidra STDERR (ultimi 3000 caratteri):\n" + result.stderr[-3000:])
            log.debug(f"  [DEBUG] Report atteso in: {report_path} (lunghezza path: {len(report_path)} caratteri)")
            if len(report_path) > 240:
                log.warning(
                    f"  [!] ATTENZIONE: il path del report e' lungo {len(report_path)} caratteri, "
                    "vicino/oltre il limite MAX_PATH di Windows (260). Possibile causa del fallimento: "
                    "abilita i long path in Windows o accorcia i nomi dei file scompattati."
                )
            return False, None

    except subprocess.TimeoutExpired as e:
        log.warning(f"  [!] Timeout: Ghidra ha superato i {GHIDRA_TIMEOUT} secondi su questo file.")
        # Anche in timeout, subprocess.run con capture_output puo' aver
        # raccolto output parziale utile alla diagnosi.
        stdout_partial = (e.stdout or "")
        stderr_partial = (e.stderr or "")
        if stdout_partial.strip():
            log.warning("  [DEBUG] Ghidra STDOUT parziale (timeout):\n" + stdout_partial[-3000:])
        if stderr_partial.strip():
            log.warning("  [DEBUG] Ghidra STDERR parziale (timeout):\n" + stderr_partial[-3000:])
        return False, None
    except FileNotFoundError:
        log.error(f"Errore: analyzeHeadless non trovato in {GHIDRA_HEADLESS_PATH}")
        return False, None
    except Exception as e:
        log_exception_full(log, "Eccezione Python in Ghidra", e)
        return False, None


def analyze_with_ida(filepath):
    """Lancia IDA Free nell'unico modo supportato: interfaccia grafica standard."""
    filepath = os.path.normpath(filepath)
    filename = os.path.basename(filepath)
    base_name = os.path.splitext(filepath)[0]

    command = [IDA_PATH, filepath]

    log.info(f"  [>] Apro l'interfaccia di IDA Free su: {filename}...")
    log.info("  [!] NOTA: IDA Free è in esecuzione. Lo script è IN PAUSA.")
    log.info("  [!] Analizza il malware e CHIUDI la finestra di IDA per far proseguire lo script.")

    try:
        process = subprocess.Popen(command)
        process.wait()

        log.info("  [+] Finestra di IDA chiusa dall'utente. Controllo file generati...")

        idb_path = base_name + ".idb"
        i64_path = base_name + ".i64"

        if os.path.exists(idb_path) or os.path.exists(i64_path):
            log.info("  [+] Database di IDA trovato nella cartella del binario.")
            return True
        else:
            log.warning("  [-] IDA è stato chiuso senza salvare il database (.i64/.idb).")
            return False

    except Exception as e:
        log.warning(f"  [!] Eccezione Python in IDA: {str(e)}")
        return False


def _build_and_save_summary(counters, target_dir):
    """Genera il report riepilogativo di fine batch (osservabilità): quanti
    file totali, e per ciascun metodo quanti successi/fallback, cosicché
    l'esito di una run intera sia leggibile in un colpo solo invece di
    dover rileggere tutto il log."""
    summary = dict(counters)
    summary["target_dir"] = target_dir

    try:
        with open(SUMMARY_REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
    except OSError as e:
        log.warning(f"Impossibile salvare il report riepilogativo: {e}")

    log.info("=" * 50)
    log.info("RIEPILOGO FASE 2")
    log.info(f"  File processati in questa run : {counters['processati']}")
    log.info(f"  Saltati (resume, già risolti)  : {counters['saltati_resume']}")
    log.info(f"  Risolti da UPX                 : {counters['upx']}")
    log.info(f"  Risolti da AspackDie           : {counters['aspackdie']}")
    log.info(f"  Risolti da InnoUnp             : {counters['innounp']}")
    log.info(f"  Risolti da 7-Zip               : {counters.get('sevenzip', 0)}")
    log.info(f"  Risolti da Unipacker           : {counters['unipacker']}")
    log.info(f"  Risolti da Qiling              : {counters['qiling']}")
    log.info(f"  Risolti da mal_unpack          : {counters['mal_unpack']}")
    log.info(f"  Verificati OK da Ghidra        : {counters['ghidra_ok']}")
    log.info(f"  Finiti su IDA (fallback)       : {counters['ida_fallback']}")
    log.info(f"  Fuori perimetro (non PE)       : {counters['fuori_perimetro']}")
    log.info(f"  File con packing multi-layer   : {counters['multilayer_rilevati']}")
    log.info(f"  Layer totali rimossi in cascata: {counters['layer_totali_rimossi']}")
    log.info(f"  Limite round multilayer raggiunto (possibili layer residui): {counters['limite_layer_raggiunto']}")
    log.info(f"  Report salvato in: {SUMMARY_REPORT_PATH}")
    log.info("=" * 50)


def looks_still_packed(filepath, is_windows):
    """
    Euristica LEGGERA e locale a Fase 2, usata solo per decidere se continuare
    il ciclo multilayer round dopo round. Non sostituisce lo scoring di Fase 1.

    Segnali controllati:
    - entropia massima di sezione >= soglia (payload ancora compresso/cifrato);
    - (solo PE) sezione con nome tipico di un packer (PACKER_SECTION_PREFIXES).

    FIX: rimossa la regola "raw_size 0 & virtual_size > 0": scattava sui normali
    .bss dei binari MinGW/GCC (b2sum dopo UPX: entropia 6.23 ma "ulteriore layer:
    SI"), innescando un round 2 inutile (AspackDie + InnoUnp + 30s di Qiling) e
    rischiando di sostituire un output buono con un dump.

    Ritorna (still_packed: bool, max_entropy: float).
    """
    try:
        binary = lief.parse(filepath)
        if not binary:
            return False, 0.0

        max_entropy = 0.0
        packer_section = False
        is_dump = os.path.basename(filepath).endswith(("_lief_fixed.exe", "_unipacker_unpacked.exe"))

        for section in binary.sections:
            entropy = section.entropy
            if entropy > max_entropy:
                max_entropy = entropy

            # Sui dump di memoria (_lief_fixed.exe) l'header e' quello dello STUB (nomi .MPRESS*/UPX*
            # anche a unpacking riuscito): il nome sezione non e' informativo, conta solo l'entropia.
            if is_windows and not is_dump:
                name = (section.name or "").strip("\x00").lower()
                if name.startswith(PACKER_SECTION_PREFIXES):
                    packer_section = True

        max_entropy = round(max_entropy, 2)
        still_packed = (max_entropy >= MULTILAYER_ENTROPY_THRESHOLD) or packer_section
        return still_packed, max_entropy

    except Exception as e:
        log.debug(f"  [i] Controllo multilayer: impossibile analizzare {os.path.basename(filepath)}: {e}")
        return False, 0.0


def unpack_cascade_multilayer(filepath, output_dir, is_windows, is_64bit, max_layers=MULTILAYER_MAX_LAYERS, die_hint=None):
    """
    Applica ripetutamente (fino a max_layers volte) la cascata di unpacking
    (UPX/AspackDie/InnoUnp -> Unipacker/Qiling a seconda dell'architettura)
    sullo STESSO campione, usando l'output di un round come input del round
    successivo. Serve a gestire i campioni con piu' layer di packing
    sovrapposti (es. UPX esterno + packer custom interno), dove un singolo
    passaggio lascia comunque il payload finale offuscato.

    die_hint (opzionale, SOLO al round 1): dict {"name", "type"} con quanto la
    Fase 1 ha gia' stabilito sul file (colonne Die_Packer_Name e
    Die_Packer_Type del CSV). Serve a due cose diverse:

    - il NOME decide se vale la pena chiamare AspackDie, che e' uno strumento
      grafico e su un file non-ASPack costa 8 s di timeout a vuoto;
    - il TIPO cambia la STRADA, non solo l'ordine. Un `installer`/`sfx` e' un
      contenitore: va aperto con un estrattore e non deve MAI finire
      nell'emulazione, che su di esso produce il codice dell'installer invece
      del payload - un risultato che Ghidra approva ed e' sbagliato.

    Non viene riusato ai round successivi: dopo che un layer e' stato rimosso,
    quanto calcolato sul file ORIGINALE non vale piu' per il layer sottostante.

    Il ciclo si ferma PRIMA di max_layers se:
    - nessun tool riesce a rimuovere un ulteriore layer nel round corrente
      (o il file era gia' pulito, o il packer residuo non e' gestito dai
      tool automatici disponibili);
    - looks_still_packed() non rileva piu' segnali di packing sul file
      appena prodotto (probabile payload finale raggiunto).

    Ritorna una tupla:
      (file_finale_o_None, metodo_ultimo_layer_riuscito_o_None,
       numero_di_layer_rimossi, limite_raggiunto: bool)
    limite_raggiunto=True significa che il ciclo si e' fermato per aver
    esaurito i round disponibili MENTRE il file mostrava ancora segnali di
    packing: e' un'indicazione che potrebbero restare layer non rimossi.
    """
    current_path = filepath
    last_method = None
    layers_removed = 0
    hit_max_layers = False

    for layer in range(1, max_layers + 1):
        log.info(f"  [>] Ciclo multilayer - round {layer}/{max_layers} su {os.path.basename(current_path)}...")

        # L'hint della Fase 1 e' calcolato sul file ORIGINALE: vale solo al primo giro.
        # Dopo che un layer e' stato rimosso, il file sotto puo' essere qualsiasi cosa.
        hint = die_hint if layer == 1 else None
        hint_name = (hint or {}).get("name", "")
        hint_type = (hint or {}).get("type", "").lower()
        hint_all = (hint or {}).get("all", "").lower()

        # Si guarda TUTTE le identificazioni di DIE, non solo la principale. Caso reale,
        # misurato sui 53 campioni Inno della matrice: DIE riporta
        #   ".NET Reactor (protector); Inno Setup Module (installer)"
        # e la Fase 1 sceglie come principale ".NET Reactor" - che e' un falso positivo
        # (quei file non hanno header .NET: Is_DotNet=NO, Has_CLR_Header=NO). Fermandosi al
        # tipo principale l'installer non verrebbe riconosciuto e finirebbe nell'emulazione,
        # che e' esattamente l'errore che questo instradamento deve evitare. Un file puo'
        # inoltre essere legittimamente un installer CHE CONTIENE un payload compresso.
        is_installer = (hint_type in ("installer", "sfx")
                        or "(installer)" in hint_all or "(sfx)" in hint_all)

        unpacked_file, method = (None, None)

        if is_installer:
            # Un installer e' un CONTENITORE, non un eseguibile compresso: si apre con un
            # estrattore. Mandarlo all'emulazione e' peggio che non fare nulla - Unipacker
            # emula lo stub e produce il codice DELL'INSTALLER, che Ghidra approva perche'
            # e' codice valido, ma non e' il payload (misurato: corrispondenza 2,6%-6,3%
            # con l'originale su 5 campioni Inno). Un fallimento dichiarato vale piu' di
            # un successo falso.
            log.info(f"  [i] Fase 1 vi riconosce un contenitore (tipo='{hint_type or "-"}', "
                     f"rilevati: {(hint or {}).get("all", "") or "-"}): uso gli estrattori, non l'emulazione.")
            for name, fn in (("sevenzip", unpack_with_7zip), ("innounp", unpack_with_innounp)):
                unpacked_file = _timed(name, fn, current_path, output_dir, is_windows)
                if unpacked_file:
                    method = name
                    break
            if not unpacked_file:
                log.info("  [-] Nessun estrattore ha aperto questo installer. Mi fermo qui: "
                         "emulare produrrebbe un risultato plausibile e sbagliato.")
                break
        else:
            unpacked_file = _timed("upx", unpack_with_upx, current_path, output_dir, is_windows)
            method = "upx" if unpacked_file else None

            # AspackDie e' uno strumento GRAFICO senza modalita' silenziosa: su un file non
            # ASPack apre una finestra bloccante e costa 8 s pieni di timeout. Nella misura
            # di partenza: 39 tentativi, 0 successi, 5,2 minuti interamente sprecati. Ora si
            # chiama SOLO se la Fase 1 ha riconosciuto ASPack per nome.
            if not unpacked_file and "aspack" in hint_name.lower():
                unpacked_file = _timed("aspackdie", unpack_with_aspackdie, current_path,
                                       output_dir, is_windows)
                method = "aspackdie" if unpacked_file else None

            if not unpacked_file:
                if not is_64bit:
                    unpacked_file = _timed("unipacker", unpack_with_unipacker, current_path, output_dir)
                    method = "unipacker" if unpacked_file else None
                else:
                    unpacked_file = _timed("qiling", unpack_with_qiling, current_path, output_dir,
                                           is_windows, is_64bit)
                    method = "qiling" if unpacked_file else None

            if not unpacked_file:
                # Ultima risorsa prima di arrendersi al layer corrente: mal_unpack esegue
                # davvero il campione. Disattivato di default, vedi MAL_UNPACK_ENABLED.
                unpacked_file = _timed("mal_unpack", unpack_with_mal_unpack, current_path,
                                       output_dir, is_windows)
                method = "mal_unpack" if unpacked_file else None

        if not unpacked_file:
            log.debug(f"  [-] Round {layer}: nessun tool ha rimosso un ulteriore layer. Ciclo interrotto.")
            break

        layers_removed += 1
        last_method = method
        current_path = unpacked_file

        still_packed, entropy = looks_still_packed(current_path, is_windows)
        log.info(f"  [+] Layer {layer} rimosso con '{method}' (entropia max sezioni: {entropy}). "
                 f"Ulteriore layer sospetto: {'SI' if still_packed else 'NO'}.")

        if not still_packed:
            break
    else:
        # Il for e' arrivato in fondo senza mai fare 'break': significa che
        # anche all'ultimo round disponibile il file risultava ancora
        # sospetto. Segnaliamo il limite raggiunto per farlo emergere nel
        # riepilogo finale.
        hit_max_layers = layers_removed > 0
        log.warning(f"  [!] Raggiunto il limite di {max_layers} round su {os.path.basename(filepath)}: "
                     "il file potrebbe avere ulteriori layer non rimossi.")

    final_path = current_path if layers_removed > 0 else None
    return final_path, last_method, layers_removed, hit_max_layers


def _ida_or_defer(filepath):
    """Esito della revisione umana. Con DEFER_IDA non apre nulla: il file resta in
    needs_manual_review dentro pipeline_state.json, che e' gia' la coda."""
    if DEFER_IDA:
        log.info("  [i] --defer-ida: IDA non aperto, il file resta in coda per la revisione manuale.")
        return "needs_manual_review"
    return "ida_session_done" if analyze_with_ida(filepath) else "needs_manual_review"


def process_packed_files(liste_malware_paths, target_dir, hints=None, force=False):
    """
    Riceve la lista dei file gia' identificati come Is_Packed_Label == 1
    dal CSV e avvia la cascata di unpacking e analisi.

    hints (opzionale): dict {percorso_completo: Die_Packer_Name}, costruito
    in parameters_info.py leggendo la colonna Die_Packer_Name del CSV di
    Fase 1. Se presente per un file, viene passato come die_hint alla
    cascata multilayer per tentare il routing diretto (vedi

    RESUME: ogni file viene identificato tramite hash SHA-256 (vedi
    pipeline_utils.PipelineState) e il suo esito viene salvato via via. Se
    la run viene interrotta (crash, chiusura terminale, timeout esterno) e
    rilanciata, i file già risolti con successo o già passati per una
    sessione IDA completata non vengono ripetuti da capo.
    """
    log.info("=" * 50)
    log.info("FASE 2: INIZIO PROCEDURE DI UNPACKING LOCALE AUTOMATICO")
    log.info("=" * 50)

    check_tool_paths()

    unpacked_dir = os.path.join(PARENT_DIR, "UNPACKED_SAMPLES")
    if not os.path.exists(unpacked_dir):
        os.makedirs(unpacked_dir)
        log.info(f"Creata cartella di output in: {unpacked_dir}")

    state = PipelineState()
    counters = {
        "processati": 0, "saltati_resume": 0,
        "upx": 0, "aspackdie": 0, "innounp": 0, "sevenzip": 0, "unipacker": 0, "qiling": 0,
        "mal_unpack": 0,
        "ghidra_ok": 0, "ida_fallback": 0, "falliti_tutti": 0, "fuori_perimetro": 0,
        "multilayer_rilevati": 0, "layer_totali_rimossi": 0,
        "limite_layer_raggiunto": 0,
    }

    for filepath in liste_malware_paths:
        filename = os.path.basename(filepath)
        file_hash = compute_file_hash(filepath)

        if file_hash and not force and state.is_fully_resolved(file_hash):
            log.info(f"[*] {filename}: già risolto in una run precedente (resume) — salto.")
            counters["saltati_resume"] += 1
            continue

        free_mb = shutil.disk_usage(unpacked_dir).free // (1024 * 1024)
        if free_mb < MIN_FREE_DISK_MB:
            log.error(f"Spazio su disco sotto la soglia di sicurezza: {free_mb} MB liberi "
                      f"(minimo {MIN_FREE_DISK_MB} MB). Interrompo il batch QUI invece di "
                      f"produrre risultati corrotti. Libera spazio e rilancia senza --force: "
                      f"il resume riprende dai file non ancora processati.")
            break

        log.info(f"[*] Analizzando sospetto: {filename}")
        counters["processati"] += 1

        info = get_binary_info(filepath)
        if info is None:
            log.warning(f"  [-] {filename}: non e' un PE, fuori dal perimetro attuale. Salto.")
            counters["fuori_perimetro"] += 1
            if file_hash:
                state.update(file_hash, filename=filename, unpack_attempted=False,
                             final_status="out_of_scope_not_pe")
            continue
        is_windows, is_64bit = info
        log.debug(f"Info Binario: {'Windows' if is_windows else 'Linux'}, {'64-bit' if is_64bit else '32-bit'}")

        die_hint = (hints or {}).get(filepath)
        if die_hint:
            log.debug(f"  [i] Hint Fase 1 per {filename}: nome='{die_hint.get('name')}' "
                      f"tipo='{die_hint.get('type')}'")

        unpacked_file, unpack_method, layers_removed, hit_max_layers = unpack_cascade_multilayer(
            filepath, unpacked_dir, is_windows, is_64bit, die_hint=die_hint
        )

        if unpack_method:
            # .get() e non counters[...]: aggiungere un tool alla cascata senza aggiornare
            # questo dizionario faceva morire l'INTERA run con KeyError a meta' batch
            # (successo di 7-Zip, run persa). Un contatore mancante non e' un motivo per
            # buttare via il lavoro gia' fatto.
            counters[unpack_method] = counters.get(unpack_method, 0) + 1

        counters["layer_totali_rimossi"] += layers_removed
        if layers_removed > 1:
            counters["multilayer_rilevati"] += 1
            log.info(f"  [i] {filename}: rilevato packing multi-layer, rimossi {layers_removed} layer in cascata.")
        if hit_max_layers:
            counters["limite_layer_raggiunto"] += 1

        ghidra_ok = False
        func_count = None
        ida_required = False

        if unpacked_file:
            log.info("  [*] SCOMPATTAMENTO RIUSCITO!")
            log.info(f"  [*] File analizzabile salvato in: {os.path.basename(unpacked_file)}")

            ghidra_ok, report_path = analyze_with_ghidra_headless(unpacked_file, is_windows, is_64bit)
            func_count = parse_ghidra_func_count(report_path) if ghidra_ok else None
            if func_count is not None:
                log.info(f"  [i] Ghidra ha identificato {func_count} funzioni nel file scompattato.")

            esito_affidabile = (
                ghidra_ok and func_count is not None and func_count >= MIN_FUNCTIONS_THRESHOLD
            )

            if esito_affidabile:
                log.info("  [+] Verifica Ghidra OK. Procedo in automatico al prossimo file...")
                counters["ghidra_ok"] += 1
                final_status = "unpacked_ok"
            else:
                log.info(f"  [?] Verifica Ghidra dubbia (esito_parsing={ghidra_ok}, funzioni={func_count}).")
                log.info("  [!] Apro IDA per una conferma manuale prima di proseguire...")
                ida_required = True
                final_status = _ida_or_defer(unpacked_file)
        else:
            log.warning("  [-] Tutti i tool automatici hanno fallito (packer sconosciuto o architettura non supportata).")
            log.warning("  [!] Richiesto intervento umano: apro il file in IDA per l'analisi manuale...")
            counters["falliti_tutti"] += 1
            ida_required = True
            final_status = _ida_or_defer(filepath)

        if ida_required:
            counters["ida_fallback"] += 1

        if file_hash:
            state.update(
                file_hash,
                relpath=os.path.relpath(filepath, target_dir),
                filename=filename,
                unpack_attempted=True,
                unpack_method=unpack_method,
                unpack_output=unpacked_file,   # letto da validate_phase2.py per il confronto con l'originale
                unpack_success=bool(unpacked_file),
                layers_removed=layers_removed,
                multilayer_detected=layers_removed > 1,
                layer_limit_reached=hit_max_layers,
                ghidra_verified=ghidra_ok,
                ghidra_func_count=func_count,
                ida_required=ida_required,
                final_status=final_status,
            )

    # Senza questo i risultati della Fase 2 si perdevano: PipelineState.save() e'
    # batched (SAVE_EVERY=50) e su una run piu' corta di 50 file nulla arrivava mai
    # su disco. La Fase 1 gia' lo faceva (header_elf_lief.py), la Fase 2 no.
    state.flush()

    _build_and_save_summary(counters, target_dir)