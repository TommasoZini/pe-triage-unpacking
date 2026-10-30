import os
import csv
import math
import pefile
import yara
import logging
import sys

from pipeline_utils import OUTPUT_DIR

# ==========================================
# GESTIONE PERCORSI GLOBALI (Parent Directory)
# ==========================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)

# ==========================================
# CONFIGURAZIONE LOGGING ESTETICO
# ==========================================
class ColorFormatter(logging.Formatter):
    GREY = "\x1b[38;20m"
    GREEN = "\x1b[32;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    RESET = "\x1b[0m"
    FORMAT = "%(asctime)s - %(levelname)-8s - %(message)s"
    DATE_FORMAT = "%H:%M:%S"

    FORMATS = {
        logging.DEBUG: GREY + FORMAT + RESET,
        logging.INFO: GREEN + FORMAT + RESET,
        logging.WARNING: YELLOW + FORMAT + RESET,
        logging.ERROR: RED + FORMAT + RESET,
        logging.CRITICAL: BOLD_RED + FORMAT + RESET
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt=self.DATE_FORMAT)
        return formatter.format(record)

def setup_logger():
    logger = logging.getLogger("PE_Analyzer")
    logger.setLevel(logging.DEBUG)
    
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO) 
    console_handler.setFormatter(ColorFormatter())

    # analisi_pe.log finisce ora in Pipeline_Reports/ (OUTPUT_DIR condiviso
    # da tutta la pipeline, definito in pipeline_utils.py) invece che
    # direttamente nella parent directory.
    log_path = os.path.join(OUTPUT_DIR, "analisi_pe.log")
    file_handler = logging.FileHandler(log_path, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter("%(asctime)s - %(levelname)-8s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    file_handler.setFormatter(file_formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger

log = setup_logger()

# ==========================================
# CONFIGURAZIONE SCRIPT E SOGLIE SCORING
# ==========================================
# OUTPUT_DIR e' importato da pipeline_utils.py (fonte unica, condivisa
# anche da header_elf_lief.py e subprocesses.py) cosi' tutti i report della
# pipeline finiscono nello stesso posto invece di essere sparpagliati.
OUTPUT_CSV = os.path.join(OUTPUT_DIR, "report_analisi_pe.csv")

VALID_PE_EXTENSIONS = {".exe", ".dll", ".elf", ".sys", ".scr"}
STANDARD_SECTIONS = [".text", ".data", ".rdata", ".bss", ".rsrc", ".reloc", ".idata", ".edata", ".pdata"]
STANDARD_EXEC_SECTIONS = [".text", "code", "text", ".code"]

PACKING_THRESHOLD = 70 

YARA_RULES = """
rule Packer_UPX {
    strings:
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $upx3 = "UPX!"
    condition:
        2 of them
}
rule Packer_ASPack {
    strings:
        $a1 = ".aspack"
        $a2 = "ASPack"
    condition:
        any of them
}
rule Anti_Debug_API {
    strings:
        $api1 = "IsDebuggerPresent" ascii wide
        $api2 = "CheckRemoteDebuggerPresent" ascii wide
    condition:
        any of them
}
"""

# ==========================================
# FUNZIONI DI SUPPORTO E STORICO
# ==========================================
def load_analysis_history(csv_path):
    analyzed = set()
    if os.path.exists(csv_path):
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'File' in row:
                        analyzed.add(row['File'])
            log.info(f"Caricati {len(analyzed)} file già analizzati dallo storico in: {csv_path}")
        except Exception as e:
            log.error(f"Errore nella lettura dello storico CSV: {str(e)}")
    return analyzed

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

def analyze_pe(filepath, compiled_rules):
    filename = os.path.basename(filepath)
    log.debug(f"Inizio analisi dettagliata per: {filename}")
    
    results = {
        "File": filename,
        "Total_Raw_Size": 0,        
        "Total_Virtual_Size": 0,    
        "Size_Difference": 0,       
        "Total_Sections": 0,
        "Suspicious_Sections": [],
        "High_Entropy_Sections": 0,
        "Max_Section_Entropy": 0.0,
        "Total_Imports": 0,
        "Imported_APIs": [],
        "Suspicious_IAT": "NO",     
        "EP_Section": "UNKNOWN",               
        "Anomalous_Size_Sections": [],         
        "YARA_Matches": [],
        "Packing_Score_%": 0,
        "Is_Packed_Label": 0
    }

    try:
        # Analisi YARA
        matches = compiled_rules.match(filepath)
        results["YARA_Matches"] = [match.rule for match in matches]
        if results["YARA_Matches"]:
            log.warning(f"Match YARA rilevati su {filename}: {', '.join(results['YARA_Matches'])}")

        pe = pefile.PE(filepath)
        
        results["Total_Sections"] = len(pe.sections)
        max_entropy = 0.0
        
        # Recupero l'Entry Point dell'eseguibile
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint

        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            virtual_size = section.Misc_VirtualSize
            raw_size = section.SizeOfRawData
            virtual_address = section.VirtualAddress
            
            results["Total_Virtual_Size"] += virtual_size
            results["Total_Raw_Size"] += raw_size

            # Mappatura locale dell'Entry Point
            if virtual_address <= ep < (virtual_address + max(virtual_size, raw_size)):
                results["EP_Section"] = sec_name

            # Rilevamento ANOMALIE LOCALI DI DIMENSIONE
            if raw_size == 0 and virtual_size > 0:
                results["Anomalous_Size_Sections"].append(sec_name)
            elif raw_size > 0 and (virtual_size > raw_size * 2.5):
                results["Anomalous_Size_Sections"].append(sec_name)

            if sec_name.lower() not in STANDARD_SECTIONS:
                results["Suspicious_Sections"].append(sec_name)

            data = section.get_data()
            entropy = calculate_entropy(data)
            if entropy > max_entropy:
                max_entropy = entropy
            
            if entropy > 7.2:
                results["High_Entropy_Sections"] += 1

        results["Max_Section_Entropy"] = round(max_entropy, 2)
        results["Size_Difference"] = results["Total_Virtual_Size"] - results["Total_Raw_Size"]

        # Analisi IAT mirata
        has_loadlibrary = False
        has_getprocaddress = False
        
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    results["Total_Imports"] += 1
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        results["Imported_APIs"].append(func_name)
                        
                        if func_name.startswith("LoadLibrary"):
                            has_loadlibrary = True
                        if func_name == "GetProcAddress":
                            has_getprocaddress = True
        
        if has_loadlibrary and has_getprocaddress and results["Total_Imports"] <= 10:
            results["Suspicious_IAT"] = "SI"
            
        # ==========================================
        # CALCOLO DELLO SCORE DI PACKING BILANCIATO
        # ==========================================
        score = 0
        
        # 1. Entropia elevata
        if results["Max_Section_Entropy"] >= 7.2:
            score += 30
            
        # 2. Anomalie Locali di Dimensione (Sezione Virtuale sbilanciata)
        if len(results["Anomalous_Size_Sections"]) > 0:
            score += 25
        elif results["Size_Difference"] > 200000:
            score += 10
            
        # 3. Posizione anomala dell'Entry Point (OEP dirottato)
        if results["EP_Section"].lower() not in STANDARD_EXEC_SECTIONS and results["EP_Section"] != "UNKNOWN":
            score += 25
            log.warning(f"  [!] Entry Point situato in sezione non standard: {results['EP_Section']}")
            
        # 4. Logica IAT
        if results["Suspicious_IAT"] == "SI":
            score += 30  
        elif results["Total_Imports"] < 20:
            score += 10  
            
        # 5. Indicatori ausiliari
        if len(results["Suspicious_Sections"]) > 0:
            score += 10
        if len(results["YARA_Matches"]) > 0:
            score += 25
            
        if score > 100:
            score = 100
            
        results["Packing_Score_%"] = score
        results["Is_Packed_Label"] = 1 if score >= PACKING_THRESHOLD else 0
        
        if results["Is_Packed_Label"] == 1:
            log.warning(f"[!] {filename} classificato come PACCHETTIZZATO (Score: {score}%)")
        else:
            log.info(f"[i] {filename} classificato come PULITO (Score: {score}%)")

        # Formattazione stringhe per CSV
        results["Suspicious_Sections"] = " | ".join(results["Suspicious_Sections"])
        results["Anomalous_Size_Sections"] = " | ".join(results["Anomalous_Size_Sections"])
        if len(results["Imported_APIs"]) > 10:
            results["Imported_APIs"] = " | ".join(results["Imported_APIs"][:10]) + f" ... (+{len(results['Imported_APIs'])-10})"
        else:
            results["Imported_APIs"] = " | ".join(results["Imported_APIs"])
        results["YARA_Matches"] = " | ".join(results["YARA_Matches"])

    except pefile.PEFormatError:
        log.error(f"Formato PE non valido o corrotto: {filename}")
        return None
    except Exception as e:
        log.critical(f"Errore inaspettato su {filename}: {str(e)}")
        return None

    return results

# ==========================================
# MAIN EXECUTION
# ==========================================
def main(target_dir: str):
    log.info("Inizializzazione dello script di Analisi Malware")
    analyzed_history = load_analysis_history(OUTPUT_CSV)
    
    try:
        compiled_rules = yara.compile(source=YARA_RULES)
    except Exception as e:
        log.critical(f"Errore durante la compilazione delle regole YARA: {str(e)}")
        return

    if not os.path.isdir(target_dir):
        log.error(f"La directory specificata non esiste: {target_dir}")
        return

    new_results = []
    files_to_process = []
    tot_files_pe = 0
    
    for root, dirs, files in os.walk(target_dir):
        for filename in files:
            estensione = os.path.splitext(filename)[1].lower()
            if estensione in VALID_PE_EXTENSIONS:
                tot_files_pe += 1
                if filename not in analyzed_history:
                    filepath = os.path.join(root, filename)
                    files_to_process.append((filename, filepath))
    
    log.info(f"Trovati {tot_files_pe} file PE (eseguibili). Di cui {len(files_to_process)} nuovi da analizzare.")

    if len(files_to_process) == 0:
        log.info("Nessun nuovo file da analizzare. Uscita.")
        return

    for filename, filepath in files_to_process:
        file_data = analyze_pe(filepath, compiled_rules)
        if file_data:
            new_results.append(file_data)

    if new_results:
        log.info(f"Salvataggio di {len(new_results)} nuovi risultati in: {OUTPUT_CSV}")
        try:
            file_exists = os.path.exists(OUTPUT_CSV)
            keys = new_results[0].keys()
            with open(OUTPUT_CSV, 'a', newline='', encoding='utf-8') as output_file:
                dict_writer = csv.DictWriter(output_file, fieldnames=keys)
                if not file_exists:
                    dict_writer.writeheader()
                dict_writer.writerows(new_results)
            log.info("Aggiornamento del report completato con successo!")
        except Exception as e:
            log.critical(f"Errore durante il salvataggio del file CSV: {str(e)}")

if __name__ == "__main__":
    print("Avvia questo script tramite parameters_info.py per selezionare la cartella.")