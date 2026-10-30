import tkinter as tk
from tkinter import filedialog
import os
import csv
import argparse
import shutil
import time

# Importiamo i nostri due "sotto-moduli"
try:
    import header_info as HI  # modulo storico, non piu' usato (solo PE): import reso opzionale
except ImportError:
    HI = None

# La Fase 2 (subprocesses.py) importa qiling, unicorn e pefile a livello di modulo.
# Importarla qui costringerebbe a installare TUTTO lo stack di emulazione anche per
# eseguire la sola Fase 1 con --phase1-only: l'import e' quindi RITARDATO al momento
# in cui la Fase 2 serve davvero (vedi _load_fase2). Cosi' la Fase 1 gira con due sole
# dipendenze di terze parti, lief e yara-python.
import header_elf_lief as HL  # Importa il nuovo modulo LIEF
from pipeline_utils import setup_logger


def _load_fase2():
    """Importa subprocesses solo quando la Fase 2 va eseguita.
    Se lo stack di emulazione non e' installato lo dice in modo esplicito, invece di
    far fallire l'avvio dello script con un ImportError oscuro."""
    try:
        import subprocesses as UT
        return UT
    except ImportError as e:
        log.critical(f"Fase 2 non disponibile: manca una dipendenza dello stack di emulazione ({e}). "
                     f"Installa 'qiling', 'unicorn' e 'pefile', oppure usa --phase1-only.")
        return None

log = setup_logger("Orchestratore")


def scegli_cartella():
    """Apre il file explorer per far selezionare all'utente una cartella."""
    root = tk.Tk()
    root.withdraw()

    percorso = filedialog.askdirectory(title="Seleziona la cartella contenente i PE/ELF da analizzare")
    return percorso


def extract_packed_files(csv_path, target_dir):
    """
    Legge il CSV appena generato, cerca le righe dove Is_Packed_Label == '1'
    e ricostruisce il percorso completo dei file.

    Nota: la colonna 'File' contiene ora il path RELATIVO alla cartella
    target (non piu' il solo basename), quindi os.path.join gestisce
    correttamente anche i campioni annidati in sottocartelle. In
    precedenza un file come "malware/sample.exe" veniva cercato come
    "<target_dir>/sample.exe" e risultava sempre non trovato.

    Oltre alla lista dei path, ritorna anche 'hints': un dict
    {percorso_completo: Die_Packer_Name}, costruito dalla colonna
    Die_Packer_Name del CSV (Fase 1, header_elf_lief.py). Passato poi a
    subprocesses.process_packed_files() per permettere alla cascata
    multilayer di tentare il routing diretto (try_hinted_static_unpacker)
    invece della sequenza cieca upx -> aspackdie -> innounp -> emulazione.
    Se la colonna e' assente/vuota per un file, semplicemente non compare
    nel dict: la cascata standard prosegue senza hint per quel file.
    """
    packed_files = []
    hints = {}

    if not os.path.exists(csv_path):
        log.error(f"Il file CSV {csv_path} non esiste.")
        return packed_files, hints

    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get('Is_Packed_Label') == '1':
                percorso_relativo = row['File']
                percorso_completo = os.path.join(target_dir, percorso_relativo)
                if os.path.exists(percorso_completo):
                    packed_files.append(percorso_completo)
                    die_name = (row.get('Die_Packer_Name') or '').strip()
                    die_type = (row.get('Die_Packer_Type') or '').strip()
                    die_all = (row.get('Die_All_Packers') or '').strip()
                    if die_name or die_type or die_all:
                        hints[percorso_completo] = {"name": die_name, "type": die_type,
                                                    "all": die_all}
                else:
                    log.warning(f"File in CSV ma non trovato su disco (spostato/rinominato?): {percorso_relativo}")

    return packed_files, hints


def main():
    parser = argparse.ArgumentParser(
        description="Pipeline di analisi statica e unpacking automatico (PE/ELF)."
    )
    parser.add_argument(
        "--dir", "-d", dest="cartella",
        help="Cartella da analizzare. Se omessa, si apre il file explorer (GUI)."
    )
    parser.add_argument(
        "--yes", "-y", action="store_true",
        help="Avvia automaticamente la Fase 2 (unpacking) senza chiedere conferma s/n. "
             "Utile per riprendere una run interrotta senza interazione manuale."
    )
    parser.add_argument(
        "--phase1-only", action="store_true",
        help="Esegue SOLO la Fase 1 (analisi statica: LIEF + YARA + DIE + capa) e si ferma prima dell'unpacking. "
             "Utile per collaudare e tarare il triage senza passare da Qiling/Ghidra/IDA.")
    parser.add_argument(
        "--capa-mode", choices=HL.CAPA_MODES, default=None,
        # NB: argparse applica la sua interpolazione %% al testo di help, quindi un '%'
        # letterale va raddoppiato o print_help() solleva un'eccezione.
        help=f"Modo di esecuzione di capa in Fase 1 (default: '{HL.CAPA_MODE}'). "
             "Misurato su 189 file: capa costa il 96%% del wall clock della fase, produce 0 segnali forti "
             "e cambia 0 verdetti, perche' l'arresto al banner impedisce di ottenere il JSON da cui si "
             "legge il packer nominato. 'full' toglie l'arresto anticipato e recupera quel segnale, al "
             "costo del tempo pieno: usalo su un sottoinsieme per il confronto fra tool, non sul dataset "
             "intero.")
    parser.add_argument(
        "--defer-ida", action="store_true",
        help="Non apre IDA: i file da rivedere a mano restano in stato 'needs_manual_review' "
             "dentro pipeline_state.json e la run prosegue. Necessario per qualunque batch "
             "non sorvegliato: IDA blocca il processo finche' non si chiude la finestra.")
    parser.add_argument(
        "--force", action="store_true",
        help="Ignora il resume e riprocessa anche i file gia' risolti in una run precedente. "
             "Serve dopo aver cambiato la logica di Fase 2, altrimenti i vecchi esiti "
             "vengono scambiati per risultati della nuova.")
    parser.add_argument(
        "--reanalyze", action="store_true",
        help="Archivia il CSV di Fase 1 esistente (.bak_<timestamp>) e rianalizza TUTTI i file. "
             "Necessario dopo aver cambiato la logica di scoring: senza, i file gia' presenti nel "
             "CSV vengono saltati ('Nessun nuovo file da analizzare') e il nuovo scoring non si applica."
    )
    args = parser.parse_args()

    if args.capa_mode:
        log.info(f"Modo capa impostato a '{HL.set_capa_mode(args.capa_mode)}' per questa run.")

    if args.cartella:
        cartella_selezionata = args.cartella
    else:
        log.info("Apertura esplora risorse in corso...")
        cartella_selezionata = scegli_cartella()

    if cartella_selezionata:
        log.info(f"Cartella selezionata: {cartella_selezionata}")
        log.info(f"Tutti i report/output della pipeline verranno raccolti in: {HL.OUTPUT_DIR}")

        # ---------------------------------------------------------
        # FASE 1: ANALISI STATICA
        # ---------------------------------------------------------
        if HI is not None:
            log.debug(">>> FASE 1a (header_info.py) disponibile ma disattivata: obsoleta, solo PE.")

        if args.reanalyze and os.path.exists(HL.OUTPUT_CSV):
            bak = f"{HL.OUTPUT_CSV}.bak_{time.strftime('%Y%m%d_%H%M%S')}"
            shutil.move(HL.OUTPUT_CSV, bak)
            log.warning(f"--reanalyze: CSV Fase 1 archiviato in {bak}")

        log.info(">>> AVVIO FASE 1: Analisi Statica dell'Header PE/ELF (LIEF + YARA + capa)...")
        HL.main(cartella_selezionata)

        if args.phase1_only:
            log.info("--phase1-only: Fase 1 completata, Fase 2 (unpacking) non eseguita.")
            log.info(f"Report: {HL.OUTPUT_CSV} | diagnostica per tool: {HL.TOOL_DIAG_PATH}")
            return

        # ---------------------------------------------------------
        # FASE 2: TRIAGE E UNPACKING (subprocesses.py)
        # ---------------------------------------------------------
        csv_generato = HL.OUTPUT_CSV

        log.info(">>> Lettura del report generato per individuare i file pacchettizzati...")
        file_da_spacchettare, die_hints = extract_packed_files(csv_generato, cartella_selezionata)

        if file_da_spacchettare:
            log.info(f"Trovati {len(file_da_spacchettare)} file candidati all'unpacking.")
            if die_hints:
                log.info(f"Hint DIE disponibili da Fase 1 per {len(die_hints)} di questi file "
                         "(verranno usati per ottimizzare l'ordine dei tentativi in Fase 2).")

            if args.yes:
                procedi = True
            else:
                scelta = input(
                    "\nVuoi avviare l'unpacking automatico (UPX/AspackDie/InnoUnp/Unipacker/Qiling), "
                    "la verifica con Ghidra e, se necessario, l'analisi manuale con IDA? (s/n): "
                )
                procedi = scelta.lower() == 's'

            if procedi:
                UT = _load_fase2()
                if UT is None:
                    return
                UT.DEFER_IDA = args.defer_ida
                UT.process_packed_files(file_da_spacchettare, cartella_selezionata,
                                        hints=die_hints, force=args.force)
            else:
                log.info("Operazione di unpacking annullata dall'utente.")
        else:
            log.info("Nessun file identificato come pacchettizzato (Score < 70%). Fine operazioni.")

        log.info("=== PIPELINE COMPLETATA ===")

    else:
        log.warning("Operazione annullata. Nessuna cartella selezionata.")


if __name__ == "__main__":
    main()