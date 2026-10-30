# @runtime Jython
# basic_info_report.py
# ============================================================
# Script POST-ANALISI per Ghidra Headless Analyzer (Jython).
# Sostituisce IDA Free (che nella edizione gratuita non supporta
# la modalita' batch/-B) come step di conferma "il binario e'
# disassemblabile correttamente" dopo l'unpacking.
#
# FIX: a partire da Ghidra 12.0, il motore di default per gli
# script .py e' diventato PyGhidra (Python 3 via Jep) invece di
# Jython. Senza la direttiva "# @runtime Jython" sulla primissima
# riga del file, Ghidra prova a instradare questo script (scritto
# in Jython puro) verso PyGhidra, che qui non e' configurato, e
# fallisce sempre con:
#   "Ghidra was not started with PyGhidra. Python is not available"
# La direttiva deve stare OBBLIGATORIAMENTE come prima riga del
# file (anche prima di eventuali commenti descrittivi), altrimenti
# non viene riconosciuta.
#
# Uso da riga di comando (vedi subprocesses.py):
#   analyzeHeadless <project_dir> <project_name> -import <file> \
#       -scriptPath <cartella_di_questo_script> \
#       -postScript basic_info_report.py <output_report_path> \
#       -deleteProject -overwrite
# ============================================================

args = getScriptArgs()
output_path = args[0] if len(args) > 0 else (currentProgram.getName() + "_report.txt")

program = currentProgram
func_manager = program.getFunctionManager()
symbol_table = program.getSymbolTable()

lines = []
lines.append("=== Ghidra Headless Report ===")
lines.append("File: " + program.getName())
lines.append("Formato: " + str(program.getExecutableFormat()))
lines.append("Base indirizzo immagine: " + str(program.getImageBase()))

# Entry point (puo' essercene piu' di uno, tipicamente uno solo per eseguibili normali)
entry_points = []
ep_iter = symbol_table.getExternalEntryPointIterator()
while ep_iter.hasNext():
    entry_points.append(str(ep_iter.next()))
lines.append("Entry point: " + (", ".join(entry_points) if entry_points else "NON TROVATO"))

# Numero di funzioni identificate dall'auto-analisi: un numero molto
# basso (es. <5) su un binario che dovrebbe essere "pulito" e' un segnale
# che l'unpacking non e' stato completo o che il disassembly e' fallito.
func_count = func_manager.getFunctionCount()
lines.append("Numero funzioni identificate: " + str(func_count))

# Simboli esterni (import): utile come ulteriore conferma incrociata
# rispetto a quanto gia' letto da pefile/LIEF nella Fase 1.
imported = []
ext_iter = symbol_table.getExternalSymbols()
for sym in ext_iter:
    imported.append(sym.getName())

lines.append("Numero simboli esterni/importati: " + str(len(imported)))
if imported:
    preview = imported[:15]
    lines.append("Esempio import: " + ", ".join(preview))

report_text = "\n".join(lines)

f = open(output_path, "w")
f.write(report_text)
f.close()

println("Report scritto in: " + output_path)
println(report_text)