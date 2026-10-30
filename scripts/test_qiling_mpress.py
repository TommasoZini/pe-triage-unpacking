"""
Test isolato: chiama unpack_with_qiling() direttamente sui due file MPRESS
gia' noti per il KeyError: 'kernel32', bypassando tutta l'orchestrazione
(niente Fase 1, niente resume-state, niente Ghidra/IDA dopo) - serve solo a
verificare se l'upgrade a Qiling 1.4.11 ha risolto il problema originale.

USO:
1. Copia questo file nella stessa cartella di subprocesses.py (o aggiusta
   la riga "sys.path.append" sotto per puntare a quella cartella).
2. Modifica TEST_FILES con i path reali dei due campioni MPRESS nel tuo
   TEST_SAMPLES (quelli che nel log precedente hanno dato KeyError).
3. Esegui: python test_qiling_mpress.py
"""
import sys
import os

# Aggiusta questo path se lo script non sta nella stessa cartella di subprocesses.py
sys.path.append(r"C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\scripts")

import subprocesses as UT

TEST_FILES = [

    r"E:\DATASET\03_NON_ETICHETTATI\malware_reali\1c72bee27bc88563e9f74a46dcf7d119e8ccc4c8801231af5cd293c5f593105a.exe",
    r"E:\DATASET\03_NON_ETICHETTATI\malware_reali\cf0d4b3837b9a23fb46cbb0a90f5ecae6b7dcd5b1f13b9d4a5fe0de7cec85041.exe",
    # r"C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\TEST_SAMPLES\awk_C57F626DD07175E23AAEF766D9C699FCE950483B1CEB665C4771A45D87C14099.exe",
    # r"C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\TEST_SAMPLES\backgroundTaskHost_20330D3CA71D58F4AEB432676CB6A3D5B97005954E45132FB083E90782EFDD50.exe",
    # r"C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\TEST_SAMPLES\b2sum_604DEB03FC039E3588A782010774A9D7B4F785F015323A4F4739AC26070569A4.exe",
    # r"C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\TEST_SAMPLES\b2sum_A09C42BA64C43175C4813B31950EFB550E48395BE9EF14A05731E9CB1508C647.exe",


]

OUTPUT_DIR = r"C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\TEST_QILING_OUT"
os.makedirs(OUTPUT_DIR, exist_ok=True)

for filepath in TEST_FILES:
    print("=" * 70)
    print(f"Test Qiling isolato su: {os.path.basename(filepath)}")
    print("=" * 70)

    if not os.path.exists(filepath):
        print(f"  [!] File non trovato: {filepath} - correggi TEST_FILES sopra.")
        continue

    # is_windows=True, is_64bit=True: gia' noto da run precedente (log:
    # "Tentativo 2b: Qiling Framework (x64 64-bit)")
    result = UT.unpack_with_qiling(filepath, OUTPUT_DIR, is_windows=True, is_64bit=True)

    if result:
        print(f"  [+] SUCCESSO: {result}")
    else:
        print(f"  [-] Fallito di nuovo (controlla pipeline.log per l'eccezione esatta).")
    print()

print("Test completato. Controlla pipeline.log per i dettagli di ogni tentativo.")
