import os
import urllib.request
import json
import zipfile
import shutil

# Percorsi relativi alla tua struttura
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(SCRIPT_DIR)
RULES_DIR = os.path.join(PARENT_DIR, "config", "yara-forge")
CACHE_FILE = os.path.join(PARENT_DIR, "config", "yara_forge_compiled.yrc")

API_URL = "https://api.github.com/repos/Yara-Forge/yara-forge/releases/latest"

def update_yara_forge():
    print("[*] Cerco l'ultima versione di Yara-Forge su GitHub...")
    
    try:
        # 1. Trova l'URL dell'ultimo pacchetto "Full"
        with urllib.request.urlopen(API_URL) as response:
            data = json.loads(response.read().decode())
            
        download_url = None
        for asset in data.get("assets", []):
            if "yara-forge-rules-full" in asset["name"] and asset["name"].endswith(".zip"):
                download_url = asset["browser_download_url"]
                break
                
        if not download_url:
            print("[-] Impossibile trovare il file ZIP nella release più recente.")
            return

        print(f"[+] Trovata nuova versione! Download da: {download_url}")
        
        # 2. Scarica il file ZIP
        zip_path = os.path.join(PARENT_DIR, "config", "temp_yara.zip")
        urllib.request.urlretrieve(download_url, zip_path)
        print("[+] Download completato.")

        # 3. Pulisce la vecchia cartella e crea la nuova
        if os.path.exists(RULES_DIR):
            shutil.rmtree(RULES_DIR)
        os.makedirs(RULES_DIR)

        # 4. Estrae i nuovi file
        print("[*] Estrazione delle regole...")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(RULES_DIR)
            
        # 5. Rimuove il file ZIP temporaneo e la cache
        os.remove(zip_path)
        if os.path.exists(CACHE_FILE):
            os.remove(CACHE_FILE)
            print("[+] Vecchia cache .yrc eliminata.")
            
        print("[+] AGGIORNAMENTO COMPLETATO CON SUCCESSO!")
        print("    Al prossimo avvio del framework, le nuove regole verranno compilate automaticamente.")

    except Exception as e:
        print(f"[!] Errore durante l'aggiornamento: {e}")

if __name__ == "__main__":
    update_yara_forge()