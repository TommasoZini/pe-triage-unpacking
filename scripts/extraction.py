import os
import time
import csv
import requests
import pyzipper

# ==============================================================================
# Configurazione
# ==============================================================================
API_KEY = os.environ.get("MB_AUTH_KEY", "")   # chiave MalwareBazaar: non committata, vedi README
OUTPUT_DIR = r"E:\DATASET\03_NON_ETICHETTATI\wild_malwarebazaar"
TAGS = ["upx", "themida", "vmprotect", "aspack", "pecompact"]
TARGET_PER_TAG = 60

POISON_TAGS = {"upx-dec", "unpacked", "extracted", "clean"}
ZIP_PASSWORD = b"infected"

HEADERS = {
    "Auth-Key": API_KEY,
    "User-Agent": "Research-Thesis-Script/2.0"
}
API_URL = "https://mb-api.abuse.ch/api/v1/"

# ==============================================================================
# Setup e File CSV
# ==============================================================================
os.makedirs(OUTPUT_DIR, exist_ok=True)
manifest_path = os.path.join(OUTPUT_DIR, "manifest.csv")

if not os.path.exists(manifest_path):
    with open(manifest_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sha256_hash", "primary_tag_queried", "all_tags", "file_type", "signature"])

def log_to_manifest(sample, primary_tag):
    with open(manifest_path, mode="a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        all_tags = "|".join(sample.get("tags", [])) if sample.get("tags") else "None"
        writer.writerow([
            sample.get("sha256_hash", ""),
            primary_tag,
            all_tags,
            sample.get("file_type", ""),
            sample.get("signature", "Unknown")
        ])

# ==============================================================================
# Esecuzione (Ricerca, Filtraggio per EXE/DLL, Download e Estrazione)
# ==============================================================================
downloaded_hashes = set()

for tag in TAGS:
    print(f"\n[*] ==========================================")
    print(f"[*] Elaborazione tag: {tag}")
    tag_dir = os.path.join(OUTPUT_DIR, tag)
    os.makedirs(tag_dir, exist_ok=True)

    # Chiediamo un lotto enorme (500) per avere margine di filtraggio
    data = {"query": "get_taginfo", "tag": tag, "limit": 500} 
    
    try:
        response = requests.post(API_URL, data=data, headers=HEADERS, timeout=15)
        if response.status_code != 200:
            response.raise_for_status() 
            
        json_data = response.json()
        if json_data.get("query_status") != "ok":
            print(f"  [!] Query rifiutata o nessun dato per '{tag}'. Motivo: {json_data.get('query_status')}")
            continue
            
        samples = json_data.get("data", [])
        
        # Serbatoi per il filtraggio
        exe_pool = []
        dll_pool = []
        
        # 1. Smistamento dei sample (EXE vs DLL) e rimozione veleni
        for sample in samples:
            hash256 = sample.get("sha256_hash")
            sample_tags = set(sample.get("tags", []))
            file_type = str(sample.get("file_type", "")).lower()
            
            # Scarta se contiene tag velenosi o se lo abbiamo già scaricato
            if POISON_TAGS.intersection(sample_tags) or hash256 in downloaded_hashes:
                continue
                
            if file_type == "exe":
                exe_pool.append(sample)
            elif file_type == "dll":
                dll_pool.append(sample)
                
        # 2. Selezione con priorità agli EXE
        selected_samples = exe_pool[:TARGET_PER_TAG]
        
        # Se gli EXE non bastano, compensiamo con le DLL
        if len(selected_samples) < TARGET_PER_TAG:
            needed = TARGET_PER_TAG - len(selected_samples)
            selected_samples.extend(dll_pool[:needed])
            
        total_found = len(selected_samples)
        print(f"  [>] Trovati {total_found} sample validi (EXE/DLL) su un target di {TARGET_PER_TAG}.")
        
        # 3. Download ed Estrazione
        for i, sample in enumerate(selected_samples, 1):
            hash256 = sample.get("sha256_hash")
            file_ext = sample.get("file_type", "exe").lower()
            zip_path = os.path.join(tag_dir, f"{hash256}.zip")
            
            print(f"  [{i}/{total_found}] Download {hash256}.{file_ext} ...")
            
            dl_data = {"query": "get_file", "sha256_hash": hash256}
            dl_resp = requests.post(API_URL, data=dl_data, headers=HEADERS, timeout=30)
            
            if dl_resp.status_code != 200 or dl_resp.headers.get('Content-Type', '').startswith('application/json'):
                print(f"      [X] Errore API durante il download.")
                continue
                
            # Salva ZIP
            with open(zip_path, "wb") as f:
                f.write(dl_resp.content)
            
            # Estrai ZIP e cancella archivio
            try:
                with pyzipper.AESZipFile(zip_path, 'r') as zf:
                    zf.setpassword(ZIP_PASSWORD)
                    zf.extractall(path=tag_dir)
                os.remove(zip_path)
                log_to_manifest(sample, tag)
                downloaded_hashes.add(hash256)
            except Exception as e:
                print(f"      [X] Errore estrazione (Password errata o file corrotto): {e}")
                
            time.sleep(2) # Rispetto del rate-limit
            
    except Exception as err:
        print(f"  [X] Errore di rete o eccezione Python: {err}")

print(f"\n[*] Operazione completata. Metadati aggiornati in: {manifest_path}")