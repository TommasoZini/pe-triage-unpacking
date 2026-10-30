# SETUP — far girare la Fase 1 su un'altra macchina

Guida per chi riceve il progetto e non l'ha scritto. Riguarda la **Fase 1** (triage statico:
decidere se un eseguibile è pacchettizzato). La Fase 2 (unpacking) non è ancora consolidata e ha
un paragrafo a parte in fondo.

Per capire *cosa fa* e *perché*, leggi **`02_fase1_riferimento_tecnico.md`**. Questo file spiega solo come
metterlo in funzione.

---

## 0. Il controllo che risponde a tutto

Prima di qualunque altra cosa:

```bash
python scripts/preflight.py --packer
```

Verifica interprete, pacchetti, strumenti esterni, regole YARA e cartelle dei dati, e per ogni cosa
che manca dice **il file e la costante da correggere**. Esce con codice 0 se la Fase 1 è
eseguibile.

Rilancialo dopo ogni passo di questa guida: è il modo più rapido per sapere dove sei.

---

## 1. Interprete e pacchetti

Python **3.13** (testato su 3.13.13, Windows 10 x64; 3.9+ dovrebbe bastare).

```bash
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements-fase1.txt
```

La Fase 1 ha **due sole dipendenze obbligatorie**:

| pacchetto | versione | a cosa serve |
|---|---|---|
| `lief` | **1.0.0** | parsing PE/ELF: sezioni, entry point, import/export, overlay |
| `yara-python` | 4.5.4 | motore delle regole YARA |

> ⚠️ **La major di LIEF non è negoziabile.** L'API 1.x non è compatibile con la 0.x e con LIEF
> 0.17 la pipeline non gira. Sul progetto originale convivevano due interpreti con major diverso e
> solo quello del `.venv` funzionava: è il motivo per cui `preflight.py` controlla la versione.

Opzionali: `flare-capa` (solo per `--capa-mode full`), `requests` + `pyzipper` (solo per scaricare
campioni da MalwareBazaar).

`qiling`, `unicorn` e `pefile` sono della **Fase 2** e stanno in `requirements-fase2.txt` (§7):
vengono importati in modo ritardato, quindi `--phase1-only` gira senza averli installati. Se sai
già che ti servirà anche la Fase 2, installa entrambi i file in un colpo:

```bash
python -m pip install -r requirements-fase1.txt -r requirements-fase2.txt
```

---

## 2. Strumenti esterni

### Obbligatorio: Detect It Easy

È una delle fonti di segnale **forte**. Serve la versione **portable da riga di comando**
(`diec.exe`), non la GUI.

1. scarica la release portable da <https://github.com/horsicq/DIE-engine/releases> (usata: **3.21**);
2. scompattala dove preferisci;
3. correggi `DIEC_PATH` in `scripts/header_elf_lief.py`:

```python
DIEC_PATH = r"E:\Tools\die_win64_portable_3.21_x64\die\diec.exe"   # <-- il tuo percorso
```

Senza DIE la Fase 1 gira comunque, ma perde il segnale con la maggiore capacità discriminante
(92 % sui packed, 0 % sui clean).

### Fortemente consigliato: regole YARA-Forge

Il progetto usa il ruleset pubblico **YARA-Forge**, precompilato in
`config/yara_forge_compiled.yrc` (47 MB).

**Quel file non è nello zip** (troppo grande per il repository). Due modi:

- **a)** chiedi all'autore `config/yara_forge_compiled.yrc` e mettilo lì: è pronto all'uso;
- **b)** scarica il pacchetto da <https://github.com/YARAHQ/yara-forge/releases> in
  `config/yara-forge/` — al primo avvio viene compilato e messo in cache (lento la prima volta,
  istantaneo dopo).

Senza YARA la Fase 1 gira e lo dichiara nel log; perde una fonte di segnale forte.

### Opzionali: i packer

Servono **solo** a `scripts/pack_samples.py`, cioè a rigenerare il dataset di campioni packed.
Per *analizzare* non servono.

| tool | versione | dove si prende |
|---|---|---|
| UPX | 5.1.1 | <https://github.com/upx/upx/releases> |
| MPRESS | 2.19 | autore, freeware |
| VMProtect Demo | 3.10.6 | sito ufficiale (serve la versione **console**, `VMProtect_Con.exe`) |
| Themida | 3.2.4.34 | licenza commerciale; richiede un file di progetto `.tmd` per architettura, creato una volta dalla GUI |
| NSIS | — | <https://nsis.sourceforge.io> (`makensis.exe`) |
| Inno Setup 6 | — | <https://jrsoftware.org/isinfo.php> (`ISCC.exe`) |

I percorsi sono le costanti in testa a `scripts/pack_samples.py`.

---

## 3. I dati: non sono nello zip

I dataset pesano **circa 15 GB su 3.941 file**, e contengono **malware reale**. Non sono
distribuibili in uno zip, e in parte non sono ridistribuibili affatto (campioni MalwareBazaar,
binari di sistema Microsoft, campioni del libro *Practical Malware Analysis*).

Lo zip contiene però tutto ciò che serve a **ricostruirli** e a **verificare i risultati**:

| cosa c'è | cosa ci fai |
|---|---|
| `Pipeline_Reports/report_analisi_lief.csv` | i risultati completi, 51 colonne per campione. Ricontrollabile senza avere i binari |
| `Pipeline_Reports/ground_truth.json` | le label con il loro oracolo, indicizzate per SHA-256 |
| `Pipeline_Reports/validation_phase1.md` | le metriche già calcolate |
| `Pipeline_Reports/tool_diagnostics.jsonl` | una riga per ogni esecuzione di strumento, con versioni e durate |
| `config/*_labels.json` | l'etichettatura manuale, versionata |
| `Build_Samples/` | i sorgenti Go/Rust e gli script di build: **ricostruibili identici** |

**Verificare le metriche senza i binari** — funziona subito, perché l'aggancio è sull'hash:

```bash
python scripts/validate_phase1.py
```

**Ricostruire i dataset**, in ordine di facilità:

| dataset | come |
|---|---|
| `goodware_non_ms` (1.042) | `python scripts/fetch_goodware_non_ms.py` — scarica da MSYS2, Cygwin, VideoLAN, PuTTY, Notepad++ e curl, verifica il digest upstream ed estrae i soli PE. Poi `python scripts/build_ground_truth.py --import-labels config/goodware_non_ms_labels.json --labels-dir "E:/DATASET/01_LABEL_CERTA/goodware_non_ms"`. Serve rete e ~500 MB di traffico; le versioni si risolvono dai repository, quindi i file possono differire da quelli misurati qui (il manifest registra l'archivio e il suo hash per ogni campione) |
| `gorust` (16) | `cd Build_Samples && .\build_rust.ps1 && .\build_go.ps1` — serve Go e Rust |
| `pypi` (341) | le estensioni `.pyd` del proprio `.venv`: script in `docs/` o rifacibile in 20 righe |
| `system32` (1.990) | copia da `C:\Windows\System32` e `SysWOW64` della propria macchina |
| `matrice_packed` (353) | `python scripts/pack_samples.py` — serve tutta la toolchain di packer |
| `wild_malwarebazaar`, `pma_book`, `flare_vm` | **non ridistribuibili**: da procurarsi alle rispettive fonti |

La struttura attesa è descritta in `02_fase1_riferimento_tecnico.md` §7. Le radici sono costanti in
`scripts/pack_samples.py` e `scripts/make_dataset_index.py`.

---

## 4. Eseguire

```bash
# analisi di una cartella (si fermano prima della Fase 2)
python scripts/parameters_info.py --dir "E:/DATASET/01_LABEL_CERTA/matrice_packed" --phase1-only

# metriche
python scripts/validate_phase1.py

# mappa dei dataset
python scripts/make_dataset_index.py
```

Opzioni utili di `parameters_info.py`:

| opzione | effetto |
|---|---|
| `--phase1-only` | si ferma dopo il triage. **È l'opzione da usare** |
| `--reanalyze` | archivia il CSV e rianalizza tutto. **Necessaria dopo aver cambiato la logica dei segnali**: senza, i file già presenti vengono saltati |
| `--capa-mode full` | riattiva capa senza arresto anticipato (lento: ~8 s/file) |
| `--dir` omesso | apre una finestra di selezione cartella |

**I file già analizzati vengono saltati**, perché lo storico è indicizzato per SHA-256 del
contenuto. Rieseguire su una cartella già fatta non produce righe nuove: è voluto.

### Test

```bash
python -m unittest discover -s scripts/tests -v
```

44 test. Uno è `expectedFailure` di proposito: documenta il difetto noto **B8**, spiegato nella
docstring del test.

---

## 5. Se qualcosa va storto

| sintomo | causa |
|---|---|
| `AttributeError` su oggetti LIEF | versione di LIEF sbagliata: serve la **1.x** |
| "Nessun nuovo file da analizzare" | i file sono già nel CSV (storico per hash). Usa `--reanalyze` |
| `BATCH INCOMPLETO` nel log | il batch si è interrotto: **non usare quel CSV per le metriche** finché non è completo |
| "DIE non disponibile" | `DIEC_PATH` sbagliato in `scripts/header_elf_lief.py` |
| tutto `Capa_Status = disabled` | normale: `CAPA_MODE = "off"` è il default, e la scelta è motivata in `02_fase1_riferimento_tecnico.md` §4 |
| `validate_phase1.py` dice "righe non agganciate" | ci sono campioni nel CSV senza label nella ground truth: normale per i set di sola analisi qualitativa |

Il log unico di tutto è `Pipeline_Reports/pipeline.log` (in append). La diagnostica per singola
invocazione di strumento è in `tool_diagnostics.jsonl`.

---

## 6. Limite noto di portabilità

**I percorsi degli strumenti sono costanti dentro gli script, non in un file di configurazione.**
Su una macchina diversa vanno corretti a mano in 3 file:

| file | costanti |
|---|---|
| `scripts/header_elf_lief.py` | `DIEC_PATH`, `CAPA_PATH` |
| `scripts/pack_samples.py` | `UPX_PATH`, `MPRESS_PATH`, `VMPROTECT_PATH`, `THEMIDA_X86/X64`, `MAKENSIS_PATH`, `ISCC_PATH`, `SOURCES`, `MASTERS_DIR`, `OUTPUT_DIR` |
| `scripts/make_dataset_index.py` | `DEFAULT_ROOT` |

`preflight.py` li elenca tutti dicendo quali non esistono. La soluzione pulita — un
`config/tools.json` unico — è il miglioramento più utile rimasto ed è dichiarata fra i limiti in
`02_fase1_riferimento_tecnico.md` §12.

---

## 7. Fase 2 (non consolidata)

Se serve anche l'unpacking:

```bash
python -m pip install -r requirements-fase2.txt
python scripts/preflight.py --fase2
```

Le versioni sono fissate in `requirements-fase2.txt` (qiling 1.4.11, unicorn 2.1.3,
pefile 2024.8.26). Sono in un file separato da quello della Fase 1 perché il triage statico
deve poter girare senza: `unicorn` è l'installazione più fragile dello stack e non ha senso che
blocchi la Fase 1. Per installare tutto in un colpo:

```bash
python -m pip install -r requirements-fase1.txt -r requirements-fase2.txt
```

⚠️ La versione di Qiling **non è indifferente**: 1.4.11 è quella su cui sono state diagnosticate
le API mancanti e su cui sono scritti gli hook localizzati in `subprocesses.py`. Cambiarla invalida
quelle correzioni.

Poi si omette `--phase1-only`. Servono in più Ghidra (analisi headless) e i vari unpacker
(`upx -d`, AspackDie, InnoUnp, Unipacker), con i percorsi in `scripts/subprocesses.py`.

**Stato reale, da sapere prima di provarci:** su 5 campioni con ground truth certa, 2 dei
"successi" di Qiling producevano un dump con `.text` a zeri. Il criterio di successo (≥ 5 funzioni
trovate da Ghidra) è troppo debole. La storia completa delle diagnosi è in
`storico/2026-09-23_status_progetto.md` §2.3 e §4.2.
