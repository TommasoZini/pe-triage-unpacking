# Analisi critica Fase 1 — sessioni del 24 e 27 settembre 2026

> Documento generato a partire dalla sessione di analisi del 24/09/2026.
> Contiene, nell'ordine: (**Parte 1**) il riepilogo tecnico della Fase 1 richiesto prima
> dell'autorizzazione alla Fase 2; (**Parte 2**) l'analisi del run completo di
> `pack_samples.py`, le cause dei fallimenti, il fix di `pe_info()` e la specifica di
> `import_packing_matrix()`; (**§12**) l'esito dell'esecuzione: pulizia del dataset
> e import delle label nella ground truth.
>
> Tutti i numeri sono stati letti direttamente da codice, artefatti su disco o misurati
> rieseguendo i tool. Dove un dato contraddice `storico/2026-09-23_status_progetto.md`, la
> contraddizione è segnalata esplicitamente.

**Indice**
- [Parte 1 — Riepilogo tecnico della Fase 1](#parte-1--riepilogo-tecnico-della-fase-1)
  - [1. Funzionamento e flow](#1-funzionamento-e-flow--il-percorso-esatto-di-un-file-in-fase-1)
  - [2. Input e output](#2-input-e-output)
  - [3. Tool utilizzati e configurazioni](#3-tool-utilizzati-e-configurazioni)
  - [4. Scelte architetturali — il "perché"](#4-scelte-architetturali--il-perché)
  - [5. Risultati raggiunti — lettura critica](#5-risultati-raggiunti--lettura-critica)
  - [6. Rilievi critici dall'ispezione del run](#6-rilievi-critici-dallispezione-del-run--non-presenti-nei-documenti)
  - [7. Valutazione finale, blind spot e step mancanti](#7-valutazione-finale-blind-spot-e-step-mancanti)
- [Parte 2 — Run completo, fix e importer](#parte-2--run-completo-fix-e-importer)
  - [8. Metriche del run completo](#8-metriche-del-run-completo-di-pack_samplespy)
  - [9. Cosa è andato storto, e quanto è critico](#9-cosa-è-andato-storto-e-quanto-è-critico)
  - [10. Fix applicato a `pe_info()`](#10-fix-applicato-a-pe_info)
  - [11. Specifica di `import_packing_matrix()`](#11-specifica-di-import_packing_matrix-da-approvare-prima-di-eseguire)
  - [12. Esecuzione — pulizia e import](#12-esecuzione--pulizia-e-import-24092026)
  - [13. Prima misura OUT-OF-SAMPLE](#13-prima-misura-out-of-sample-della-fase-1-24092026)
  - [14. Estensione dataset — classe negativa non-Microsoft](#14-estensione-del-dataset--classe-negativa-non-microsoft-p0)
  - [15. Correzione: i master già pacchettizzati erano tre](#15-correzione-i-master-già-pacchettizzati-erano-tre-non-due)
  - [16. Sessione del 27/09 — chiusura della Fase 1](#16-sessione-del-27-settembre-2026--chiusura-della-fase-1)
  - [17. Verifica su malware reale e analisi manuale](#17-verifica-su-malware-reale-e-analisi-manuale-27-settembre-2026)
  - [18. Pulizia e portabilità](#18-pulizia-e-portabilità-27-28-settembre-2026)
  - [19. Le due correzioni ai segnali, applicate](#19-le-due-correzioni-ai-segnali-applicate-28-settembre-2026)
  - [20. Validazione su dataset esterno](#20-validazione-su-dataset-esterno-28-settembre-2026)
  - [21. Dataset esterno completo, e una correzione di metodo](#21-dataset-esterno-completo-e-una-correzione-di-metodo-28-settembre-2026)
  - [22. Seconda classe negativa non-Microsoft](#22-seconda-classe-negativa-non-microsoft--distribuzioni-ufficiali-29-settembre-2026)
  - [23. I 152 campioni fuori da ogni misura](#23-i-152-campioni-che-erano-fuori-da-ogni-misura-30-settembre-2026)

---
---

# PARTE 1 — Riepilogo tecnico della Fase 1

---

## 1. Funzionamento e flow — il percorso esatto di un file in Fase 1

### 1.1 Catena di invocazione

```
parameters_info.py (orchestratore)
  └─ argparse: --dir | --phase1-only | --capa-mode | --reanalyze | --yes
  └─ HL.main(target_dir)              ← header_elf_lief.py, Fase 1
       └─ analyze_with_lief(file)     ← per singolo campione
  └─ [se non --phase1-only] extract_packed_files(CSV) → subprocesses.process_packed_files()
```

`pipeline_utils.py` non è un passaggio del flow: è il **substrato trasversale** importato da
tutti e tre i moduli. Fornisce quattro cose e nient'altro:

- `setup_logger(name)` — logger unico, stesso `pipeline.log` in append per Fase 1 e Fase 2,
  con `name` che identifica la fase (`Fase1-LIEF`, `Fase2-Unpack`, `Orchestratore`) così una
  run è ricostruibile da un solo file;
- `compute_file_hash()` — SHA-256 del contenuto, **chiave primaria** di tutto lo stato;
- `PipelineState` — `pipeline_state.json`, resume condiviso Fase 1/Fase 2, con
  `SAVE_EVERY = 50`, retry con backoff e la garanzia che `save()` **non sollevi mai** (era la
  causa del batch troncato al file 945/1987 con exit code 0);
- `run_external()` / `write_tool_diag()` / `sanitize_tool_text()` — esecuzione di tool esterni
  con timeout, encoding UTF-8, kill dell'albero di processi, streaming stderr con arresto
  anticipato, e una riga di diagnostica per ogni invocazione.

### 1.2 Fase di batch (`header_elf_lief.main`)

1. `_archive_csv_if_schema_changed()` — se le colonne del CSV su disco non corrispondono a
   `CSV_FIELDNAMES`, il vecchio viene rinominato `.bak_<timestamp>`. Impedisce di mescolare
   righe prodotte da scoring diversi.
2. `load_analysis_history()` — insieme degli **SHA-256** già presenti nel CSV. Era il bug più
   insidioso: la chiave era il path relativo, e `TEST_SAMPLES/awk_6DAD….exe` (268.800 B)
   copriva `TEST_BIN_PULITI/awk_6DAD….exe` (627.466 B), facendo saltare in silenzio 15 file.
3. Init **una tantum** per batch: `get_yara_rules()` (cache compilata `.yrc`),
   `is_capa_available() + ensure_capa_rules() + ensure_capa_sigs()`, `is_die_available()`.
   Un tool mancante degrada la run, non la blocca.
4. `os.walk` con doppio filtro: estensione in `VALID_EXTENSIONS` **oppure** magic number valido
   — così i campioni rinominati (`.vir`, `.dat`, senza estensione) entrano comunque.
5. Riga `phase1_start` su `tool_diagnostics.jsonl` con **tutta** la configurazione (timeout,
   `DIE_ARGS`, `CAPA_MODE`, `WEAK_SIGNALS_REQUIRED`, `EP_ENTROPY_THRESHOLD`, versioni dei tool).
   È ciò che rende un CSV auto-documentato.
6. CSV aperto in append, **una riga per file con flush immediato**.
7. Al termine: controllo `len(new_results) == len(files_to_process)` → `BATCH INCOMPLETO`
   esplicito, più `_log_phase1_summary`.

### 1.3 Estrazione feature per singolo file (`analyze_with_lief`)

Ordine non casuale — è ordinato per **costo crescente** e per dipendenze:

| # | Step | Perché lì |
|---|---|---|
| a | **Magic number** (B13) | 4 byte. Se non è MZ/ELF → `Parse_Status = not_executable`, score 0, ritorno immediato. Sul set benigno il 19 % erano delta di Windows Update con estensione `.exe` e magic `DCS`: prima venivano passati a YARA prima di essere scartati |
| b | **YARA** (regole compilate, timeout 60 s) | Indipendente dal parsing: funziona anche su header corrotti |
| c | **`lief.parse`** | Se fallisce → `_finish_without_lief()`: il file **non viene scartato**, si classifica con YARA/DIE/capa. Con B5 riceve `packer_sections` e `lief_ok` reali, così un'eccezione tardiva non sostituisce più un segnale FORTE già trovato (es. `UPX0`) con il debole spurio "header non parsabile" |
| d | PE: `Subsystem`, `Total_Exports` | Servono dopo, come **eccezioni** al segnale "pochi import" |
| e | **DIE** `diec.exe -j -u` | 1–4 s. Tre categorie con peso diverso (vedi §3) |
| f | **Loop sezioni** | Entropia (con `.rsrc` escluso), nomi standard/kernel/packer, W+X, dimensioni anomale **solo su sezioni eseguibili**, sezione dell'EP, `EP_Outside_Sections` |
| g | Import/IAT, `Is_DotNet` (`mscoree.dll`), overlay (size + entropia) | |
| h | **`_maybe_run_capa`** | Ultimo perché è il più caro, e perché il modo `lazy` ha bisogno dei risultati di DIE/YARA/sezioni per decidere se saltare |

### 1.4 Dai segnali alla classificazione

`_packing_signals()` produce tre liste. `_classify_packing()` le riduce:

```python
if strong:                          return 100, True          # un forte basta
if len(weak) >= WEAK_SIGNALS_REQUIRED (3):
                                    return 40 + 15*len(weak), True   # ≥ 85, sempre > 70
                                    return min(69, 15*len(weak)), False
```

`PACKING_THRESHOLD = 70` è ormai **cosmetico**: i due rami producono per costruzione valori su
lati opposti della soglia. Lo score serve solo a rendere leggibile il CSV, non decide nulla —
ed è un punto da dichiarare in tesi, perché un lettore che vede "Score 85 %" pensa a un modello
probabilistico che non c'è.

**Precisazione importante su "Packed / Clean / Unknown".** La Fase 1 **non emette una terza
classe**. L'output è binario (`Is_Packed_Label` ∈ {0,1}) più una qualificazione dell'evidenza:

- `Packing_Evidence` = `named` (packer riconosciuto **per nome**: sezione tipica, YARA
  specifico, DIE, capa nominato — B6) · `structural` (forte senza nome) · `weak_only`
  (3+ deboli) · `none`;
- `Parse_Status = not_executable` è un'**esclusione dal perimetro**, non una classe;
- `unknown` esiste solo nella **ground truth** (`ground_truth.json`), dove indica "nessun
  oracolo esterno si è pronunciato": 112 righe che escono dalle metriche.

Sono tre cose diverse e in tesi vanno tenute separate, altrimenti il lettore pensa che il
classificatore si astenga, cosa che non fa mai.

### 1.5 Consegna alla Fase 2

`extract_packed_files()` rilegge il CSV, prende le righe con `Is_Packed_Label == 1`,
ricostruisce i path (relativi, non basename) e costruisce `hints = {path: Die_Packer_Name}`,
passato a `process_packed_files()` per instradare la cascata invece della sequenza cieca
`upx → aspackdie → innounp → emulazione`. **`Packing_Evidence` non è ancora letto dalla
Fase 2**: è prodotto e scritto, ma il routing usa solo l'hint DIE. È lavoro di Fase 2, non un
difetto di Fase 1.

---

## 2. Input e output

### 2.1 `pack_samples.py` — generatore di matrice

**Input (sorgenti master)**

| Sorgente | Etichetta | Ruolo |
|---|---|---|
| `TEST_BIN_PULITI/` | `mingw` | toolchain datate, quasi tutte UPX-abili |
| `E:\DATASET_CLEAN_MS` | `msvc` | System32/SysWOW64 |

**Criteri di ammissione a master**, tutti verificati sul binario via LIEF (`pe_info()`),
nessuno dedotto:

1. estensione `.exe` e `10.000 B < size < 3.000.000 B`;
2. parsabile come `lief.PE.Binary`;
3. **subsystem GUI o CUI** — i NATIVE/EFI/boot sono rifiutati dai packer user-mode
   (`unsupported subsystem`, intercettato nello smoke test su un master MSVC con subsystem 16);
4. **privo di Control Flow Guard** (`dll_characteristics & 0x4000`) — UPX solleva
   `CantPackException: GUARD_CF enabled PE files are not supported`.

Il vincolo CFG è **imposto dallo strumento, non scelto**: solo il 5 % di System32 è UPX-abile
senza `--force` (93/1.990) contro il 94 % dei binari MinGW (88/94). Il prezzo è che il set
master è sistematicamente di toolchain più datate. È da dichiarare come restrizione, ed è
difendibile proprio perché quantificata.

**Determinismo**: `random.Random(seed=20260923)`, `ARCH_TARGET = 30` per architettura,
`MSVC_PER_ARCH = 10` di quota MSVC e il resto da MinGW.

**Output**

- `E:\DATASET_MASTERS\<arch>_<source>_<hash12>.exe` — copie dei master, mai toccate;
- `E:\DATASET_PACKED\<arch>_<source>_<hash12>_<layer>.exe` — un file **distinto** per
  combinazione;
- `E:\DATASET_PACKED\manifest.csv` — colonne `filename, sha256, layers, origin_sha256, arch,
  source, size_in, size_out, generated_at`, riscritto **a ogni campione** (incrementale: una
  interruzione non perde il lavoro), con skip per `filename` già presente.

`origin_sha256` è il pezzo architetturalmente più importante: rende il disegno **appaiato**,
cioè permette il confronto prima/dopo sullo stesso identico binario invece che fra due
popolazioni.

### 2.2 Artefatti di Fase 1 (`Pipeline_Reports/`)

| File | Contenuto | Stato al 23/09 |
|---|---|---|
| `report_analisi_lief.csv` | **49 colonne**, una riga per campione, chiave `SHA256` + `Dataset` | 2.179 righe |
| `pipeline_state.json` | stato per SHA-256; Fase 1 scrive `clean` / `needs_manual_review` | 760 KB |
| `tool_diagnostics.jsonl` | una riga per **invocazione di tool** (comando, rc, durata, stato, testa di stdout/stderr, `banner_at_s`, `probe_s`, `size_mb`) + riga di config + riepilogo | 6,9 MB |
| `pipeline.log` | log unificato Fase 1 + Fase 2, in append | 3,9 MB |
| `ground_truth.json` | manifest per SHA-256 con label e **fonte dell'oracolo** | 2.174 voci |
| `validation_phase1.{json,md}` | matrice di confusione, discriminazione per segnale, sweep soglia, esposizione al non determinismo | |

Colonne del CSV che portano il peso analitico: `Packing_Score_%`, `Is_Packed_Label`,
`Packing_Evidence`, `Strong_Signals`, `Weak_Signals`, `Info_Signals`, `Die_All_Packers`,
`Max_Entropy_No_Rsrc`, `EP_Section_Entropy`, `EP_Section_WX`, `EP_Outside_Sections`,
`Capa_Mode`, `*_Status` per ciascun tool. Le colonne `_Status` sono ciò che permette di dire
"0 decisioni prese sotto timeout" invece di sperarlo.

---

## 3. Tool utilizzati e configurazioni

### 3.1 Ecosistema di analisi

| Tool | Versione | Invocazione | Timeout | Peso del segnale |
|---|---|---|---|---|
| **LIEF** | 1.0.0 (nel `.venv`) | in-process | — | strutturale: sezioni, EP, import/export, overlay, `PT_LOAD` per ELF senza SHT |
| **YARA-Forge** | yara 4.5.4 | cache compilata `yara_forge_compiled.yrc` (48 MB) | 60 s | packer **nominato** = FORTE; generico/anti-analysis = **informativo** |
| **DIE** | 3.21, `diec.exe -j -u` | `subprocess` via `run_external` | 60 s | packer/protector/cryptor/cruncher e installer/sfx = FORTE; `~packer`/`~protection` = DEBOLE |
| **capa** | 9.4.0 (`.venv\Scripts\capa.exe`) | `-r <rules> -s <sigs> -j --os <win\|linux>` | 90 s (600 s in `full`) | **disattivato di default** |

**DIE — le scelte che contano**

- Abbandonato `die-python` (`ModuleNotFoundError: No module named 'die._die'`) per la CLI
  nativa `diec.exe -j`. Non è un ripiego: la CLI è versionabile, citabile e produce JSON
  stabile.
- `-u` (euristiche) tenuto, `-d` (deep scan) **rimosso**: su 46 file non aggiungeva nessun
  rilevamento nominato sui packed (0 differenze su 16) ma faceva dire "protector: VMProtect
  [info `DS`]" a 9 binari MinGW puliti. Le firme marcate `DS` ora sono comunque declassate a
  euristica nel parser.
- `~debug data` esplicitamente ignorata: compariva nel 33 % dei benigni e non riguarda il
  packing.
- **B11**: si conserva `Die_All_Packers` con **tutte** le firme ordinate, non solo la prima. Su
  `awk_6DAD…` e `awk_8515…` DIE riporta `MPRESS; UPX`, cioè esattamente i due layer applicati
  da `pack_samples.py`. Prima il layer UPX veniva buttato in silenzio — su una tesi sul
  multilayer era il dato centrale a sparire.

**capa — il caso più interessante da raccontare in tesi**

L'ottimizzazione è documentata, ma la conclusione è più forte dell'ottimizzazione:

- lo stderr viene normalizzato (via ANSI e riferimenti `common.py:90` che spezzano le frasi) e
  lo streaming si arresta al banner (`stopped_at_banner`) o allo scadere di una finestra
  **proporzionale**, `15 s + 2 s/MB` (`no_banner_probe`). Il banner misurato compare a
  ~1,4 s/MB;
- timeout con `taskkill /F /T`: nessun processo orfano;
- `CAPA_RC_FILE_LIMITATION = 17` riconosciuto come esito valido;
- solo `anti-analysis/packer/*` (escluso `/generic`) conta come packer **nominato**;
  `internal/limitation/*` no — la regola `(internal) .NET file limitation` valeva 5 falsi
  positivi su assembly .NET benigni.

E poi il dato che chiude la questione: **su 189 file capa consumava 1.539 s su 1.599 (96,3 %),
produceva 0 segnali forti e cambiava 0 verdetti**. La causa è strutturale, non di tuning: capa
scrive il JSON su stdout **alla fine**, mentre il banner compare **all'inizio** — l'arresto
anticipato rende per costruzione illeggibile il namespace `anti-analysis/packer/<nome>`, cioè
proprio il segnale forte. Da qui `CAPA_MODE = "off"` come default, `--capa-mode full`
disponibile per un confronto fra tool su un sottoinsieme, e il modo `lazy` **scartato sui
dati** (risparmio misurato 6 %: salta i file economici da 4,6 s e conserva quelli da 17,2 s).
Ogni riga del CSV porta `Capa_Mode`, quindi dice sempre come è nata.

### 3.2 Ecosistema di packing

Il discrimine adottato è **l'esistenza di una CLI**, verificata eseguendo i tool, non leggendo
la documentazione:

| Tool | Versione | CLI | Invocazione in `pack_samples.py` |
|---|---|---|---|
| UPX | 5.1.1 | ✅ | `-9 -f -q` sulla copia, 120 s |
| MPRESS | 2.19 | ✅ | `-q` **in place sulla copia**, 60 s + `taskkill` su timeout |
| VMProtect | 3.10.6 Demo | ✅ console | `VMProtect_Con.exe <in> <out>`, 900 s |
| Themida | 3.2.4.34 | ✅ | `/protect <proj.tmd> /inputfile /outputfile /q /shareconsole`, 1200 s, progetto `.tmd` **per architettura** |
| NSIS | makensis | ✅ | script `.nsi` generato con `SilentInstall silent` + `ExecWait` — è un dropper reale, non un archivio |
| Inno Setup 6 | ISCC | ✅ | script `.iss` generato, `OutputDir` puntato **esattamente** a `out` (serve per i multilayer, dove l'output vive in una temp) |
| PECompact / ASPack | | ❌ | aprono una GUI anche senza argomenti → non automatizzabili |
| PEiD / ExeInfo PE | | ❌ | solo-GUI: **decaduta** l'ipotesi di usarli come oracolo CLI. Resta il loro `userdb.txt` (~4.445 firme testuali) come possibile oracolo semi-indipendente |

Due correzioni trasversali già applicate e da citare: `MPRESS_ARGS = ["-r"]` era commentato
come "overwrite senza backup" ma nell'help di MPRESS 2.19 significa **"do not compress
resources"** — stava riducendo la compressione; e `MULTILAYER[…]["archs"]` limita `UPX+MPRESS`
a x86 (motivazione poi **rivista**, vedi §9.5).

**Packer esclusi e perché** — la motivazione è doppia e va data doppia: FSG, Petite, kkrunchy,
Enigma sono abandonware, quindi c'è il rischio di scaricarli da archivi non ufficiali **e,
soprattutto, l'impossibilità di citarne la provenienza in tesi**. La seconda ragione è quella
che regge in sede di discussione.

---

## 4. Scelte architetturali — il "perché"

### 4.1 Da scoring additivo percentuale a due livelli logici

**Cosa c'era prima.** Una somma di punti percentuali con soglia al 70 %: entropia +20, sezioni
anomale +15, EP sospetto +15, e così via.

**Perché era sbagliato, in ordine di gravità:**

1. **I pesi non erano misurati, erano inventati.** "+20 per entropia alta" non deriva da nessuna
   osservazione. Il documento ora ha la tabella che quei pesi avrebbero dovuto avere: entropia
   ≥ 7.2 discrimina 85 % vs 0 % (lift +84), YARA generico discrimina **−33** (12 % packed
   contro 45 % clean). Un sistema additivo a pesi arbitrari sommava questi due nella stessa
   valuta.
2. **Il modello additivo è falso rispetto al fenomeno.** `UPX0` in una sezione **non è
   probabilistico**: è UPX. Non ha senso che valga "20 punti su 100" e debba trovare compagnia
   per superare una soglia. Simmetricamente, un singolo indizio strutturale debole non dovrebbe
   mai bastare, per quanto lo si pesi. La struttura reale del problema è *disgiunzione di
   condizioni sufficienti, OR congiunzione di condizioni necessarie insieme* — che è
   esattamente la forma forte/debole.
3. **Il sistema additivo confondeva due nozioni diverse.** Un punteggio percentuale suggerisce
   una probabilità; qui non c'è nessuna probabilità, c'è una regola. La distinzione `named` /
   `structural` / `weak_only` porta l'informazione che serve davvero alla Fase 2 — *quanto è
   affidabile questo verdetto e che strumento merita* — che un numero unico comprimeva via.
4. **Non era tarabile.** Con un solo numero, correggere un falso positivo significa toccare un
   peso, il che sposta tutte le altre decisioni in modo non tracciabile. Con due livelli il
   parametro tarabile è **uno solo** (`WEAK_SIGNALS_REQUIRED`) e il suo effetto è misurabile per
   sweep — cosa che è stata fatta, con un risultato non banale: a 2 → 142 FP, **a 3 → 0 FP /
   0 FN**, a 4 → 4 FN. E la nota metodologica che l'accompagna vale più della tabella: **prima**
   delle correzioni lo sweep indicava 4 come ottimo (23 FP a soglia 3 contro 7 a soglia 4).
   Alzare la soglia avrebbe **mascherato segnali difettosi al prezzo del recall**; correggere le
   cause ha reso 3 l'ottimo. È il modo giusto di usare un iperparametro: come diagnostico, non
   come cerotto.

**Cosa resta da dire in tesi.** Lo score non è più un modello: `min(100, 40+15n)` produce sempre
≥ 85 e l'altro ramo sempre ≤ 69. Va presentato come un indicatore di leggibilità, non come una
confidenza. E la conseguenza pratica è che **non si può tracciare una curva ROC/PR**: l'output è
binario. È il punto B14 nei rimandabili, ed è l'unica cosa che una commissione potrebbe chiedere
e che oggi non c'è.

### 4.2 Definizione di "packed" puramente strutturale

> Un eseguibile è `packed` quando presenta un'alterazione strutturale — compressione, cifratura,
> offuscamento, wrapping SFX/installer o protezione vendor — che rende il codice originale non
> direttamente analizzabile via analisi statica. **Mai in base alla natura malevola o
> all'intento.**

**Perché è la scelta corretta, non un compromesso:**

1. **È l'unica definizione osservabile.** L'intento non è una proprietà del file. Se un malware
   comprime per eludere l'analisi e un installer comprime per ridurre le dimensioni, il PE
   risultante è alterato allo stesso modo e fa scattare le stesse metriche. Una regola che li
   distinguesse dovrebbe conoscere qualcosa che l'analisi statica non vede — cioè sarebbe una
   regola su nomi e vendor travestita da regola strutturale.
2. **È l'unica che non richiede eccezioni.** Il momento in cui aggiungi "ma se è firmato
   Microsoft allora non è packed" hai iniziato a mantenere una lista di casi speciali, e ogni
   caso speciale è overfitting che dovrai difendere. **La stessa metrica che intercetta Themida
   intercetta Warbird** — e il fatto che non sia stata scritta una riga per gestire Warbird è la
   prova che la regola è generale.
3. **Il caso Warbird è la dimostrazione, non il problema.** I quattro binari di licensing
   Windows hanno `.text` a entropia 7,19–7,70 contro 6,28 di `notepad.exe` sulla stessa
   macchina, e `sppsvc.exe` ha quattro sezioni `?g_Encry…` che nessun compilatore produce.
   **DIE non li nomina** (`Die_Packer_Match = NO`, nessun nome di packer): è la prova, su campioni
   non scelti da noi, che i segnali strutturali intercettano casi dove le firme sono cieche.
   **Correzione del 01/10/2026 (§24.5):** qui era scritto *«il rilevamento viene interamente dai
   segnali strutturali»*, e la misura lo smentisce. Il verdetto è `weak_only` su tre deboli, di cui
   due strutturali e uno dato dall'euristica *generica* di DIE; senza quest'ultima scendono a 2 e
   passano sotto soglia. Nessuna firma li nomina — questo resta vero ed è il punto — ma il
   rilevamento non è interamente strutturale.
4. **È allineata all'obiettivo della pipeline.** L'output della Fase 1 non è un giudizio morale:
   è *"questo file va mandato alla Fase 2 oppure no"*. Un installer legittimo **va** mandato a un
   estrattore, un binario Warbird **va** dichiarato fuori portata. La definizione strutturale è
   esattamente la domanda che il sistema deve rispondere.

**Il prezzo, e la mitigazione obbligata.** La classe `packed` diventa eterogenea, quindi le
metriche vanno **sempre riportate scomposte** nelle tre sotto-classi (packer terze parti /
installer-SFX / protezione vendor). Su un corpus di software reale gli installer legittimi
sommergerebbero numericamente i packer, che sono l'oggetto della tesi. Oggi questa scomposizione
**non è ancora implementata** in `validate_phase1.py` — è stimata in ~10 righe ed è la cosa più
urgente prima di generare la tabella finale, perché senza quella la matrice a quattro celle è
tecnicamente corretta e retoricamente fragile.

### 4.3 Copie pulite invece di reverse-unpacking

La versione precedente packava **in place**, quindi un multilayer dipendeva dal pack precedente e
per rigenerare serviva "spacchettare" — cioè far tornare indietro un'operazione **non invertibile
in generale**.

Le ragioni per cui l'abbandono è corretto:

1. **Il reverse-unpacking risolve un problema che la copia elimina.** Ripristinare un binario
   impacchettato è il problema centrale della *tesi*: usarlo come utility di supporto per
   costruire il dataset di validazione significa far dipendere la correttezza della ground truth
   dalla correttezza di ciò che si sta misurando. **Circolarità metodologica pura.**
2. **Il ripristino sarebbe verificabile solo con la ground truth che deve produrre.** Neanche
   `upx -d` garantisce il byte-identico su ogni build; MPRESS, VMProtect e Themida non hanno
   inverso. `apply_stack()` invece parte sempre dal master intatto: `cur = master["path"]`, ogni
   strato scrive un file nuovo, gli intermedi vengono rimossi e **l'originale non viene mai
   toccato**.
3. **Rende la generazione idempotente e riavviabile.** Il manifest salta per `filename`, quindi
   interrompere e rilanciare è sicuro. Con l'in-place, un'interruzione a metà lasciava il master
   in uno stato indeterminato — packato a un layer e indistinguibile da un master.
4. **Rende indipendenti le celle della matrice.** `UPX+MPRESS` e `MPRESS` da soli partono
   entrambi dal master pulito, quindi il confronto fra celle è un confronto fra trattamenti, non
   una catena dove l'errore si propaga.
5. **Costo reale: disco.** ~450 campioni con Themida a +518 %/+703 % e Inno a +666 %/+776 %. È il
   prezzo giusto da pagare per una label certa al 100 %.

L'unica eccezione al "non toccare l'originale" è MPRESS, che lavora in place **ma sulla copia di
destinazione** (`shutil.copy2(src, out)` poi `mpress -q out`) — invariante rispettata.

---

## 5. Risultati raggiunti — lettura critica

### 5.1 La matrice (stato al 23/09/2026)

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** | TP = 26 | FN = 0 |
| **reale clean** | FP = 0 | TN = 2041 |

Precision 1,000 · Recall 1,000 · F1 1,000 su 2.067 campioni etichettati (2.179 righe, 112
`unknown` esclusi). 0 decisioni prese con un tool troncato da timeout.

**La lettura asimmetrica è quella giusta, e va difesa:**

- 0 FP su 2.041 clean → limite superiore al 95 % sul tasso di FP ≈ **0,15 %**. Questa metà è
  **solida**.
- 0 FN su 26 packed → limite superiore sui FN ≈ **11,5 %**. Questa metà **non lo è**. La
  formulazione corretta in tesi è *"nessun falso negativo osservato su 26 campioni"*, **mai**
  "recall del 100 %".

**Aggravante non quantificata nei documenti.** Scomponendo i 26 packed per famiglia:

| famiglia | n | fonte |
|---|---|---|
| UPX | **13** | `upx -t` (9) + PMA (2) + `pack_samples` (1) + multilayer (2) |
| Microsoft Warbird | 4 | verifica manuale |
| MS Cabinet SFX (`wextract`) | 2 | verifica manuale |
| MPRESS (secondo layer) | 2 | `pack_samples` |
| PlayReady DRM | 1 | verifica manuale |
| (Win)Upack · FSG 1.0 · PECompact · ASPack | 1 ciascuno | PMA |

Cioè: **metà del supporto packed è UPX, e quattro famiglie hanno supporto 1**. Il limite
dell'11,5 % è sul *tasso aggregato*; **per famiglia il supporto è statisticamente nullo**. Non è
un errore nel calcolo — è che il calcolo risponde a una domanda meno interessante di quella vera.

### 5.2 Come sono stati risolti i 23 falsi positivi iniziali

| Causa | n | Tipo di correzione |
|---|---|---|
| **binari kernel-mode e boot** (`ntoskrnl`, `ntdll`, `winload`, `winresume`, `hvax64/hvix64`, `tcblaunch`, `kd_*`, `mcupdate`, `WinSAT`) | 13 | **codice**: famiglie `PAGE*`/`INIT*` riconosciute come nomi di sezione standard; eccezione al segnale "pochi import" per subsystem NATIVE/BOOT e per binari con export table consistente |
| **entropia nelle RISORSE, non nel codice** (`wermgr` x64/x86, `auditpolmsg`) | 3 | **codice**: `.rsrc` escluso dal calcolo che alimenta il segnale (`Max_Entropy_No_Rsrc`), mentre `Max_Section_Entropy` resta come dato informativo |
| SFX Microsoft (`wextract` x64/x86) | 2 | **label**: veri positivi per la definizione adottata |
| protezione vendor (`sppsvc`, `SppExtComObj`, `ClipUp`, `GenValObj`, `PlayReady`) | 5 | **label**: veri positivi per la definizione adottata |

Progressione: 23 FP (1,12 %) → 4 (0,20 %) → **0**, **senza perdere un solo vero positivo in
nessuno stadio**. E un file (`d3d10ref.dll`, 43 export) si è risolto da solo grazie alla regola
sugli export.

**Quello che rende questa sezione difendibile** è la distinzione fra le due colonne "tipo": 16 su
23 sono correzioni al **codice** basate su una proprietà generale (*ntdll ha 2.433 export e 0
import per costruzione*, non *"escludi ntdll"*), 7 su 23 sono **riclassificazioni di label** che
derivano direttamente dalla definizione adottata al §4.2, non da convenienza. Se tutti e 23
fossero stati risolti nel codice, l'accusa di overfitting sarebbe legittima.

Due lezioni metodologiche da tenere nel testo:

- **B7** — la formulazione iniziale era "`EP_Section == UNKNOWN` produce un segnale". È falsa:
  `UNKNOWN` vale anche per le DLL con `AddressOfEntryPoint = 0`, che sono il caso normale.
  Implementata così avrebbe prodotto **1.051 falsi positivi** proprio mentre si correggevano i
  falsi positivi. La versione corretta distingue EP con RVA non nullo fuori dalle sezioni (2
  file) da EP nullo di DLL (1.051). La contro-prova è ora un test permanente.
- **B8 non corretto di proposito** — promuovere "pochissimi import" a forte creerebbe un FP su
  `Lab03-01`, che ha un solo import (`ExitProcess`) ma il cui EP disassembla a
  `mov eax,0x400400; call eax` verso codice in chiaro in `.data` (entropia 6.65): risoluzione
  dinamica degli import, non compressione. Un `expectedFailure` con la motivazione nella
  docstring vale più di una correzione approssimativa.

### 5.3 Controllo negativo

I capitoli 15–17 di PMA (anti-disassembly, anti-debugging, anti-VM) contengono campioni che il
libro conferma **non pacchettizzati**. La Fase 1 li classifica tutti e 8 puliti, 7 con score 0. È
la risposta **misurata** alla domanda *"il rilevatore riconosce il packing o riconosce che il file
è difficile da analizzare?"* — su campioni scelti da terzi. È il controllo negativo più forte
disponibile, e va in tesi con quel framing.

### 5.4 Prestazioni

189 file: **1.598,9 s → 57 s (28×)**, e decisioni con un tool troncato da timeout **73/189 (39 %)
→ 0**. Il secondo numero conta più del primo: significa che l'accelerazione non è stata comprata
tagliando analisi a metà.

### 5.5 Smoke test della nuova matrice

15 campioni (1 master x86 + 1 x64), **0 fallimenti**, tutti rilevati packed dalla Fase 1 (10
`named`, 2 `structural`, 2 `weak_only`). I due risultati di valore per la tesi:

1. **VMProtect x86 non viene nominato da DIE e viene comunque intercettato.** Scatta *"stub
   strutturale: EP in sezione ad alta entropia (H = 7.82) e sezioni eseguibili
   svuotate/sproporzionate"*. VMProtect 3.x randomizza i nomi di sezione (`._\`a`, `.)r>`,
   `.5@"` — non stampabili) e `.text` esce con `raw = 0`, quindi le firme che cercano
   `.vmp0`/`.vmp1` falliscono. **Label certa al 100 %, perché il campione è stato generato
   internamente**: è la prova più forte disponibile del perché servano i segnali strutturali
   accanto alle firme.
2. **Asimmetria x86/x64 di DIE sullo stesso tool.** Stesso VMProtect 3.10.6, stesse impostazioni:
   l'x64 viene riconosciuto, l'x86 no. La copertura delle firme non è uniforme fra architetture —
   dato pubblicabile, e poco documentato altrove.

**Limite da dichiarare sui campioni VMProtect:** senza file di progetto VMProtect avvisa
`[Warning] Functions for protection not selected` e applica **solo** lo strato di packing, non la
virtualizzazione (che richiede la marcatura delle funzioni nel sorgente). I campioni esercitano la
compressione/protezione, non la VM. Da scrivere esplicitamente, altrimenti "abbiamo testato
VMProtect" è sovra-dichiarato.

---

## 6. Rilievi critici dall'ispezione del run — non presenti nei documenti

> Rilevati durante il run in corso (56 master, 236 campioni al momento dell'ispezione).
> I numeri definitivi sono nella Parte 2.

### 6.1 🔴 Due master sono **già packati con UPX** — contaminazione di label

> ⚠️ **Superato da §15:** i master già pacchettizzati sono risultati **tre**, non due.

```
x86_mingw_2e1adf481ac0.exe → sezioni ['UPX0', 'UPX1', '.rsrc']
x86_mingw_befa024422b3.exe → sezioni ['UPX0', 'UPX1', '.rsrc']
```

Sono `NBHextract_2E1ADF…` e `RAIU_BEFA02…` di `TEST_BIN_PULITI` e — questo è il punto — **sono
già etichettati `packed` in `ground_truth.json`** con fonte `upx -t`. Sono due dei 26 packed.

`pe_info()` filtrava su PE / subsystem / CFG / dimensione e **non verificava che il master fosse
pulito**. Conseguenze:

- i campioni derivati hanno un `layers` sbagliato: `…_Themida.exe` è in realtà `UPX + Themida`,
  `…_Inno.exe` è `UPX + Inno`. La label binaria `packed` resta corretta, ma **il layer è la
  variabile indipendente di una tesi sul multilayer packing**;
- `origin_sha256` punta a un binario già packato, quindi per quei campioni il **disegno appaiato
  prima/dopo è invalidato**;
- UPX rifiuta correttamente quei master (`AlreadyPackedException: already packed by UPX`),
  quindi la cella UPX manca, e con essa `UPX+MPRESS` e `UPX+NSIS`.

### 6.2 🟠 Assembly .NET AnyCPU etichettati `x86`

`pe_info()` derivava l'architettura da `b.header.machine`, che per un assembly **AnyCPU vale
I386** anche quando il binario vive in System32 a 64 bit. Quindi:

- una parte significativa dei master "x86" non è x86: è AnyCPU. E l'architettura è **il
  confondente dichiarato e misurato** (packed 67 % x86 vs clean 39 %): sporcare proprio
  quell'asse è il danno peggiore;
- spiega i master con sole 4 celle su 8: UPX rifiuta (`CantPackException: .NET files are not yet
  supported`) e MPRESS pure sui master nativi, quindi cadono UPX, UPX+MPRESS, UPX+NSIS;
- **la quota MSVC è di fatto collassata**: la gran parte dei master MSVC x86 sono .NET. C'è una
  ragione strutturale interessante da scrivere in tesi: *nel System32 moderno, "MSVC senza CFG"
  ≈ "assembly .NET", perché il CFG è default nel codice nativo ma non si applica al managed*.

**Rovescio della medaglia, positivo:** quei master × i packer che li accettano producono
**campioni .NET packed a label certa**, in un dataset che ne ha **zero**. Non colmano il blind
spot (sono wrapper nativi Themida/VMProtect/NSIS/Inno, non offuscatori .NET tipo ConfuserEx) ma
sono un caso di test reale per l'eccezione `Is_DotNet`.

### 6.3 🟡 56 master invece di 60

Reale: **30 x86 (20 mingw + 10 msvc) + 26 x64 (23 mingw + 3 msvc)**. Il pool x64 idoneo è
esaurito: MinGW in `TEST_BIN_PULITI` ne offre 23 e MSVC senza CFG solo 3 (il documento diceva 7 —
il filtro GUI/CUI aggiunto dopo ne ha tolti altri). Da dichiarare, o da correggere allargando la
sorgente MinGW.

### 6.4 🟡 Manca l'importer dal nuovo manifest

`build_ground_truth.py:53` legge ancora `PACKING_REPORT = <Packing>/report_compressione.json`,
formato della **vecchia** `pack_samples.py`. Il nuovo generatore scrive
`E:\DATASET_PACKED\manifest.csv`. Finché non si aggiunge `import_packing_matrix()`, i campioni
**non entrano nella ground truth** e la matrice di confusione resta a 26 packed.

**Nota di riproducibilità:** `Unpacking/Packing/config/` è untracked, e contiene
`pma_labels.json` e `manual_labels_clean_ms.json` — che sono **input di ground truth**, non
configurazione. Finché sono fuori dal repo, `validate_phase1.py` non è riproducibile da un clone.
(`extraction.py` è correttamente in `.gitignore`: contiene la API key MalwareBazaar in chiaro.)

---

## 7. Valutazione finale, blind spot e step mancanti

### 7.1 Giudizio sull'affidabilità

**Il lato clean è pronto per la tesi.** 0 FP su 2.041 campioni con oracolo esterno (Authenticode
Microsoft), limite superiore 0,15 %, e — più importante del numero — le quattro categorie di FP
iniziali sono state risolte con correzioni **strutturali** (nomi di sezione kernel, subsystem
NATIVE/BOOT, export table, esclusione `.rsrc`), non con liste di eccezioni. Il fatto che nessuna
correzione abbia perso un vero positivo in nessuno dei tre stadi è la prova che non si è barattato
recall per precision.

**Il lato packed non è pronto.** Non è "26 campioni", è "26 campioni di cui 13 UPX e 4 famiglie
con supporto 1". Il run della matrice lo risolve — se i difetti §6.1 e §6.2 vengono corretti
**prima** di importare le label, altrimenti si importa materiale con `layers` e `arch` sbagliati
dentro la ground truth "certa al 100 %", che è l'unica cosa che non ci si può permettere di
sporcare.

**Il lato metodologico è la parte più forte del lavoro.** Gli oracoli esterni sono realmente
indipendenti dai segnali misurati (`upx -t` è UPX stesso, Authenticode è Microsoft, PMA è un libro
di terzi, `pack_samples.py` è il fatto di aver eseguito il packer). `validate_phase1.py` si rifiuta
di stampare metriche a supporto zero. `build_ground_truth.py` non lascia che nessuna scansione
assegni `clean`, solo `unknown`. Il controllo negativo su PMA 15–17 risponde all'obiezione più
ovvia. I 38 test con 4 `expectedFailure` documentano i bug noti invece di nasconderli.

### 7.2 Blind spot dichiarati

| Blind spot | Evidenza | Raccomandazione |
|---|---|---|
| **Assembly .NET offuscati** | 28 clean, 0 packed. L'eccezione `Is_DotNet` **sopprime** l'unico segnale che potrebbe scattare ("pochi import"), e i packer .NET non producono le firme strutturali cercate → falsi negativi **attesi per costruzione** | Misurare con **ConfuserEx** e poi **dichiarare il .NET fuori perimetro con i dati a supporto**. Aggiungere un ramo `dnlib` farebbe esplodere lo scope di una triennale |
| **Go / Rust** | 0 campioni. Linking statico, `.text` enormi, import minimi, sezioni atipiche: colpiscono **tre segnali deboli insieme** → è il candidato più probabile a rompere `WEAK_SIGNALS_REQUIRED = 3` | **Il test più severo disponibile**, e il più economico: compilare 10 binari Go e 10 Rust in proprio. Label certa, costo un'ora |
| **Packer x86-only mancanti (FSG, ASPack, PECompact, Petite, kkrunchy)** | FSG documentato da `Lab18-02` (label confermata dal libro): **né DIE né YARA producono un nome** | Non recuperabili (abandonware, provenienza non citabile). Il blind spot resta, **documentato da un campione con label di terzi** |
| **Packer x64 sottorappresentati** | packed: 16 x86 / 8 x64. Molti packer classici esistono solo a 32 bit | La matrice corregge parzialmente (Themida/VMProtect/UPX/MPRESS x64) |
| **Installer legittimi** | `DIE_INSTALLER_TYPES` è segnale **FORTE** verificato su **2 soli file** (`wextract` x64/x86) | `winget download` per una decina di installer reali. Nota di perimetro: gli **MSI non sono PE** (contenitori OLE) → usciranno `not_executable` |
| **Goodware non-Microsoft** | Il set clean è **100 % System32**: la classe negativa facile | MSYS2/Cygwin, wheel Python con `.pyd`, e soprattutto Go/Rust |
| **FLARE VM (800 file)** | Copiati, **mai analizzati**. Non possono fare da classe negativa (contengono i packer stessi, unpacker, PE editor, tool commerciali protetti) | Analizzarli come **hard set** e fare l'analisi qualitativa dei FP: è il capitolo sui tool di RE legittimi ma protetti |
| **ELF** | `type object 'ARCH' has no attribute 'x86_64'`: gli ELF vengono trattati come "Windows 64-bit" e salvati come `.exe` | Bug noto. Se l'ELF non entra nello scope, **dichiararlo fuori perimetro** invece di lasciarlo mezzo rotto |
| **Nessuno score continuo** | Output binario → **nessuna curva ROC/PR** | B14 |

### 7.3 Step mancanti prima della Fase 2 — in ordine

**Bloccanti (senza questi la Fase 2 ottimizzerebbe contro una misura sbagliata):**

1. **Correggere `pe_info()`** — rifiutare master già packati (§6.1) e marcare gli AnyCPU (§6.2).
   ✅ *fatto, vedi §10.*
2. **`import_packing_matrix()` in `build_ground_truth.py`** — leggere
   `E:\DATASET_PACKED\manifest.csv` come label `packed` **certe**, portando `layers`,
   `origin_sha256`, `arch`, `source` nel manifest. Senza questo il run della matrice non produce
   nessuna metrica. *Specifica in §11.*
3. **Metrica scomposta in `validate_phase1.py`** — per sotto-classe (packer terze parti /
   installer-SFX / vendor) e per architettura. È la mitigazione obbligata della definizione al
   §4.2, non un abbellimento.
4. **Un unico run di Fase 1 su TUTTO** — matrice + wild + contro-campione + FLARE + i 2.179
   esistenti — e matrice di confusione finale, con `--reanalyze` se lo schema è cambiato.

**Per il set "in the wild" (MalwareBazaar):**

5. **Stato attuale reale**: `upx` 45, `vmprotect` 60, `themida` 13, `aspack` 3, **`pecompact` 0**,
   `_senza_tag` 60 → **181 campioni**, non i 50-60 per tag pianificati. Themida e ASPack sono
   sotto quota e PECompact è vuoto. È una **proprietà reale del panorama** (packer obsoleti
   spariti dalla circolazione), da riportare come dato, non da forzare.
6. **Le label restano `proposte`, mai ground truth.** L'opzione oracolo PEiD/ExeInfo è **decaduta**
   (entrambi solo-GUI); resta l'opzione A (nome cartella = tag) e, volendo, la lettura dei loro
   `userdb.txt` (~4.445 firme testuali) come oracolo semi-indipendente da DIE/YARA.
7. **I due rischi vanno dichiarati, non risolti**, perché non sono risolvibili:
   - **circolarità** — molti tag nascono da strumenti della famiglia di DIE/YARA, che la Fase 1
     usa come fonti FORTI: si rischia di misurare l'accordo fra due istanze dello stesso
     strumento;
   - **distorsione di selezione** — un file è taggato `fsg` perché *qualcuno lo ha riconosciuto*;
     gli FSG non riconosciuti non sono taggati e non entrano mai nel campione, **gonfiando il
     recall**. Il contro-campione `_senza_tag` (60 file) serve esattamente a **misurare** quanto
     si sta perdendo invece di subirlo.
   - Attenzione al tag `upx-dec` = **già decompresso**, non packed. `POISON_TAGS` in
     `extraction.py` lo filtra già.
8. **Framing corretto:** il set wild risponde a *"quali famiglie la pipeline non sa nominare"*,
   **non** misura il recall. Il recall lo misura solo la matrice in-house.

**Rimandabili senza impatto sulla validità:** `config/tools.json` + preflight interprete; score
continuo per ROC/PR (B14); i 112 `unknown` residui; l'ELF.

**Sulla Fase 2:** la Fase 1 sta già producendo `Packing_Evidence` che nessuno legge. Quando si
aprirà la Fase 2, il primo intervento a costo quasi nullo è instradare `weak_only` → nessuna
emulazione e `Die_Packer_Type ∈ {installer, sfx}` → estrattore, non Qiling.

---
---

# PARTE 2 — Run completo, fix e importer

---

## 8. Metriche del run completo di `pack_samples.py`

Run terminato (nessun processo residuo). **365 campioni generati**, manifest con 365 righe,
365 file su disco: **nessuna discrepanza fra manifest e filesystem**.

### 8.1 Resa per cella

| layer | generati | attesi | resa |
|---|---|---|---|
| Themida | 56 | 56 | **100 %** |
| NSIS | 56 | 56 | **100 %** |
| Inno | 56 | 56 | **100 %** |
| VMProtect | 51 | 56 | 91 % |
| MPRESS | 50 | 56 | 89 % |
| UPX | 44 | 56 | 79 % |
| UPX + NSIS | 44 | 56 | 79 % |
| UPX + MPRESS | 8 | 30 (solo x86) | **27 %** |
| **totale** | **365** | **422** | **86,5 %** |

### 8.2 Composizione

| asse | valori |
|---|---|
| architettura | 186 x86 · 179 x64 — **bilanciato** |
| toolchain | 295 mingw · 70 msvc |
| .NET (AnyCPU) | **40 campioni** da 9 master managed |
| master | 56 (30 x86, 26 x64) |

### 8.3 Rapporto di compressione/espansione medio

| layer | size_out / size_in |
|---|---|
| UPX + MPRESS | 41 % |
| MPRESS | 47 % |
| UPX | 48 % |
| UPX + NSIS | 83 % |
| NSIS | 104 % |
| VMProtect | 1.019 % |
| Themida | 2.623 % |
| Inno | 3.211 % |

### 8.4 Impatto sulla ground truth

Il lato packed passa da **26** a **391** campioni a label certa (26 + 365). Il limite superiore
al 95 % sui falsi negativi scende da **~11,5 %** a **~0,8 %** — a patto che i campioni vengano
importati e che la Fase 1 li classifichi tutti correttamente (da verificare con il run di Fase 1,
non assunto).

---

## 9. Cosa è andato storto, e quanto è critico

57 celle mancanti su 422. Causa per causa, tutte **riprodotte eseguendo i tool**, non dedotte.

### 9.1 🔴 CRITICO — 2 master erano già packati con UPX → 8 campioni con `layers` sbagliato

> ⚠️ **Superato da §15:** un terzo master (`UHARC04`, UPX con nomi di sezione azzerati)
> è sfuggito al filtro sui nomi. I suoi 4 campioni sono ancora da correggere.

| campione | `layers` dichiarato | `layers` reale |
|---|---|---|
| `x86_mingw_2e1adf481ac0_VMProtect.exe` | VMProtect | **UPX + VMProtect** |
| `x86_mingw_2e1adf481ac0_Themida.exe` | Themida | **UPX + Themida** |
| `x86_mingw_2e1adf481ac0_NSIS.exe` | NSIS | **UPX + NSIS** |
| `x86_mingw_2e1adf481ac0_Inno.exe` | Inno | **UPX + Inno** |
| `x86_mingw_befa024422b3_VMProtect.exe` | VMProtect | **UPX + VMProtect** |
| `x86_mingw_befa024422b3_Themida.exe` | Themida | **UPX + Themida** |
| `x86_mingw_befa024422b3_NSIS.exe` | NSIS | **UPX + NSIS** |
| `x86_mingw_befa024422b3_Inno.exe` | Inno | **UPX + Inno** |

I due master sono `NBHextract_2E1ADF…` e `RAIU_BEFA02…`, entrambi **già etichettati `packed` in
`ground_truth.json`** (oracolo `upx -t`). Sono due dei 26 packed originali.

**Perché è critico:** la label binaria `packed` resta corretta, ma `layers` è la variabile
indipendente di una tesi sul **multilayer packing**, e `origin_sha256` punta a un binario non
pulito → il disegno appaiato prima/dopo salta per quegli 8.

**Entità:** 8 campioni su 365 = **2,2 %**. Contenuto, ma va rimosso prima dell'import, non dopo.

### 9.2 🟠 MEDIO — 9 master sono assembly .NET, e la detection via `mscoree` ne mancava uno

`x64_msvc_3c4de3f013d4` è .NET (data directory `CLR_RUNTIME_HEADER` presente) **ma non importa
`mscoree.dll`**: gli assembly a 64 bit e quelli più recenti possono non avere alcuna import table.

**Questo è anche un bug latente di Fase 1**: `header_elf_lief.py` rileva `Is_DotNet` solo
dall'import di `mscoree.dll`. Per un assembly managed senza import table, `Is_DotNet = NO` →
l'eccezione al segnale "numero import basso (<20)" **non scatta** → il file accumula un segnale
debole che non dovrebbe avere. Sul corpus clean attuale non ha prodotto FP (0 FP misurati), ma è
una bomba a orologeria sul set .NET futuro.

**Conseguenze sul dataset:**

- UPX li rifiuta tutti (`CantPackException: .NET files are not yet supported`) → perse le celle
  UPX, UPX+NSIS, UPX+MPRESS;
- **MPRESS invece li packa**: 9 campioni `MPRESS` su master .NET esistono nel manifest;
- **40 campioni .NET packed a label certa** ora esistono, in un dataset che ne aveva **zero**.
  Non colmano il blind spot (sono wrapper nativi, non offuscatori .NET) ma sono il primo
  materiale di test per l'eccezione `Is_DotNet`;
- gli AnyCPU hanno `machine = I386` → etichettati `arch = x86` pur non essendo binari a 32 bit,
  cioè **sporcano l'asse architettura, che è il confondente dichiarato**.

### 9.3 🟢 NON CRITICO — VMProtect non risolve le dipendenze .NET

5 fallimenti VMProtect, tutti su master .NET. Messaggio riprodotto:

```
Loading x86_msvc_0be7f413037a.exe... 100%
[Error] Can't resolve assembly "Microsoft.Uev.Common, Version=10.0.0.0, ..."
```

**Causa:** il master è stato copiato in `E:\DATASET_MASTERS`, **fuori dalla directory dove vivono
le sue dipendenze** (System32). VMProtect, per un assembly managed, deve risolvere i riferimenti.
È un artefatto della copia, non un limite del tool: i 4 .NET self-contained sono stati protetti
senza problemi.

**Rimediabile** copiando anche le dipendenze, ma non ne vale la pena: 4 campioni VMProtect .NET
esistono già.

### 9.4 🟢 NON CRITICO — rifiuti legittimi dei packer

| causa | celle perse | messaggio riprodotto |
|---|---|---|
| `x86_mingw_a45c6f7da7d9` non comprimibile | 4 | `NotCompressibleException` |
| MPRESS rifiuta 3 master nativi | 6 | `rc=10`, file invariato, nessun messaggio |

Sono proprietà dei singoli binari (troppo piccoli o già densi). Nulla da correggere.

### 9.5 🟠 DA CORREGGERE NELLA DOCUMENTAZIONE — la motivazione di `UPX+MPRESS` x86-only era sbagliata

Il documento afferma: *"MPRESS si **blocca** su un x64 già compresso con UPX"*, e su questa base
`MULTILAYER` limita la combinazione a x86.

**Rimisurato eseguendo i tool:**

| test | esito reale |
|---|---|
| MPRESS su x64 UPX-compresso (3 campioni) | `rc = 7` / `rc = 9`, **in 0 secondi**, nessun file scritto |
| MPRESS su x86 UPX-compresso | fallisce su **11 dei 19** tentati (`rc = 7`) |

**Quindi:** MPRESS **non si blocca mai** — esce subito con un codice di rifiuto. E il rifiuto
**non dipende dall'architettura** ma dall'input già compresso: fallisce anche sul 58 % degli x86.
La restrizione x86-only resta difendibile come scelta di economia (evita 26 tentativi a resa
attesa bassa), ma la motivazione scritta era falsa. Il commento nel codice è stato corretto con la
misura reale; per tentare anche gli x64 basta aggiungere `"x64"` alla tupla — il costo è ~0 s per
fallimento.

### 9.6 Riepilogo di criticità

| # | Problema | Campioni toccati | Critico | Azione |
|---|---|---|---|---|
| 9.1 | master già UPX | 8 (2,2 %) | 🔴 **Sì** | eliminare prima dell'import |
| 9.2 | .NET AnyCPU etichettati x86 + `Is_DotNet` incompleto | 40 (11 %) | 🟠 Medio | colonna `is_dotnet` aggiunta; fix `Is_DotNet` in Fase 1 da valutare |
| 9.3 | VMProtect su .NET senza dipendenze | 5 celle perse | 🟢 No | dichiarare |
| 9.4 | rifiuti legittimi dei packer | 10 celle perse | 🟢 No | dichiarare |
| 9.5 | motivazione `UPX+MPRESS` errata | 0 | 🟠 Documentale | commento corretto |

**Verdetto complessivo: il run è riuscito.** 365 campioni a label certa, 86,5 % di resa, asse
architettura bilanciato, nessuna discrepanza manifest/disco. L'unico difetto che invalida dei dati
tocca 8 campioni su 365 ed è circoscritto e rimovibile.

---

## 10. Fix applicato a `pe_info()`

File: `scripts/pack_samples.py`. Backup del file originale nello scratchpad di sessione.

### 10.1 Cosa è cambiato

**Firma:** `pe_info(path)` ritorna ora `(usable, arch, has_cfg, flags)` invece di
`(usable, arch, has_cfg)`, con `flags = {"packed": <nome sezione o None>, "dotnet": bool}`.

**Tre funzioni nuove:**

| funzione | cosa fa |
|---|---|
| `_sec_name(section)` | nome di sezione **sempre** `str`. LIEF restituisce `bytes` quando il nome non è UTF-8 valido — esattamente il caso di VMProtect 3.x, che randomizza i nomi con byte non stampabili. Senza normalizzare, `.startswith()` solleva `TypeError` e il controllo fallirebbe proprio sui file che deve intercettare (è lo stesso bug che in Fase 1 faceva sparire 2 file su 16) |
| `_already_packed(binary)` | ritorna il nome della sezione se una qualunque sezione ha un prefisso da packer noto (`PACKER_SECTION_PREFIXES`, 16 prefissi, tabella allineata a `header_elf_lief.py` ma **duplicata di proposito** per tenere il generatore indipendente dalla pipeline) |
| `_is_dotnet(binary)` | test sulla data directory **`CLR_RUNTIME_HEADER`**, con fallback sull'import di `mscoree.dll`. È la correzione del difetto §9.2 |

**`gather_candidates()`** ritorna ora `(cells, rejected)`: scarta i master già packati e **conta i
motivi di scarto**, così la selezione è ispezionabile invece che silenziosa.

**`select_masters()`** stampa il riepilogo degli scarti e la lista dei master già packati, e porta
`dotnet` dentro il dict del master.

**Manifest:** nuova colonna **`is_dotnet`** (posizione 7, dopo `source`). `load_manifest()`
**fa il backfill** delle righe scritte prima della modifica, leggendo il master corrispondente:
senza il backfill la colonna resterebbe vuota per tutti i 365 campioni già su disco, cioè
inutilizzabile senza rigenerare la matrice.

**Commento `MULTILAYER`:** riscritto con la misura reale del §9.5.

### 10.2 Verifica eseguita

```
x86_mingw_2e1adf481ac0   usable=True arch=x86 cfg=False packed='UPX0'  dotnet=False   ← intercettato
x86_msvc_0be7f413037a    usable=True arch=x86 cfg=False packed=None    dotnet=True    ← .NET via mscoree
x64_msvc_3c4de3f013d4    usable=True arch=x64 cfg=False packed=None    dotnet=True    ← .NET SOLO via CLR header
x64_mingw_a09c42ba64c4   usable=True arch=x64 cfg=False packed=None    dotnet=False
```

Dry-run completo della selezione (seed invariato 20260923):

```
[!] 6 candidati SCARTATI perche' gia' packati:
      NBHextract_2E1ADF…  (sezione UPX0)
      RAIU_BEFA0244…      (sezione UPX0)
      UNUHARC06_A9CF9DA…  (sezione UPX0)
      WUN_F6C607C8…       (sezione UPX0)
      clit_E87BF25B…      (sezione UPX0)
      upx_4D3D363B…       (sezione UPX0)
[*] Scartati: 41 non-PE/sottosistema, 897 con Control Flow Guard, 6 gia' packati
[*] 10 master sono assembly .NET
```

Il filtro intercetta **6** candidati già packati nei pool sorgente, non solo i 2 finiti nella
selezione: è un filtro generale, non una patch su due file. Backfill del manifest verificato:
**40 righe `is_dotnet=1`**, 325 a `0`, nessuna vuota.

### 10.3 ⚠️ Conseguenza da decidere: il fix cambia la selezione dei master

Rimuovere 2 candidati dal pool `mingw x86` cambia la permutazione prodotta da `rng.shuffle` →
**14 stem su 56 cambiano** (42 in comune). Tutte le variazioni sono su `x86_mingw`.

Tre opzioni:

| opzione | costo | risultato |
|---|---|---|
| **A — tenere il dataset attuale** e cancellare solo gli 8 campioni contaminati | 0 | 357 campioni validi. Il fix protegge i run futuri. ✅ **scelta ed eseguita, vedi §12** |
| **B — aggiungere `--reuse-masters`** che riusa `E:\DATASET_MASTERS` invece di riselezionare | ~15 righe | la matrice resta completabile senza reshuffle, determinismo preservato. *Non implementata* |
| **C — rigenerazione completa** con il filtro corretto | ore (Themida/Inno sono lenti) | dataset più pulito, selezione coerente col codice attuale. *Scartata* |

**Nota:** un semplice rilancio di `pack_samples.py` senza scelta produce un **misto** delle due
selezioni — i vecchi file restano nel manifest (skip per nome) e si aggiungono le celle dei 14
master nuovi. Non è sbagliato (ogni label è per-file e resta corretta) ma è disordinato.

Comando per l'opzione A (**da eseguire solo dopo conferma**):

```bash
cd /e/DATASET_PACKED && rm -f x86_mingw_2e1adf481ac0_{VMProtect,Themida,NSIS,Inno}.exe x86_mingw_befa024422b3_{VMProtect,Themida,NSIS,Inno}.exe
```

Le righe corrispondenti vanno poi tolte da `manifest.csv` (o il manifest rigenerato).

---

## 11. Specifica di `import_packing_matrix()` — da approvare prima di eseguire

### 11.1 Perché serve

`build_ground_truth.py` ha già `import_packing_report()`, ma legge
`Packing/report_compressione.json`: il formato della **vecchia** `pack_samples.py`, indicizzato
per nome e sovrascritto a ogni run. Il nuovo generatore scrive `E:\DATASET_PACKED\manifest.csv`,
per SHA-256 e in append. **Senza un nuovo importer i 365 campioni non esistono per la validazione**
e la matrice di confusione resta ferma a 26 packed.

### 11.2 Cosa farebbe, esattamente

**Firma proposta**

```python
def import_packing_matrix(manifest, matrix_csv=MATRIX_MANIFEST, packed_dir=PACKED_DIR):
    """Importa la matrice di pack_samples.py come label `packed` CERTE."""
```

**Per ogni riga di `manifest.csv`:**

1. verifica che il file esista in `E:\DATASET_PACKED`; se manca → warning e skip;
2. ricalcola lo **SHA-256 dal file su disco** e lo confronta con la colonna `sha256`. Se non
   coincidono → **skip con errore**: significa che il file è stato modificato dopo la generazione
   e la label non è più garantita. *Questo controllo non esiste nel vecchio importer ed è il
   motivo principale per cui vale la pena riscriverlo invece di adattarlo;*
3. scrive/sovrascrive la voce `manifest[sha256]` con:

```python
{
  "relpath":       <filename>,
  "filename":      <filename>,
  "dataset":       "packed_matrix",              # distinto da "packed_by_us" del vecchio import
  "size":          <size_out>,
  "magic":         _magic(filepath),
  "label":         "packed",                     # label CERTA: il packer è stato eseguito
  "packers":       ["UPX", "MPRESS"],            # da `layers`, splittato su " + "
  "source":        "pack_samples_matrix",
  "origin_sha256": <origin_sha256>,              # disegno appaiato
  "notes":         "matrice pack_samples.py (seed 20260923): arch=x86, source=mingw, dotnet=0",
  "updated":       <timestamp>,
}
```

**Cosa NON farebbe:**

- **non tocca mai i master**: `E:\DATASET_MASTERS` non viene scansionato e nessun master riceve
  label `clean`. I master sono `unknown` finché un oracolo esterno non si pronuncia — coerente
  con la regola di `build_ground_truth.py` per cui nessuna scansione può assegnare `clean`;
- **non inferisce nulla**: ogni campo viene dal manifest o dal file su disco;
- **non cancella** voci esistenti che non sono nel manifest.

**Wiring CLI:** nuovo flag `--import-packing-matrix` (più `--matrix-csv` per il path), sulla
falsariga di `--import-packing-report`, con `save_manifest()` atomico solo se qualcosa è cambiato.

### 11.3 Effetto atteso sulla ground truth

| | prima | dopo |
|---|---|---|
| voci totali | 2.174 | ~2.539 |
| label `packed` | 26 | **391** |
| label `clean` | 2.036 | 2.036 (invariate) |
| limite sup. 95 % sui FN | ~11,5 % | **~0,8 %** |
| famiglie di packer rappresentate | 9 (13 = UPX) | 9 + UPX/MPRESS/VMProtect/Themida/NSIS/Inno a supporto **44-56 ciascuna** |

### 11.4 Tre decisioni da prendere prima di lanciarlo

1. **Gli 8 campioni contaminati (§9.1)**: eliminarli **prima** dell'import, oppure importarli con
   `layers` corretto a mano (`UPX + Themida`, …)? *Raccomandazione: eliminarli — sono 8 su 365 e
   correggerli a mano introduce una voce "aggiustata a mano" in un dataset il cui unico pregio è
   di non averne.*
2. **I 40 campioni .NET**: importarli normalmente (con `is_dotnet` nelle note) oppure marcarli
   come sotto-classe separata? *Raccomandazione: importarli, con `dotnet=1` nelle note, e tenerli
   fuori dalle tabelle per architettura — l'`arch` di un AnyCPU non è significativa.*
3. **Rigenerazione sì/no** (§10.3): opzione A, B o C.

✅ **Decisioni prese: (1) cancellare gli 8 · (2) import normale per i .NET · (3) opzione A.**
Esito dell'esecuzione in §12.

---

## 12. Esecuzione — pulizia e import (24/09/2026)

### 12.1 Cancellazione degli 8 campioni contaminati

Backup preventivi nello scratchpad di sessione: `manifest_prima_della_pulizia.csv`,
`ground_truth_prima_import.json`.

```
file .exe prima:  365
cancellati:         8   (x86_mingw_2e1adf481ac0_* e x86_mingw_befa024422b3_*)
file .exe dopo:   357
residui dei 2 master contaminati: 0
```

`manifest.csv` riscritto a **357 righe**, con la colonna `is_dotnet` **persistita** dal backfill
(317 a `0`, 40 a `1`). Controllo di coerenza eseguito **prima** della riscrittura: nessuna riga
senza file su disco. **Manifest e filesystem allineati: 357 = 357.**

### 12.2 `import_packing_matrix()` — scritto ed eseguito

Aggiunto a `scripts/build_ground_truth.py`, con `import csv`, la costante `MATRIX_MANIFEST`
(sovrascrivibile via variabile d'ambiente `PACK_MATRIX_MANIFEST`) e i flag CLI
`--import-packing-matrix` / `--matrix-csv`.

```bash
python scripts/build_ground_truth.py --import-packing-matrix --stats
```

Esito:

```
[+] Inno            54     [+] UPX              44
[+] MPRESS          50     [+] UPX + MPRESS      8
[+] NSIS            54     [+] UPX + NSIS       44
[+] Themida         54     [+] VMProtect        49
Importate 357 label 'packed' CERTE dalla matrice di pack_samples.py
```

**0 file mancanti · 0 sha256 non corrispondenti · 0 conflitti con label `clean`.**

### 12.3 Ground truth: prima → dopo

| | prima | dopo |
|---|---|---|
| voci totali | 2.174 | **2.530** |
| `packed` | 26 | **382** |
| `clean` | 2.036 | 2.036 *(invariate)* |
| `unknown` | 112 | 112 *(invariate)* |
| utilizzabili per le metriche | 2.062 (95 %) | **2.418 (96 %)** |

`packed` per fonte: `pack_samples_matrix` 357 · `manual` 13 · `upx-t` 10 · `pack_samples` 2.

Verifiche sulle 357 voci importate: **357/357 con `origin_sha256`** (disegno appaiato integro),
**357/357 con `packers` non vuoto**, **40** annotate come .NET AnyCPU, **54 master distinti**
(56 − i 2 contaminati rimossi), 305 a un layer e 52 a due layer.

### 12.4 Un risultato non previsto: prova di determinismo del generatore

L'import ha prodotto **+356 voci, non +357**: un campione della matrice ha lo **stesso SHA-256**
di una voce già presente.

```
x64_mingw_c30c5b2cd43a_UPX.exe   ==   b2sum_C30C5B2CD43AB3E93DDC1BC59D0331F351BDFECB2...exe
prima: packed | pack_samples          (dal vecchio report_compressione.json)
dopo : packed | pack_samples_matrix
```

Stesso master, stesso packer, stessa versione di UPX → **byte identici**, a settimane di distanza
e da due run diverse dello script. Due conseguenze:

1. **La generazione è riproducibile a livello di contenuto**, non solo di procedura: è un
   argomento diretto a favore della riproducibilità del dataset in tesi.
2. **Il manifest indicizzato per SHA-256 ha deduplicato da solo**, invece di contare due volte lo
   stesso campione sotto due nomi. È esattamente il motivo per cui la chiave è l'hash e non il
   nome file.

### 12.5 Effetto sulla validazione

Il limite superiore al 95 % sui falsi negativi passa da **~11,5 %** (26 packed) a **~0,8 %**
(382 packed) — *a condizione* che la Fase 1 li classifichi effettivamente tutti, cosa **non ancora
verificata**: serve il run di Fase 1 su `E:\DATASET_PACKED` e poi `validate_phase1.py`.

E il collo di bottiglia per famiglia è risolto: da "9 famiglie di cui 13 campioni UPX" a sei
famiglie di packer con supporto 44–54 ciascuna, più le due combinazioni multilayer.

**Prossimi passi, in ordine:**

1. `python scripts/parameters_info.py --dir "E:/DATASET_PACKED" --phase1-only` — primo run di
   Fase 1 sui 357 campioni;
2. `python scripts/validate_phase1.py` — nuova matrice di confusione;
3. metrica **scomposta** per sotto-classe (packer / installer / vendor) e per architettura,
   escludendo i 40 AnyCPU dalle tabelle per architettura;
4. valutare il fix di `Is_DotNet` in `header_elf_lief.py` (§9.2): oggi usa solo l'import di
   `mscoree.dll` e manca gli assembly senza import table;
5. solo dopo: set wild e FLARE.

---

## 13. Prima misura OUT-OF-SAMPLE della Fase 1 (24/09/2026)

### 13.1 Protocollo

I 357 campioni della matrice sono **l'unico materiale che non ha partecipato alla calibrazione**
della regola di scoring. Per questo la misura che segue è la prima out-of-sample del progetto, e
il protocollo è stato rispettato alla lettera:

1. **configurazione congelata e registrata prima del run** — nessuna costante toccata:

   | parametro | valore |
   |---|---|
   | `WEAK_SIGNALS_REQUIRED` | 3 |
   | `EP_ENTROPY_THRESHOLD` | 7.0 |
   | `EXPORTS_REAL_API` | 10 |
   | `ENTROPY_EXCLUDED_SECTIONS` | `(".rsrc",)` |
   | `PACKING_THRESHOLD` | 70 |
   | `CAPA_MODE` | `off` |
   | `DIE_ARGS` | `-j -u` |
   | keyword packer YARA / colonne CSV | 29 / 49 |

2. `header_elf_lief.py` e `pipeline_utils.py` **invariati** rispetto al commit `61b8bca`
   (verificato con `git status`);
3. run e misura **senza alcuna modifica successiva**.

> **Regola da non violare:** se una soglia venisse toccata dopo aver visto questi risultati, il
> set cesserebbe di essere out-of-sample e servirebbe un terzo corpus per rimisurare.

### 13.2 Risultato

```
python scripts/parameters_info.py --dir "E:/DATASET_PACKED" --phase1-only
  File analizzati: 356 in 163 s | pacchettizzati: 356 | puliti: 0
  Parse_Status : ok=355, lief_none=1
  Yara_Status  : ok=356      Die_Status: ok=356      Capa_Status: disabled=356
```

**356 su 356 rilevati. Zero falsi negativi out-of-sample.** (357 − 1: un campione era già nel CSV
per deduplicazione sull'hash, vedi §12.4.)

Matrice di confusione complessiva dopo l'aggiunta:

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** | **TP = 382** | **FN = 0** |
| **reale clean** | FP = 0 | TN = 2041 |

Precision 1,000 · Recall 1,000 · F1 1,000 su 2.423 campioni etichettati (2.535 righe, 112
`unknown`). **0 / 2.535 righe decise con un tool troncato da timeout.**

Qualità dell'evidenza sui 356: **`named` 332 · `structural` 23 · `weak_only` 1**.

### 13.3 Come va riportato questo numero

Il limite superiore al 95 % sui falsi negativi scende da ~11,5 % a **~0,8 %**, ma vale **per la
popolazione rappresentata**, che è la matrice: sei famiglie di packer scelte da noi, su master
tutti privi di CFG e a toolchain datata. Formulazione corretta in tesi:

> *"Nessun falso negativo osservato su 356 campioni a label certa, coprenti sei famiglie di
> packer/installer. La misura non si estende alle famiglie assenti dalla matrice (FSG, ASPack,
> PECompact, Petite, kkrunchy, offuscatori .NET), per le quali il rilevamento resta non
> misurato."*

Ciò che il numero dimostra davvero: la regola calibrata su 26 packed **non era sovradattata a
quei 26**, perché regge su 356 campioni mai visti, prodotti da packer diversi (Themida, VMProtect,
Inno, NSIS) e in gran parte assenti dal set di calibrazione.

### 13.4 Conferma della soglia, questa volta su 382 packed

| soglia | TP | FP | FN | precision | recall |
|---|---|---|---|---|---|
| 1 | 382 | 395 | 0 | 0,492 | 1,000 |
| 2 | 382 | 142 | 0 | 0,729 | 1,000 |
| **3 (in uso)** | **382** | **0** | **0** | **1,000** | **1,000** |
| 4 | 378 | 0 | 4 | 1,000 | 0,990 |
| 5–6 | 376 | 0 | 6 | 1,000 | 0,984 |

3 resta l'ottimo unico con un supporto packed **15 volte maggiore** di quello su cui era stato
scelto. È la conferma più solida disponibile che la soglia non fosse un artefatto dei 26.

### 13.5 Discriminazione per segnale, ricalcolata su 382 packed

| segnale | tipo | packed | clean | lift | variazione vs 26 packed |
|---|---|---|---|---|---|
| DIE packer nominato | forte | 92 % | 0 % | +92 | **77 % → 92 %** |
| nomi sezione non standard | debole | 96 % | 6 % | +90 | 81 % → 96 % |
| euristica DIE | debole | 99 % | 17 % | +82 | 85 % → 99 % |
| EP in sezione non standard | debole | 69 % | 0 % | +69 | 65 % → 69 % |
| sezione tipica di packer | forte | 67 % | 0 % | +67 | 54 % → 67 % |
| entropia sezione ≥ 7.2 | debole | 55 % | 0 % | +55 | **85 % → 55 %** |
| sezioni con dimensione anomala | debole | 54 % | 0 % | +54 | 58 % → 54 % |
| numero import basso | debole | 50 % | 3 % | +47 | **73 % → 50 %** |
| stub strutturale | forte | 41 % | 0 % | +41 | 42 % → 41 % |
| overlay grande ad alta entropia | debole | 27 % | 0 % | +27 | **nuovo, era 0 %** |
| IAT minimale sospetta | forte | 17 % | 0 % | +17 | **42 % → 17 %** |
| YARA packer specifico | forte | 14 % | 0 % | +14 | **50 % → 14 %** |
| YARA generico/anti-analysis | *info* | 1 % | 45 % | −43 | 12 % → 1 % |

Le variazioni non sono rumore, sono **composizione del dataset**: i 26 packed originali erano per
metà UPX (compressore classico → entropia altissima, IAT distrutta, firma YARA nota), mentre la
matrice è dominata da installer e protector, che **conservano una IAT plausibile, non fanno
scattare le firme YARA e comprimono meno**. Due conseguenze da scrivere:

- **YARA scende dal 50 % al 14 %.** Su un corpus realistico le firme coprono una frazione
  minoritaria dei casi: è l'argomento quantitativo a favore dei segnali strutturali;
- **"overlay grande ad alta entropia" passa da 0 % a 27 %**: era un segnale che sui 26 non
  scattava mai, e con gli installer diventa il quarto segnale debole per frequenza. Se fosse
  stato rimosso come "morto" (come è successo giustamente a `differenza size virtuale/raw`) si
  sarebbe perso. È la controprova che rimuovere segnali su un supporto di 26 campioni è
  rischioso.

### 13.6 Il risultato più forte: VMProtect x86, ora su n = 49

L'asimmetria x86/x64 di DIE, osservata su un solo campione nello smoke test, è ora misurata sulla
matrice completa, con **label certa al 100 %**:

| | campioni | DIE lo nomina |
|---|---|---|
| VMProtect **x64** | 26 | **25 (96 %)** |
| VMProtect **x86** | 23 | **0 (0 %)** |

Dicotomia perfetta. Stesso tool, stessa versione 3.10.6, stesse impostazioni.

E la contro-prova: **i 23 campioni `structural` del run sono esattamente i 23 VMProtect x86.**
Sono stati intercettati **solo** dai segnali strutturali (`stub strutturale`: EP in sezione ad
alta entropia con sezioni eseguibili svuotate), perché VMProtect 3.x randomizza i nomi di sezione
e le firme che cercano `.vmp0`/`.vmp1` falliscono.

> Senza i segnali strutturali, questi 23 campioni sarebbero **23 falsi negativi**. È la
> giustificazione sperimentale dell'intera architettura forte/debole, su campioni generati
> internamente e quindi con label non contestabile.

Detection rate di DIE per packer reale:

| packer reale | DIE lo nomina |
|---|---|
| Inno · NSIS · Themida · MPRESS · UPX · UPX+MPRESS · UPX+NSIS | **100 %** |
| **VMProtect** | **51 % (25/49)** |

### 13.7 Il campione più fragile dell'intero dataset

Uno solo dei 356 è stato classificato con **soli segnali deboli**:

```
x64_msvc_3c4de3f013d4_VMProtect.exe      (master .NET x64 + VMProtect)
  Evidence : weak_only    Score: 100
  Weak     : sezioni con dimensione anomala | nomi sezione non standard |
             numero import basso (<20) | DIE euristica: protection: Obfuscation;
             protection: Anti analysis; packer: Generic
```

È l'unico VMProtect x64 che DIE non nomina (25/26), ed è anche un assembly .NET. Regge su
**4 segnali deboli contro una soglia di 3**: un solo segnale in meno e sarebbe un falso negativo.
Da citare come il caso limite osservato, ed è l'argomento più concreto contro l'ipotesi di alzare
`WEAK_SIGNALS_REQUIRED` a 4.

### 13.8 Conferma della robustezza al fallimento di LIEF

Un campione ha `Parse_Status = lief_none` — LIEF non riesce a parsarlo — ed è stato comunque
classificato correttamente:

```
x86_mingw_9c5c58a524d5_UPX.exe
  Parse_Status: lief_none          Evidence: named    Score: 100
  Strong      : DIE: packer identificato (UPX)
  Weak        : header non parsabile da LIEF (lief_none): possibile malformazione voluta
```

È la validazione sul campo di due scelte di progetto: che un fallimento di parsing **non elimini
il file** dall'analisi, e della correzione **B5** (un'eccezione tardiva non cancella i segnali
forti già raccolti).

### 13.9 Bug trovato — non tocca la classificazione, ma sbaglia l'instradamento alla Fase 2

**Tutti e 54 i campioni Inno Setup** ricevono:

```
Die_Packer_Name = ".NET Reactor"      Die_Packer_Type = "protector"
Die_All_Packers = ".NET Reactor (protector); Inno Setup Module (installer)"
```

DIE emette una sotto-firma spuria `.NET Reactor` sullo stub Inno, e `run_die_analysis()` sceglie
con `(packers or installers)[0]`: i packer hanno la precedenza, quindi la firma spuria vince su
quella corretta.

**Effetto:** la classificazione è giusta (packed, `named`, score 100 — la matrice di confusione non
cambia di una cella), ma `extract_packed_files()` passa alla Fase 2 l'hint `.NET Reactor` con tipo
`protector`. La Fase 2 manderebbe **tutti gli installer Inno all'emulazione invece che
all'estrazione** — esattamente il contrario di ciò per cui `DIE_INSTALLER_TYPES` era stato creato.

NSIS non ne è affetto (54/54 e 44/44 correttamente `installer`).

**Correzione proposta, da applicare solo dopo aver congelato questa misura:** quando DIE riporta
sia un packer sia un installer, preferire l'**installer** per il routing (o almeno non lasciare
che una firma di tipo `protector` con `info` di basso peso sovrascriva un installer riconosciuto).
La colonna `Die_All_Packers` conserva già entrambe, quindi l'informazione non è persa: è solo
scelta male. **Non cambia `Is_Packed_Label`**, quindi non invalida la misura out-of-sample.

### 13.10 Cosa resta non misurato

| | stato |
|---|---|
| sei famiglie della matrice (UPX, MPRESS, VMProtect, Themida, NSIS, Inno) | ✅ recall misurato, 0 FN su 356 |
| FSG, ASPack, PECompact, Petite, kkrunchy | ❌ non misurato (tool non automatizzabili o non reperibili) |
| offuscatori .NET nativi (ConfuserEx…) | ❌ non misurato — i 40 campioni .NET della matrice sono **wrapper nativi**, non offuscamento managed |
| goodware non-Microsoft (Go, Rust, MSYS2) | ❌ **il buco più grande ora**: il set clean è 100 % System32, e le eccezioni kernel/`.rsrc` sono state cucite proprio su quello |
| FLARE VM (800 file, hard set) | ❌ copiati, mai analizzati |
| set wild MalwareBazaar (181 campioni) | ❌ mai analizzato |

Il collo di bottiglia si è **spostato dal lato packed al lato clean**: il FP rate è misurato solo
sulla classe negativa facile.

---

## 14. Estensione del dataset — classe negativa non-Microsoft (P0)

> **Questa sezione è stata scritta PRIMA di eseguire la Fase 1 sul set.** Il protocollo è
> dichiarato in anticipo proprio perché non sia ritoccabile dopo aver visto i risultati. Al
> momento della stesura l'esito è ignoto.

### 14.1 Perché questa classe, e perché adesso

Dopo §13 il lato packed è misurato (0 FN su 356 out-of-sample). Il lato clean **no**: 2.041
campioni provenienti tutti da `System32` firmato Microsoft, cioè da un'unica distribuzione — ed è
**esattamente la distribuzione su cui sono state tarate le eccezioni ai falsi positivi** (famiglie
di sezioni kernel `PAGE*`/`INIT*`, esclusione di `.rsrc` dall'entropia, regola sugli export).

Un limite superiore dello 0,15 % sul tasso di FP, misurato dove le eccezioni sono state scritte,
non dice nulla su cosa accade su binari di altra natura. Aggiungere altri file di System32 non
aggiunge informazione: serve una **classe negativa di natura diversa**.

### 14.2 Il materiale: estensioni native Python (`.pyd`)

| proprietà | perché conta |
|---|---|
| compilate da **terzi**, non da Microsoft | oracolo di provenienza diverso da Authenticode |
| toolchain eterogenee (Cython, mypyc, Meson/Fortran, MSVC, LLVM) | rompe l'omogeneità di System32 |
| sono **DLL con export table e pochissimi import** | colpiscono in pieno `EXPORTS_REAL_API = 10` e l'eccezione "numero import basso", due delle correzioni tarate su System32 |
| provenienza **verificabile** | wheel ufficiali da PyPI, con hash registrato nel `RECORD` del wheel |
| costo di acquisizione | **zero**: sono già nel `.venv` del progetto |

Nota di perimetro: `.pyd` non è in `VALID_EXTENSIONS`, ma la Fase 1 li acquisisce lo stesso grazie
al fallback sul magic number `MZ` (§1.2, punto 4). È anche una verifica incidentale di quel
meccanismo su file reali con estensione inattesa.

### 14.3 Costruzione del set

Script: `scratchpad/build_pypi_set.py`, seed **20260924**, output `E:\DATASET_CLEAN_PYPI\`.

- soglia dimensionale 20 KB (sotto si trovano solo stub di import);
- **dedup per SHA-256**: 0 duplicati trovati su 341 file;
- **split PER PACCHETTO, non per file.** I `.pyd` dello stesso pacchetto condividono toolchain e
  opzioni di build: distribuirli a caso fra le due metà renderebbe la metà di test piena di
  "parenti stretti" di quella di calibrazione, cioè non indipendente. Lo split è greedy sul
  numero di file, così le due metà restano di dimensione confrontabile;
- manifest `manifest.csv` con `half, filename, sha256, package, source_path, size`.

| metà | file | pacchetti | composizione |
|---|---|---|---|
| **calib** | 171 | 14 | scipy 106 · win32 29 · Cryptodome 14 · PIL 5 · altri 17 |
| **test** | 170 | 14 | sklearn 67 · pandas 45 · numpy 16 · gevent 16 · win32comext 14 · altri 12 |

Dimensioni: min 20 KB · mediana 121 KB · max 11,8 MB.

**Limite statistico da dichiarare.** Il supporto *effettivo* non è 171 e 170, ma circa **14 e 14**:
i file di uno stesso pacchetto non sono osservazioni indipendenti. Il set serve a **scoprire un
problema sistematico** su una toolchain, non a stringere l'intervallo di confidenza sul tasso di
FP. Va riportato come numero di pacchetti, non solo di file.

### 14.4 Protocollo, dichiarato in anticipo

1. Le voci entrano nella ground truth come **`unknown`**, tramite `--scan`. **Nessuna label
   `clean` assegnata in automatico**: vale la regola di `build_ground_truth.py` per cui una
   scansione non può dichiarare "non packed". È la stessa disciplina che ha evitato i 15 finti
   falsi positivi di `TEST_BIN_PULITI`.
2. Si esegue la Fase 1 **solo sulla metà `calib`**, a configurazione invariata (§13.1).
3. Ogni campione che risulta `packed` viene **verificato a mano prima di essere chiamato falso
   positivo**: un `.pyd` può essere legittimamente compresso o protetto, e contarlo come FP
   senza guardarlo ripeterebbe l'errore commesso con il materiale FLARE.
4. Se emergono FP reali, si corregge **la causa strutturale**, mai il campione — nello stesso
   modo in cui `ntdll` è stato risolto con *"0 import ma 2.433 export"* e non con una lista di
   esclusione.
5. La metà `test` si esegue **una volta sola, alla fine**, e il numero che produce è quello che va
   in tesi. **Qualunque esito abbia.**

> **Vincolo:** se la metà `test` venisse usata per tarare qualcosa, cesserebbe di essere di test e
> servirebbe un quarto corpus. Per questo `calib` e `test` sono separate fisicamente, in due
> cartelle distinte, e non in una colonna dello stesso CSV.

### 14.5 Cosa succede dopo (P1 e P2, già pianificati)

- **P1 — Go e Rust**, 20 binari generati dall'utente. Stesso protocollo: split calib/test
  dichiarato prima, causa strutturale, test una volta sola. È il test più severo perché un
  binario Go statico e stripped fa scattare *pochi import* + *sezioni di dimensione anomala* +
  *nomi sezione non standard* insieme, cioè esattamente i 3 segnali deboli della soglia.
- **P2 — .NET offuscato** (ConfuserEx sui 9 master .NET già selezionati): l'obiettivo non è
  rilevarlo, è **misurare quanti falsi negativi produce e dichiarare il .NET fuori perimetro con
  i dati a supporto**.

### 14.6 Esito sulla metà di calibrazione (171 file, 14 pacchetti)

```
File analizzati: 171 in 81 s | pacchettizzati: 0 | puliti: 171
Parse_Status: ok=171   Yara_Status: ok=171   Die_Status: ok=171   Capa_Status: disabled=171
```

**Zero falsi positivi.** Nessun file con un solo segnale forte. Score massimo osservato: **30**
(cioè 2 segnali deboli, contro una soglia di 3).

**Margine dalla soglia** — è il dato più informativo, più del conteggio dei FP:

| segnali deboli | file |
|---|---|
| 0 | 57 |
| 1 | 112 |
| 2 | **2** |
| ≥ 3 *(soglia)* | **0** |

Solo 2 file su 171 arrivano a un segnale dalla soglia. Il margine è ampio, non fortunato.

**Quali segnali deboli scattano:**

| segnale | file |
|---|---|
| euristica DIE `protection: Generic` | **109** |
| entropia sezione ≥ 7.2 | 3 |
| euristica DIE `packer: Generic` | 2 |
| nomi sezione non standard | 2 |

### 14.7 Tre risultati da registrare

**1. Una mia previsione sbagliata, da correggere nel ragionamento.** Il set era stato scelto
aspettandosi che i `.pyd` stressassero la regola export/import (*"DLL con export table e pochissimi
import"*). **Non è così**: gli import misurati vanno da 28 a 1.814, mediana **177** — un'estensione
Python linka `python3xx.dll` più il CRT e importa molto. **Il segnale "numero import basso" non è
mai scattato, e l'eccezione sugli export non è mai stata esercitata.** Il set è quindi un test
*più blando* del previsto, e questo **alza** l'importanza di Go/Rust, non la abbassa.

Nota collaterale con valore diagnostico: gli export dei `.pyd` hanno **mediana 1** (esportano il
solo `PyInit_<modulo>`). Se un `.pyd` avesse davvero pochi import, `EXPORTS_REAL_API = 10` **non lo
proteggerebbe**. È un caso limite latente, oggi non raggiunto perché gli import abbondano.

**2. L'euristica DIE è il segnale che degrada di più fuori distribuzione.**

| | clean System32 | `.pyd` PyPI |
|---|---|---|
| euristica DIE (`~packer`/`~protection`) | 17 % | **64 %** |

È il segnale debole più rumoroso del sistema, e il rumore **quadruplica** su una classe negativa
di natura diversa. Non ha causato falsi positivi qui, perché da solo non basta, ma è il candidato
numero uno a farlo quando si combina con altri due su una classe ancora diversa. Da tenere
d'occhio su Go/Rust.

**3. Controprova misurata della scelta di rendere YARA generico "informativo".** 104 file su 171
hanno un match YARA generico (`Anti_Debug_API`). Se quel match fosse contato come segnale
**debole** invece che informativo:

| segnali deboli | file (controfattuale) |
|---|---|
| 0 | 2 |
| 1 | 120 |
| 2 | 47 |
| **≥ 3** | **2 falsi positivi** |

La decisione, presa su 27 benigni e 16 packed, regge su una classe negativa che non l'ha mai vista.

### 14.8 I due casi limite, guardati uno per uno

```
Cryptodome__Cipher___raw_aes.pyd      score 30 | import 28 | entropia max 7.47
  weak: entropia sezione >= 7.2 | DIE euristica: packer: Generic

Cryptodome__PublicKey___ec_ws.pyd     score 30 | import 33 | entropia max 7.70
  weak: entropia sezione >= 7.2 | DIE euristica: packer: Generic
```

Sono entrambi estensioni crittografiche: l'entropia alta viene da **tabelle e costanti di
cifratura**, non da compressione. È il falso positivo classico che la letteratura sul packing
segnala, ed è proprio il motivo per cui l'entropia è un segnale **debole** e non forte. Restano a
2 su 3 e non vengono classificati packed.

### 14.9 Stato della label e conseguenza sulle metriche

Le 171 voci restano **`unknown`** nella ground truth: il protocollo (§14.4) prevede che nessuna
scansione assegni `clean`, e l'unica verifica manuale prevista era sui file risultati `packed` —
che sono zero.

**Conseguenza da sapere:** finché restano `unknown`, questi 171 file **non entrano nella matrice
di confusione** e il tasso di FP riportato resta quello misurato su System32. Il risultato di
§14.6 è, allo stato, un'evidenza **qualitativa** ("nessuno dei 171 è stato segnalato"), non una
riga di metrica.

Per farli contare come veri negativi serve una label `clean` da un oracolo **indipendente dai
segnali valutati**. Quello disponibile è la **provenienza**: wheel ufficiali da PyPI, installate
via `pip` dal `requirements.txt` del progetto, con hash registrato nel `RECORD` del wheel. È un
oracolo dello stesso tipo di quello usato per System32 (firma Authenticode Microsoft): non guarda
il contenuto, guarda **chi lo ha prodotto e come è arrivato lì**. Da formalizzare in
`config/pypi_labels.json` sulla falsariga di `manual_labels_clean_ms.json`, e da **dichiarare in
tesi come label di provenienza, non come verifica strutturale**.

La metà `test` (170 file, 14 pacchetti) **non è stata toccata** e resta disponibile per la misura
finale, una volta sola.

---

## 15. Correzione: i master già pacchettizzati erano **tre**, non due

> Aggiornamento del 24/09/2026, successivo a §9.1 e §12. I paragrafi 6.1 e 9.1 dicono "due
> master": era corretto con quello che si sapeva allora, ed è **superato** da qui.

### 15.1 Come è emerso

Verifica appaiata sui 56 master: sono gli originali *puliti* da cui nasce `DATASET_PACKED`, ed
erano già tutti nel CSV. Esito atteso: 56 puliti. Esito reale: **53 puliti, 3 packed**.

I primi due erano noti (`NBHextract`, `RAIU`, sezioni `UPX0`/`UPX1`). Il terzo no:

```
UHARC04_A45C6F7DA7D9….exe
  sezioni : ['', '', '']          <- tre sezioni SENZA NOME
  import  : KERNEL32.DLL, USER32.dll
  Evidence: named
  Strong  : DIE: packer identificato (UPX)
          | IAT minimale sospetta (solo LoadLibrary/GetProcAddress)
          | stub strutturale: EP in sezione ad entropia 7.92, sezione EP W+X
```

È **UPX con i nomi di sezione azzerati**: la variante dell'esercizio `Lab18-02` del libro PMA.

### 15.2 Perché il filtro non l'ha preso

`_already_packed()` (§10.1) confronta i **nomi delle sezioni** con `PACKER_SECTION_PREFIXES`. Su
un file con i nomi azzerati non ha niente da confrontare. La Fase 1 invece lo intercetta con **tre
prove forti indipendenti**, nessuna delle quali dipende dai nomi.

Spiega anche un dettaglio rimasto aperto in §9.4: UPX aveva risposto `NotCompressibleException`
invece di `AlreadyPackedException` proprio perché non riconosce il proprio header modificato. In
§9.4 era stato archiviato come "rifiuto legittimo, file non comprimibile". **Era invece un terzo
master contaminato.**

### 15.3 Stato e correzione

| master | esito |
|---|---|
| `NBHextract_2E1ADF…` | intercettato; 4 campioni cancellati (§12.1) |
| `RAIU_BEFA0244…` | intercettato; 4 campioni cancellati (§12.1) |
| `UHARC04_A45C6F7D…` | **non intercettato** dal filtro; i suoi 4 campioni sono stati cancellati dopo la scoperta (§15.5) |

**Correzione da applicare a `pe_info()`:** sostituire (o affiancare) il filtro sui nomi di sezione
con un controllo sulla **ground truth** — se lo SHA-256 del candidato è già etichettato `packed`
in `ground_truth.json`, si scarta. Avrebbe preso tutti e tre, perché tutti e tre erano già
etichettati `packed` dall'oracolo `upx -t`.

### 15.4 Cosa dice questo episodio, al di là del bug

Due cose che vale la pena riportare, perché è un caso in cui il sistema si è comportato come
doveva:

1. **Il rilevamento basato sui nomi è fragile, quello strutturale no.** Lo stesso file sfugge a un
   filtro sui nomi di sezione e viene preso da entropia + IAT + layout dello stub. È la stessa
   lezione dei 23 VMProtect x86 (§13.6), qui su una variante di UPX.
2. **La verifica appaiata funziona come test di regressione.** Confrontare i 56 master con le loro
   357 versioni packed non costa nulla (sono tutti già nel CSV) e ha trovato un difetto reale. È
   un controllo da rifare dopo ogni rigenerazione del dataset.

### 15.5 Rimozione dei 4 campioni e stato finale

I campioni derivati da `UHARC04` sono stati cancellati e rimossi da **tutti e tre** gli artefatti
che li citavano, per non lasciarli disallineati fra loro:

| artefatto | prima | dopo |
|---|---|---|
| file `.exe` in `E:\DATASET_PACKED` | 357 | **353** |
| righe di `manifest.csv` | 357 | **353** |
| voci in `ground_truth.json` | 2.701 | **2.697** |
| righe di `report_analisi_lief.csv` | 2.706 | **2.702** |

Controllo di coerenza eseguito prima della riscrittura (nessuna riga senza file su disco) e
verifica dopo: **353 file = 353 righe di manifest**.

Matrice di confusione ricalcolata, invariata nella sostanza:

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** | **TP = 378** | **FN = 0** |
| **reale clean** | FP = 0 | TN = 2041 |

Su 2.419 campioni etichettati. Righe agganciate al manifest: **2.702 su 2.702, nessuna orfana**.

Conteggio per layer aggiornato: Themida 53 · NSIS 53 · Inno 53 · MPRESS 50 · VMProtect 48 ·
UPX 44 · UPX+NSIS 44 · UPX+MPRESS 8.

**Il filtro `_already_packed()` non è stato modificato**: intercetta ancora solo i nomi di sezione.
La correzione robusta (scarto per label `packed` nella ground truth) resta da applicare prima di
una eventuale rigenerazione della matrice.

---

## 16. Sessione del 27 settembre 2026 — chiusura della Fase 1

### 16.1 Go e Rust: integrati

Gli 8 binari Rust erano già stati costruiti dall'utente; `build_go.ps1` non era mai stato eseguito.
Lanciato con Go nel PATH (`go1.27.1`, installato in `C:\Program Files\Go\bin`): **8 Go prodotti**
(`g1`–`g6`, `g9`, `g10`). `g7`/`g8` falliti — richiedono un compilatore C per `cgo`, assente
(`cgo: C compiler "gcc" not found`).

**16 binari** in totale, copiati in `01_LABEL_CERTA\gorust` con manifest che riporta linguaggio,
profilo e **comando di build esatto**. Escursione 344 KB → 9,7 MB.

Esclusi di proposito: i 6 `build-script-build.exe` sotto `netjson_deps_r9/target/release/build/`
(script di cargo delle dipendenze — `proc-macro2`, `quote`, `rustversion`, `generic-array`,
`icu_*` — non i programmi del progetto) e le copie byte-identiche in `target/release/deps/`.
Un glob li avrebbe inclusi tutti: la selezione è esplicita per nome di progetto.

### 16.2 Esito sui 16: zero falsi positivi, e una spiegazione

```
File analizzati: 16 in 14 s | pacchettizzati: 0 | puliti: 16
```

| | file | segnali deboli | soglia |
|---|---|---|---|
| 8 Rust + 2 Go stripped | 10 | **0** | 3 |
| 6 Go con debug info | 6 | **2** | 3 |

Score massimo 30, nessun segnale forte.

**Perché i 6 Go arrivano a 2.** Hanno una sezione a entropia **8,00** esatta. Le sezioni:

```
hello_default_g1.exe              rpncalc_stripped_g3.exe   (-ldflags "-s -w")
  .text     H 6.26                  .text     H 6.27
  .rdata    H 5.60                  .rdata    H 5.59
  /19       H 7.98                  .idata    H 4.38
  /65       H 8.00  <-- qui         .reloc    H 5.44
  /78       H 7.99                  .symtab   H 0.81
  /95       H 7.98
```

Le sezioni `/4`, `/19`, `/65`… sono **nomi lunghi COFF** (la forma `/N` rimanda alla string table
quando il nome supera 8 caratteri). In Go sono le sezioni **DWARF compresse con zlib**: da qui
l'entropia massima. Non è packing, è informazione di debug compressa. La prova: `-ldflags "-s -w"`
rimuove il DWARF, le sezioni `/N` scompaiono e l'entropia massima scende a 6,27 → **zero segnali**.

**Il margine non è fortuna.** Il terzo segnale che avrebbe prodotto il falso positivo è "nomi di
sezione non standard", e non scatta per una riga in `is_standard_section_name()`:

```python
return bool(re.fullmatch(r"/\d+", lname))  # nomi DWARF/COFF lunghi tipo "/4", "/19"
```

Scritta per i binari di sistema Windows. **Senza di essa i 6 Go sarebbero 6 falsi positivi.** È
una regola strutturale che generalizza a una toolchain su cui non era mai stata provata.

Nota: la configurazione "rischiosa" è quella **non** stripped, cioè il default dello sviluppatore.
Il malware in Go è quasi sempre stripped, quindi finisce a zero segnali.

### 16.3 Riorganizzazione dei dataset

Undici cartelle sparse fra `E:\` e il repository, con prefissi incoerenti (`DATASET_*`,
`TEST_BIN_*`) e un nome che mentiva (`TEST_BIN_PULITI`). Consolidate sotto **`E:\DATASET\`**.

**Principio adottato: la cartella corrisponde all'ORACOLO, non alla label binaria.** Unire in una
cartella `CLEAN` System32 e le estensioni PyPI farebbe perdere l'informazione che le rende
difendibili — firma Microsoft nel primo caso, provenienza PyPI nel secondo.

**Correzione all'albero inizialmente proposto.** Il primo livello non può essere `PACKED`/`CLEAN`,
perché **4 sorgenti su 6 contengono label miste**:

| cartella | contenuto reale |
|---|---|
| `system32` | 1.975 clean **+ 7 packed** (Warbird, wextract, PlayReady) |
| `pma_book` | 42 clean **+ 5 packed** |
| `flare_vm` | 19 clean **+ 7 packed** + 100 unknown |
| `malware_reali` | **4 packed** + 12 unknown |

Un primo livello per label avrebbe prodotto nomi falsi — lo stesso difetto che si stava eliminando.
Il primo livello raggruppa quindi per **affidabilità della label**: `01_LABEL_CERTA`,
`02_MATERIA_PRIMA`, `03_NON_ETICHETTATI`.

**Mappa dello spostamento** — 3.897 file su 3.897, nessun errore. Su `E:` rinomine istantanee, da
`C:` copie fra volumi. Nessun file rinominato, solo le cartelle.

| prima | adesso |
|---|---|
| `E:\DATASET_PACKED` | `01_LABEL_CERTA\matrice_packed` |
| `E:\DATASET_CLEAN_MS` | `01_LABEL_CERTA\system32` |
| `E:\DATASET_CLEAN_PYPI` | `01_LABEL_CERTA\pypi` |
| `E:\DATASET_CLEAN_GORUST` | `01_LABEL_CERTA\gorust` |
| `…\TEST_SAMPLES` | `01_LABEL_CERTA\autopacked_vecchi` |
| `E:\DATASET_MASTERS` | `02_MATERIA_PRIMA\masters` |
| `E:\DATASET_WILD` | `03_NON_ETICHETTATI\wild_malwarebazaar` |
| `E:\DATASET_BENIGN` | `03_NON_ETICHETTATI\flare_vm` |
| `…\TEST_BIN_MALWARE` | `03_NON_ETICHETTATI\malware_reali` |
| `…\TEST_BIN_PULITI` | `03_NON_ETICHETTATI\legacy_misto` |
| `…\TEST_BIN_PMA` | spostata in un secondo momento, vedi §16.9 |

**Percorsi aggiornati nel codice: 12 in 5 file** — non 2 come previsto: `pack_samples.py`
(`SOURCES` ×2, `MASTERS_DIR`, `OUTPUT_DIR`), `build_ground_truth.py` (`MATRIX_MANIFEST`, default di
`--packed-dir`, help, esempi), `extraction.py` (`OUTPUT_DIR`), `test_qiling_mpress.py` (2 path),
`validate_phase1.py` (esempio).

**Verifica:** matrice di confusione **identica** dopo lo spostamento, 353 campioni re-importati con
controllo SHA-256 su tutti (0 mismatch), suite di test **38 verdi** (1 `expectedFailure`: B8,
aperto di proposito). Lo spostamento non ha toccato una sola label, perché la ground truth è
indicizzata per contenuto e non per percorso.

### 16.4 `make_dataset_index.py` — la mappa generata

Nuovo script che scrive `E:\DATASET\INDICE.md` dai fatti: conta i campioni sul disco, legge label e
oracolo da `ground_truth.json`, aggancia le due cose con lo **SHA-256**. Riporta per cartella se
concorre alle metriche, i **file senza label** e le **label senza file**.

Un indice scritto a mano va fuori sincrono al primo file aggiunto, e a quel punto mente — il
difetto di `TEST_BIN_PULITI`.

**Al primo lancio ha subito trovato tre cose**, che è esattamente il suo scopo:

1. `gorust` (17 unknown) e `pypi` (171 unknown + 171 orfani) stavano in `01_LABEL_CERTA` **senza
   avere label**: il nome del gruppo dichiarava un'intenzione che i dati non confermavano;
2. **1.020 file senza voce nel manifest** — `flare_vm` 679, metà `test` di pypi 171,
   `wild_malwarebazaar` 169. Set mai analizzati: non un errore, ma ora visibile;
3. contava `manifest.csv` come campione (per questo `gorust` risultava 16/17). Corretto: i file di
   servizio (`.csv`, `.md`, `.json`, `.txt`) non sono campioni.

### 16.5 Etichettatura delle classi negative non-Microsoft

Generati due file di label **versionati nel repository**, non comandi una tantum, così
l'etichettatura è riproducibile su un'altra macchina:

| file | voci | oracolo |
|---|---|---|
| `config/gorust_labels.json` | 16 | compilati in proprio, con il comando di build nella nota |
| `config/pypi_labels.json` | 341 | wheel ufficiali PyPI, provenienza |

Registrata anche la metà `test` di pypi (170 file mai visti) e analizzata: **0 packed su 170**,
score massimo 15, 169 file con zero segnali deboli. È l'insieme più "pulito" dei tre.

La classe negativa passa da **2.041 tutti System32** a **2.393 con quattro oracoli indipendenti**:

| oracolo | campioni |
|---|---|
| firma Authenticode Microsoft | 1.994 |
| wheel ufficiali PyPI | 341 |
| verifica manuale (libro PMA) | 42 |
| **compilazione in proprio** | 16 |

### 16.6 Un difetto trovato nella metrica: righe contro binari

Dopo l'etichettatura, `TN = 2398` mentre la ground truth aveva 2.393 `clean`. Cinque di troppo.

Causa, verificata: **System32 contiene file byte-identici con nomi diversi.**

```
x64_MicrosoftEdgeBCHost.exe  ==  MicrosoftEdgeCP.exe  ==  MicrosoftEdgeDevTools.exe   (1 binario, 3 nomi)
x86_dplaysvr.exe  ==  dpnaddr.dll  ==  dpnhpast.dll  ==  dpnsvr.exe                   (1 binario, 4 nomi)
```

7 file su disco, **2 binari distinti**. La ground truth ha 2 voci (è per SHA-256), il CSV ha 7
righe (ed è corretto: è il log dell'analisi), ma `validate_phase1.py` contava **righe**: lo stesso
binario veniva pesato fino a 4 volte.

**Corretto nella metrica, non nel rilevatore** — che resta congelato: `load_rows()` deduplica per
SHA-256 e registra a log quali righe collassa. Numeri finali coerenti con la ground truth:
**2.393 clean + 378 packed = 2.771**.

È un difetto piccolo (0,18 % del supporto) ma del tipo che un esaminatore può trovare.

### 16.7 Stato finale della Fase 1

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** | **TP = 378** | **FN = 0** |
| **reale clean** | FP = 0 | **TN = 2.393** |

Su 2.771 campioni etichettati (2.883 righe, 112 `unknown`). **0 righe non agganciate al manifest,
0 decisioni prese con uno strumento in timeout, 38 test verdi.**

Margine sulle tre classi negative (soglia 3 segnali deboli):

| insieme | campioni | 0 | 1 | 2 | ≥ 3 |
|---|---|---|---|---|---|
| `pypi` calib | 171 | 57 | 112 | 2 | **0** |
| `pypi` test | 170 | 169 | 1 | 0 | **0** |
| `gorust` | 16 | 10 | 0 | 6 | **0** |

### 16.9 Ultimi due spostamenti, e `01_LABEL_CERTA` diventa vera

Due correzioni finali alla struttura, entrambe suggerite da quello che l'indice mostrava.

**`autopacked_vecchi` → `03_NON_ETICHETTATI`.** Stava in `01_LABEL_CERTA` ma aveva solo 8 label su
15 campioni: il nome del gruppo prometteva una certezza che quei file non hanno. È materiale
storico (output della prima `pack_samples.py`, senza seed), conservato perché 2 campioni sono
`packed` certi.

**`TEST_BIN_PMA` → `01_LABEL_CERTA\pma_book`.** Era l'unico dataset rimasto fuori dalla radice,
perché versionato in git. L'utente l'ha rimossa dall'indice git (`git rm --cached`, 48 cancellazioni
in staging, cartella aggiunta a `.gitignore`), quindi lo spostamento non produce più rumore nella
storia. Verificato prima di procedere: `git ls-files` restituisce 0 file tracciati.

Va in `01_LABEL_CERTA` e non in `03`: le sue label vengono **dal libro** (42 clean + 6 packed), che
è un oracolo di terzi indipendente da qualunque strumento della pipeline. Nell'indice risultava
già ✅.

**Risultato:** `01_LABEL_CERTA` è ora ✅ su **tutte e cinque** le cartelle, cioe' ogni campione ha
una label e concorre alle metriche. Il nome del gruppo è finalmente una descrizione, non
un'intenzione. E `EXTRA_DIRS` in `make_dataset_index.py` è vuota: nessun dataset vive fuori dalla
radice.

| gruppo | cartelle | campioni | metriche |
|---|---|---|---|
| `01_LABEL_CERTA` | matrice_packed, system32, pypi, pma_book, gorust | 2.748 | ✅ tutte |
| `02_MATERIA_PRIMA` | masters | 56 | mai valutata |
| `03_NON_ETICHETTATI` | flare_vm, wild_malwarebazaar, legacy_misto, malware_reali, autopacked_vecchi | 1.137 | ❌ qualitativa |

### 16.8 Cosa resta, e cosa no

**Resta da fare (non blocca la chiusura):**
- commit — lo fa l'utente;
- `autopacked_vecchi` sta in `01_LABEL_CERTA` ma ha solo 8 label su 15: andrebbe spostata in
  `03_NON_ETICHETTATI` o ripulita;
- `_already_packed()` in `pack_samples.py` filtra ancora solo sui nomi di sezione: la correzione
  robusta (scartare i candidati già `packed` nella ground truth) serve solo se si rigenera la
  matrice;
- fix del routing Inno → `.NET Reactor` (§13.9): **riguarda la Fase 2**, non cambia nessuna metrica
  di Fase 1.

**Dichiarato come sviluppo futuro, non fatto:**
`flare_vm` (800) e `wild_malwarebazaar` (181) mai analizzati; ConfuserEx e il .NET offuscato;
curva ROC/PR (l'output è binario); `config/tools.json` e il preflight sull'interprete — oggi il
progetto gira su una macchina sola, ed è il punto strutturalmente più debole, da dichiarare.

---

## 17. Verifica su malware reale e analisi manuale (27 settembre 2026)

### 17.1 Il run

168 malware reali da MalwareBazaar (`03_NON_ETICHETTATI\wild_malwarebazaar`), mai analizzati, in
157 s. 13 dei 181 sono stati saltati perché lo stesso **binario** era già nel CSV come
`TEST_BIN_MALWARE`: gli stessi campioni scaricati due volte, e la deduplicazione per SHA-256 ha
evitato di rianalizzarli.

**117 segnalati packed, 51 puliti.**

| tag | campioni | packed | `named`/`struct`/`weak` | DIE nomina il packer atteso |
|---|---|---|---|---|
| `upx` | 43 | 42 (97 %) | 42/0/0 | 42/43 (98 %) |
| `vmprotect` | 56 | 52 (92 %) | 15/**34**/3 | **10/56 (18 %)** |
| `themida` | 9 | 8 (88 %) | 8/0/0 | 7/9 (78 %) |
| `_senza_tag` | 60 | 15 (25 %) | 6/3/6 | — |

### 17.2 Il risultato che chiude il cerchio

Su VMProtect reale **DIE nomina 10 campioni su 56**; la Fase 1 ne segnala 52, di cui **34 solo per
via dei segnali strutturali**.

È la stessa cosa misurata sulla matrice generata in casa — DIE 0/23 su VMProtect x86 (§13.6) — ora
riprodotta su materiale reale etichettato da terzi. Una previsione ottenuta da campioni controllati
che si verifica in the wild: per l'architettura forte/debole è la validazione più forte che il
progetto potesse produrre, e non dipende da nostre etichette.

### 17.3 Analisi manuale dei 15 `_senza_tag` segnalati

Guardati uno per uno, con DIE, sezioni, entropia per sezione e lista degli import.

| # | n | verdetto | evidenza |
|---|---|---|---|
| 1 | 3 | ✅ TP | DIE nomina `.NET Reactor` (protector) |
| 2 | 2 | ✅ TP | DIE nomina `Microsoft Cabinet` (SFX) |
| 3 | 1 | ✅ TP | DIE nomina `Nullsoft Scriptable Install System` |
| 4 | 1 | ✅ TP | `.text`, `.rdata`, `.data` e `. \|V` con **raw = 0**, payload di 5,2 MB in `.&-#` a H 7,98, 2 import. Packer custom, caso da manuale |
| 5 | 5 | ✅ TP (quasi certo) | assembly .NET con `.text` a **H 7,76–7,94**: l'IL normale sta a 5–6. Uno porta l'euristica DIE `protection: Obfuscation; protection: Anti analysis` |
| 6 | **2** | ❌ **FP** | MSVC, `.text` a H **6,20** e **5,45**, sezioni tutte regolari (`.text`/`.rdata`/`.data`/`.pdata`), import: **solo** `GetProcAddress`, `LoadLibraryA`, `ExitProcess` |
| 7 | **1** | ❌ **FP** | Delphi, 188 import (kernel32, wininet, bcrypt, shell32), `.text` a H 6,43. Segnalato perché `.itext` e `.didata` risultano non standard |

**12 veri positivi, 3 falsi positivi.** Sono i **primi falsi positivi misurati del progetto**.

Nota sui 6 `named`: sono packer e installer **veri** che nessuno aveva taggato. Non sono errori del
rilevatore, sono la misura di quanto il campionamento per tag stava nascondendo — cioè lo scopo per
cui il contro-campione `_senza_tag` esisteva.

**Il punto cieco .NET è più stretto di quanto dichiarato.** I 5 campioni del caso 5 sono stati
intercettati nonostante il §12 desse il .NET per perso. L'eccezione `Is_DotNet` sopprime "pochi
import", ma entropia ed entropia dell'EP restano attive e bastano quando il crypter incorpora un
payload cifrato. Resta scoperto l'offuscamento *dell'IL*, che non alza l'entropia.

### 17.4 Le due cause dei falsi positivi, con impatto misurato

Nessuna delle due era osservabile su System32: non contiene né malware che evade né binari Delphi.

**Causa A — "IAT minimale sospetta" è un segnale FORTE troppo permissivo.**
Scatta su malware che importa solo `LoadLibrary` + `GetProcAddress` per risolvere il resto a
runtime. È evasione, non compressione: `.text` a H 5,45–6,20 è codice in chiaro.

È esattamente il caso **B8** (§7.4), che era stato lasciato aperto scrivendo *"la correzione giusta
è condizionale — pochi import più entropia alta o sezioni anomale — e richiede campioni che oggi
non esistono nel dataset"*. **Adesso esistono.**

Misura dell'impatto sui 378 packed etichettati:

| | valore |
|---|---|
| packed con "IAT minimale" fra i forti | 64 |
| packed in cui è **l'unico** segnale forte | **0** |
| veri positivi persi rendendolo condizionale | **0** |

**Causa B — `.itext` e `.didata` non sono in `STANDARD_SECTIONS`.**
Sono sezioni standard di Delphi/Borland. Un binario Delphi normale prende due segnali deboli
("EP in sezione non standard" + "nomi sezione non standard") che con l'euristica DIE fanno 3.

| | valore |
|---|---|
| packed con `.itext`/`.didata` fra le sezioni sospette | 53 (sono gli installer **Inno**, che è un programma Delphi) |
| di questi, quanti **non** hanno segnali forti | **0** |
| clean con quelle sezioni | 0 |
| veri positivi persi aggiungendole a `STANDARD_SECTIONS` | **0** |

Entrambe le correzioni sono della stessa natura delle 16 che hanno portato i FP da 23 a 0 su
System32: si corregge **la causa strutturale**, non il campione.

> **Non sono state applicate.** Applicarle richiede un `--reanalyze` completo (2.883 righe) per
> mantenere il CSV coerente, e trasforma il set wild da verifica indipendente a dato di
> calibrazione. È una decisione dell'utente.

### 17.5 I 6 con tag ma non segnalati

Non sono automaticamente falsi negativi: i tag sono label **proposte**.

| tag | cosa mostra il binario |
|---|---|
| `vmprotect` | score **0**, 150 import, H 6,45, EP in `.text` → sembra davvero non packed |
| `vmprotect` ×2 | score 30 con H 7,69 → a **un segnale** dalla soglia |
| `vmprotect` | overlay di **63 MB a H 8,0**, EP in `.text` con 185 import → dropper con payload in coda, il codice proprio non è packed |
| `themida` | 364 import, EP in `.text` → troppi import per Themida, tag sospetto |
| `upx` | 44 import, nessuna sezione UPX, DIE muto → forse già decompresso |

### 17.6 Le label wild NON sono state importate

Deliberato. Importarle farebbe entrare etichette **proposte** in un manifest che contiene solo
oracoli verificabili, e la matrice di confusione perderebbe il suo valore. Questo run va in tesi come
**analisi di accordo con i tag di MalwareBazaar**, in un paragrafo separato dalle metriche, con i due
caveat già dichiarati: circolarità e distorsione di selezione.

La ground truth resta a **2.393 clean + 378 packed = 2.771**, tutti da oracoli verificabili.

---

## 18. Pulizia e portabilità (27-28 settembre 2026)

### 18.1 Pulizia eseguita — 5,4 MB

Eliminati, tutti **untracked** e verificati uno per uno prima di procedere:

| cosa | dim. |
|---|---|
| `Pipeline_Reports/report_analisi_lief.csv.bak_*` (5 file) | 3,8 MB |
| `Pipeline_Reports/baseline_20260921_225821/` + `.last_baseline` | 976 KB |
| `scripts/__pycache__/` + `__pycache__/` | 384 KB |
| `Pipeline_Reports/pipeline_state.json.tmp` | 407 KB |
| `report_compressione.json` + `.txt` | 700 B |
| `Pipeline_Reports/analisi_pe.log` (vuoto) | 0 B |
| `GHIDRA_PROJECTS/`, `Themida_Template/` (vuote) | — |

Controllo fatto prima di cancellare `GHIDRA_PROJECTS`: `subprocesses.py:1343` la ricrea con
`os.makedirs(exist_ok=True)`, quindi la Fase 2 non si rompe. `Themida_Template` non è referenziata
da nessuno script.

**Non toccati:** CSV corrente, `ground_truth.json`, `pipeline_state.json`,
`tool_diagnostics.jsonl`, `pipeline.log`, `config/`, `Build_Samples/`, e gli output di Fase 2
(`UNPACKED_SAMPLES/` 28 MB, `TEST_QILING_OUT/` 8,7 MB, `TEST_SINGOLO/` 7 MB) — quelli contengono i
dump con `.text` a zeri, che sono l'evidenza documentale dei falsi successi di Qiling.

### 18.2 Documenti storici archiviati

Creata `docs/storico/` con:

- `AppuntiChat.md` (98 KB) — appunti di conversazione;
- `TEXT_STEPS_PROCEDURE.txt` (2,8 KB, 10 settembre) — note di procedura superate.

Restano al primo livello: `02_fase1_riferimento_tecnico.md` e `04_fase1_log_sessioni.md` (i correnti) e
**`storico/2026-09-23_status_progetto.md`**, tenuto fuori perché contiene la diagnosi della Fase 2
(§2.3 crash Qiling, §4.2 roadmap) che non è replicata altrove e che servirà quando la Fase 2 verrà
ripresa.

Entrambi i file archiviati restano coperti da `.gitignore` (i pattern senza slash valgono a
qualunque livello), verificato con `git check-ignore`.

### 18.3 Portabilità: il blocco vero, trovato e rimosso

Il progetto doveva essere zippato e passato a un'altra persona. Verificando cosa serviva davvero è
emerso un blocco che non era stato notato:

> **`parameters_info.py` importava `subprocesses` a livello di modulo**, e `subprocesses` importa
> `qiling`, `unicorn` e `pefile` alla riga 10-15. Quindi per eseguire la **sola Fase 1** con
> `--phase1-only` bisognava avere installato tutto lo stack di emulazione.

Corretto rendendo l'import **ritardato** (`_load_fase2()`), con un messaggio esplicito se lo stack
manca invece di un `ImportError` all'avvio. Verificato simulando `qiling` e `unicorn` assenti:
`parameters_info` si importa e `subprocesses` non viene caricato.

Effetto: la Fase 1 ha ora **due sole dipendenze obbligatorie**, `lief==1.0.0` e
`yara-python==4.5.4`.

### 18.4 Tre file nuovi per la portabilità

**`requirements-fase1.txt`** — il `requirements.txt` alla radice del progetto è in **UTF-16** e
contiene le dipendenze di tutto (flet, fastapi, numpy: la UI), non quelle della Fase 1. Il nuovo
file elenca il minimo con le versioni **fissate a quelle con cui i risultati documentati sono stati
prodotti**, e dice esplicitamente cosa NON serve.

**`scripts/preflight.py`** — verifica interprete, pacchetti, strumenti esterni, regole YARA e
cartelle dei dati, e per ogni cosa mancante indica **il file e la costante da correggere**. Controlla
in particolare la **major di LIEF**: l'API 1.x non è compatibile con la 0.x, ed era il difetto che
sul progetto originale rendeva inutilizzabile l'interprete di sistema. Esce con codice 0/1, quindi è
usabile anche in uno script.

**`03_setup_e_esecuzione.md`** — guida per chi riceve lo zip: interprete e pacchetti, strumenti esterni con versioni
e fonti di download, cosa fare dei dataset (non distribuibili), come eseguire, tabella dei sintomi
di errore con la causa, e il limite di portabilità dichiarato.

### 18.5 Il punto che va detto a chi riceve lo zip

**I dataset non ci sono e non possono esserci**: ~15 GB su 3.941 file, e in parte non
ridistribuibili (malware da MalwareBazaar, binari di sistema Microsoft, campioni del libro PMA).

Nello zip c'è però tutto ciò che serve a **verificare i risultati senza i binari**, perché l'aggancio
fra CSV e ground truth è lo SHA-256: `validate_phase1.py` ricalcola la matrice di confusione
partendo solo da `report_analisi_lief.csv` e `ground_truth.json`.

E c'è tutto ciò che serve a **ricostruire** la parte ricostruibile: `Build_Samples/` rigenera i 16
binari Go/Rust identici, `pack_samples.py` rigenera la matrice packed se si ha la toolchain, e le
estensioni `.pyd` si prendono dal proprio `.venv`.

### 18.6 Stato finale

| | |
|---|---|
| matrice di confusione | TP 378 · FN 0 · FP 0 · TN 2.393 su 2.771 etichettati |
| oracoli sul lato clean | 4 indipendenti (Authenticode 1.994 · PyPI 341 · PMA 42 · compilati in proprio 16) |
| verifica su malware reale | 168 campioni: 97 % UPX, 92 % VMProtect, 88 % Themida |
| falsi positivi misurati | 3, entrambe le cause individuate e quantificate (§17.4) |
| test | 38 verdi, 1 `expectedFailure` voluto |
| preflight | 0 problemi, 0 avvisi sulla macchina di sviluppo |

---

## 19. Le due correzioni ai segnali, applicate (28 settembre 2026)

### 19.1 Cosa è stato cambiato

**Correzione A — "IAT minimale sospetta" resa condizionale** (`_packing_signals()`):

```python
iat_corroborata = results["Max_Entropy_No_Rsrc"] >= 7.2 or len(anomalous) > 0
iat_non_corroborata = results["Suspicious_IAT"] == "SI" and not iat_corroborata
if results["Suspicious_IAT"] == "SI" and iat_corroborata:
    strong.append("IAT minimale sospetta (...) con compressione osservata")
# ...e fra i deboli:
if iat_non_corroborata:
    weak.append("IAT minimale senza compressione: possibile risoluzione dinamica degli import")
```

**Declassata, non scartata**: l'informazione resta leggibile nel CSV. È la correzione condizionale
che **B8** (§7.4) indicava come giusta scrivendo *"richiede campioni che oggi non esistono nel
dataset"* — i campioni sono arrivati con il set wild (§17.4).

**Correzione B — `.itext` e `.didata` aggiunte a `STANDARD_SECTIONS`**, con il commento che spiega
che sono nomi prodotti dal **compilatore** Delphi/Borland, non da un packer.

### 19.2 Un intoppo intercettato prima di eseguire

`test_iat_minimale_e_forte` codificava il **vecchio** contratto (`Suspicious_IAT="SI"` senza
entropia → forte): con la correzione avrebbe fallito. Sostituito con **tre** test:

| test | cosa fissa |
|---|---|
| `test_iat_minimale_con_compressione_e_forte` | entropia 7,6 → forte |
| `test_iat_minimale_senza_compressione_e_solo_debole` | entropia 6,2 → **non** forte, e l'informazione deve comparire fra i deboli |
| `test_sezioni_delphi_sono_standard` | `.itext` e `.didata` sono standard |

I due nuovi sono la **contro-prova permanente** dei tre falsi positivi reali: una regressione futura
si vede subito.

Verificato anche che **B8 resti `expectedFailure`**: quel test usa `Total_Imports=0`, che non attiva
`Suspicious_IAT`, quindi la correzione non lo tocca. Un `expectedFailure` che inizia a passare
viene segnalato da unittest come fallimento della suite, e sarebbe stato un falso allarme.

**40 test verdi, 1 `expectedFailure`** (erano 38 + 1). *Diventeranno 44 con i test del ripiego .NET, vedi §20.8.*

### 19.3 La rianalisi: perché 9 run e non uno

`--reanalyze` archivia il CSV **intero** e riparte da storico vuoto, ma `HL.main(dir)` analizza
**solo la cartella passata**. Quindi:

> `--reanalyze` su una cartella **cancella dal CSV vivo le righe di tutte le altre**. Restano nel
> `.bak_*`, ma il CSV attivo conterrebbe un decimo dei dati e `validate_phase1.py` misurerebbe su
> quello.

Procedura corretta: **9 run in sequenza**, la prima con `--reanalyze`, le altre otto senza.
`--reanalyze` è stato messo su `autopacked_vecchi` (15 file) e non su `system32` (1.987): archivia
il CSV in 6 secondi e fa vedere subito se il flusso funziona, invece di scoprirlo dopo 10 minuti.

| # | cartella | file | packed | puliti | tempo |
|---|---|---|---|---|---|
| 1 | `autopacked_vecchi` *(--reanalyze)* | 15 | 3 | 12 | 6 s |
| 2 | `system32` | 1.987 | **7** | 1.980 | 622 s |
| 3 | `matrice_packed` | 352 | **352** | 0 | 103 s |
| 4 | `pypi` | 341 | 0 | 341 | 101 s |
| 5 | `gorust` | 16 | 0 | 16 | 8 s |
| 6 | `pma_book` | 48 | 6 | 42 | 14 s |
| 7 | `legacy_misto` | 113 | 9 | 104 | 27 s |
| 8 | `malware_reali` | 16 | 16 | 0 | 10 s |
| 9 | `wild_malwarebazaar` | 168 | **114** | 54 | 140 s |
| | **totale** | **3.056** | | | **~17 min** |

Nota sui conteggi: alcune cartelle mostrano meno file di quanti ce ne siano su disco
(`legacy_misto` 113 su 125, `autopacked_vecchi` 15 su 15 mentre prima erano 3 righe) perché la
deduplicazione è **per contenuto**: un binario identico presente in due cartelle viene analizzato una
volta sola, sotto la prima che lo incontra. Con il CSV azzerato l'ordine è cambiato, quindi
l'attribuzione si è spostata. È corretto e voluto.

### 19.4 Esito: esattamente quello che la misura prevedeva

**I 3 falsi positivi sono spariti.** `wild_malwarebazaar` passa da 117 a **114** packed:

```
1762139fd2a2d860 (Delphi)   Is_Packed=0  score 30
    deboli: entry point in sezione non standard (.itext) | DIE euristica: packer: Generic
8f985b77b7fc449a (MSVC)     Is_Packed=0  score 30
    deboli: numero import basso (<20) | IAT minimale senza compressione: ...
ff63d6c3e73b9961 (MSVC)     Is_Packed=0  score 30
    deboli: numero import basso (<20) | IAT minimale senza compressione: ...
```

Tutti e tre a **2 segnali deboli**, uno sotto la soglia.

**E i veri positivi sono intatti.** `_senza_tag` passa da 15 a **12** segnalati, che sono
**esattamente i 12** che l'analisi manuale del §17.3 aveva giudicato veri positivi. Accordo perfetto
fra giudizio manuale e comportamento del codice corretto.

| | prima | dopo |
|---|---|---|
| `_senza_tag` segnalati | 15 (6 named · 3 struct · 6 weak) | **12** (6 named · 1 struct · 5 weak) |
| `upx` | 42/43 (97 %) | 42/43 (97 %) |
| `vmprotect` | 52/56 (92 %) | 52/56 (92 %) |
| `themida` | 8/9 (88 %) | 8/9 (88 %) |
| VMProtect: DIE nomina / structural | 10 / 34 | **10 / 34** |

**Matrice di confusione invariata:**

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** | TP = 378 | FN = 0 |
| **reale clean** | FP = 0 | TN = 2.393 |

Su 2.771 etichettati. **0 decisioni prese sotto timeout su 3.051 righe.**

### 19.5 La prova che il costo era davvero zero

Nella tabella di discriminazione per segnale, **"iat minimale sospetta" resta al 17 % (64 campioni)
sui packed**: tutti e 64 avevano entropia alta o sezioni anomale, quindi hanno conservato il segnale
forte. La previsione fatta prima di applicare ("0 veri positivi persi") è confermata sul dato.

Il nuovo segnale debole scatta su **2 campioni in tutto il corpus** — esattamente i due ex falsi
positivi, entrambi ora `clean`. È un segnale preciso, non un cerotto ad ampio spettro.

Sweep della soglia, ricalcolato: **3 resta l'ottimo unico** (a 2 → 150 FP, a 4 → 4 FN).

### 19.6 Il costo metodologico, da dichiarare

Le due correzioni **nascono dall'analisi manuale dei 168 malware wild**. Quel set non è più una
verifica indipendente: è diventato **dato di calibrazione**.

Non si può più scrivere *"verificato su 168 malware reali mai usati per tarare nulla"*. Si scrive
invece: *"terza iterazione dello stesso metodo — 23 falsi positivi su System32 corretti risalendo
alla causa strutturale, poi 3 su malware reale, stessa procedura"*. È una tesi sul **metodo di
diagnosi**, che è più difendibile di un numero che non cambia.

Il costo reale è contenuto perché quel set non era comunque una misura di recall: era un'analisi di
accordo con label proposte, con circolarità e distorsione di selezione già dichiarate (§17.6).

### 19.7 Residuo noto, non corretto di proposito

Il campione Delphi prende ancora "entry point in sezione non standard", perché quel controllo usa
`STANDARD_EXEC_SECTIONS`, una lista **diversa** da `STANDARD_SECTIONS`. Con 2 soli segnali deboli
resta correttamente `clean`, quindi non è stato toccato: aggiungere `.itext` anche a quella lista
sarebbe la correzione completa, ma va misurata prima, come sono state misurate le altre due.

---

## 20. Validazione su dataset esterno (28 settembre 2026)

### 20.1 L'obiezione che l'ha motivata

Osservazione dell'utente, corretta: *"0 FN e 0 FP mi sembra impossibile"*.

Lo è, nel senso che il risultato è reale ma misurato dove le due classi sono facilmente separabili
e dove **i casi difficili sono esclusi per costruzione**. I 3 falsi positivi trovati sul set wild
(§17) stanno in materiale senza label, quindi non entrano nella matrice: il corpus più duro è
sistematicamente fuori dal conteggio. E il 93 % dei packed è auto-generato.

Serviva un banco di prova non costruito da noi.

### 20.2 Il dataset e la verifica preliminare

**`packing-box/dataset-packed-pe`** — 3.664 campioni, 25 famiglie, fork sanificato di
`chesvectain/PackingData`. Gli autori dichiarano di aver già rimosso campioni UPX finiti per errore
in `not-packed` e deduplicato gli hash fra cartelle: hanno cioè incontrato e risolto lo stesso
problema che in questo progetto ha prodotto `NBHextract`, `RAIU` e `UHARC04`.

| cartella | campioni |
|---|---|
| `packed/` | 3.080, 25 famiglie |
| `not-packed/` | 432 — goodware: 7-Zip, Sysinternals, NirSoft, tool .NET |
| `outliers/` | 152 (142 packed + 10 not-packed) — *"campioni classificati not-packed ma con caratteristiche da packed"* |

**Verifica della loro metà `not-packed`**, con tre oracoli indipendenti dai segnali della Fase 1:

| controllo | esito |
|---|---|
| `upx -t` | **0** positivi |
| nomi di sezione da packer noti | **1** |
| sovrapposizione col nostro corpus | 5 (tutti FLARE VM) |
| non parsabili / duplicati interni | 0 / 0 |

**441 su 442 puliti.** L'unico segnalato, `Uninstall.exe`, è un disinstallatore NSIS: `.ndata` con
`raw = 0`, `.text` a H 6,46, 8 DLL importate. **Non è un errore loro**: nulla è compresso, ma DIE lo
nomina `installer: NSIS`. Divergenza di definizione — la nostra (§3) include il wrapping
SFX/installer, la loro no. Registrata nella chiave del campione come tale.

**Sovrapposizione sull'intero dataset: zero.** Hashati tutti e 3.664 i campioni, nessuno era già nel
corpus del progetto — quindi nessuno verrebbe saltato dallo storico.

### 20.3 Il protocollo del campione V1

Costruito da `scratchpad/build_v1.py`, seed **20260928**, destinazione
`E:\DATASET\04_VALIDAZIONE_ESTERNA\v1_misto`:

- **8 campioni × 25 famiglie = 200 packed**;
- **60** dalla metà `not-packed` + **tutti e 10** gli `outliers/not-packed` = 70;
- **stratificato e non casuale**: l'oggetto della misura è il recall *per famiglia*, e un
  campionamento casuale sui 3.080 avrebbe dato ~6,5 campioni per famiglia con varianza alta,
  lasciandone fuori qualcuna;
- **nomi neutri** (`v1_0001.exe` …) e ordine mescolato: una cartella chiamata `Themida` non è un
  test cieco;
- **chiave in un CSV separato**, per SHA-256, con colonna `nota_divergenza` per i casi definitori
  noti.

`Uninstall.exe` **non è finito nel campione** (60 estratti su 432).

### 20.4 Il risultato

```
File analizzati: 270 in 99s | pacchettizzati: 208 | puliti: 62
```

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** (200) | **TP = 200** | **FN = 0** |
| **reale clean** (70) | FP = 8 | TN = 62 |

**Recall 1,000** — 200 rilevati su 200.

> ⚠️ **Precision, F1 e tasso di falsi positivi non si calcolano su questo dataset.** Il protocollo
> firmato prima del run (`05_protocollo_validazione_esterna.md`, §3.2) lo vieta, per una ragione
> che regge: la metà `not-packed` **non è un oracolo**. Il fork ammette di aver rimosso da quella
> cartella campioni compressi con UPX, e per ripulirla sono stati usati rilevatori della **stessa
> famiglia dei nostri** (PEiD reimplementato, Bintropy, PyPackerDetect, REMINDer). I casi difficili
> erano già stati tolti: misurare FP = 0 là sarebbe in parte una **tautologia**, e un bias
> ottimistico — il tipo che in tesi fa più danno.
>
> Si riporta **una sola riga di matrice**, e si scrive che è una sola.

**Recall 8/8 in tutte e 25 le famiglie.** Nessuna esclusa.

**Zero falsi positivi sui 60 `not-packed` ordinari**: nessun segnale forte, score massimo 30, 49 su
60 con zero segnali deboli.

**Tutti e 8 i disaccordi vengono da `outliers/not-packed`** (8 dei 10) e sono della stessa
categoria:

| categoria | n | dettaglio |
|---|---|---|
| SFX | 7 | 5 WinZip, 2 Microsoft Cabinet |
| installer | 1 | `distutils`, installer pywin32, overlay 6,6 MB a H 8,0 |

Stessa divergenza definitoria di `Uninstall.exe`. Il fatto che non siano **sparsi** ma tutti di
**un solo tipo** è l'informazione: indica una definizione diversa, non un difetto del rilevatore.
Non sono però un tasso di falsi positivi misurato: su questo dataset non si calcola (§3.2 del
protocollo).

### 20.5 La previsione era sbagliata, e il perché è interessante

Previsione fatta **prima** del run: falsi negativi attesi su MEW, Neolite, Exe32pack e
BeRoEXEPacker — compressori piccoli e vecchi, che comprimono poco e potrebbero non raggiungere i 3
segnali deboli.

**Sbagliata: 8/8 per tutte e quattro.** Il motivo è esattamente ciò che il ragionamento aveva
trascurato: sono vecchi e *ben noti*, quindi le firme di DIE li coprono per intero. Il ragionamento
guardava ai segnali strutturali e dimenticava che su quel materiale non servono.

### 20.6 La misura che questo dataset permette: quanto pesano le firme

Evidenza sui 200 packed: `named` **195**, `weak_only` 4, `structural` 1.

| scomposizione | campioni |
|---|---|
| packed presi **senza alcun segnale forte da firma** | **13** — 8 Enigma Virtual Box, 4 Alienyze, 1 FSG |
| falsi negativi **simulando DIE assente** (via segnali forti + euristica) | **8** — tutti Amber |

Senza DIE il sistema ne prenderebbe comunque 192/200, ma il contributo strutturale qui è marginale.

**È l'opposto del caso VMProtect x86**, dove DIE nomina 0/23 sui nostri campioni e 10/56 sui malware
reali. I due risultati insieme danno la conclusione difendibile: le firme coprono bene i packer
**noti e vecchi**; falliscono sui protector **moderni** che randomizzano la propria struttura.
Nessuna delle due famiglie di segnali basta da sola, e ora entrambe le affermazioni hanno un numero.

### 20.8 Modifica al rilevatore trovata nell'albero di lavoro (non scritta in questa sessione)

Verificando lo stato finale sono emerse **51 righe non committate in `header_elf_lief.py`** che non
provengono da questa sessione, più 4 test corrispondenti. Registrate qui perché incidono sul CSV e
sui documenti.

**Cosa fa.** Aggiunge un **ripiego del segnale "stub strutturale" per gli assembly .NET**. Il
segnale originale è ancorato all'entry point, ma un assembly .NET ha `AddressOfEntryPoint = 0` per
costruzione — l'EP vero sta nell'header CLR — quindi nessuna sezione contiene l'EP,
`EP_Section_Entropy` resta 0.0 e **il segnale non può scattare, quali che siano le sezioni**.

Il ripiego cerca la stessa proprietà senza l'ancoraggio all'EP: una sezione eseguibile compressa
**più un'altra** sezione eseguibile svuotata, con il vincolo che siano **sezioni distinte** (per non
contare due volte la stessa evidenza). Scatta solo dove `Has_CLR_Header = SI` ed
`EP_Section = UNKNOWN`.

**Due colonne nuove** nel CSV, che passa da 49 a **51**: `Has_CLR_Header` e
`Exec_High_Entropy_Sections`.

**Impatto misurato: 1 riga su 3.320.**

```
x64_msvc_3c4de3f013d4_VMProtect.exe
   prima: weak_only, 4 segnali deboli su una soglia di 3
   dopo : structural, score 100
   forte: "stub strutturale (assembly .NET, nessuna sezione di EP): sezione eseguibile
           compressa .7lh e sezioni eseguibili svuotate/sproporzionate"
```

È **esattamente il campione segnalato in §13.7** come "il più fragile dell'intero dataset", a un
solo segnale dal diventare un falso negativo. La fragilità è risolta.

**Le matrici non cambiano**, perché quel campione era già classificato correttamente — solo in modo
fragile: matrice principale TP 378 / FN 0 / FP 0 / TN 2.393, validazione esterna TP 200 / FN 0 /
FP 8 / TN 62. Rimisurate entrambe a processi fermi dopo aver constatato che il CSV era stato
riscritto durante le misure precedenti.

**Suite di test: 44 verdi**, 1 `expectedFailure` (B8). I 4 test nuovi coprono il ripiego: che
scatti sul layout giusto, che non scatti senza header CLR, che pretenda due sezioni distinte, e che
non scatti su un .NET pulito.

### 20.7 Scelte di metodo, e cosa NON è stato fatto

**Le label esterne non sono state importate in `ground_truth.json`.** Deliberato: il manifest
contiene solo oracoli che possiamo garantire, e mescolarvi label di terzi abbasserebbe la qualità
media senza che si veda. Vivono in `v1_chiave.csv` e si misurano con il nuovo
`scripts/validate_external.py`, che scrive una tabella separata.

**Conseguenza sull'indice:** `make_dataset_index.py` mostra i 270 campioni di
`04_VALIDAZIONE_ESTERNA` come privi di label, perché legge `ground_truth.json`. È corretto e va
letto così: non concorrono alla matrice principale.

**I 142 `outliers/packed` non sono stati usati**: non hanno voce in `labels.json`, quindi l'unica
label disponibile sarebbe il nome della cartella — più debole delle altre.

**Passo 2 non eseguito**: il run sull'intero dataset (3.664 campioni) per il recall per famiglia su
base ampia. Ha senso solo se il passo 1 regge, e regge, quindi è la prossima cosa da fare.

---

## 21. Dataset esterno completo, e una correzione di metodo (28 settembre 2026)

### 21.1 Il protocollo che non avevo letto

Riorganizzando i documenti è emerso in `docs/` un file di 20 KB che non proveniva da questa
sessione: **`05_protocollo_validazione_esterna.md`**, redatto alle 12:25, cioè **prima** che il
campione V1 venisse lanciato. È più rigoroso del modo in cui avevo proceduto, e tre delle sue
prescrizioni invalidano parte di quanto era stato riportato al §20.

**1. Precision, F1 e tasso di falsi positivi non si calcolano su questo dataset (§3.2).**
La metà `not-packed` non è un oracolo, per tre motivi in ordine di forza: vale la regola per cui una
scansione non può dichiarare "non packed"; il fork **ammette** di aver rimosso da quella cartella
campioni compressi con UPX; e per ripulirla sono stati usati rilevatori della **stessa famiglia dei
nostri** — PEiD reimplementato, Bintropy, PyPackerDetect, REMINDer, tutti progetti dello stesso
gruppo. I casi difficili erano già stati tolti: misurare FP = 0 là è in parte una **tautologia**, e
un bias *ottimistico*.

Il `Precision 0,962 · F1 0,980` riportato al §20.4 **non andava prodotto**. Corretto nei tre
documenti e in `validate_external.py`, che ora emette una sola riga di matrice e scrive che è una
sola.

**2. Il supporto reale è 3.078, non 3.080.** Due campioni FSG non hanno magic `MZ` e vanno contati
come **non analizzabili**, mai come falsi negativi (§9.2). Il run lo ha confermato:
`Parse_Status: not_executable = 2`.

**3. Il dataset è a 32 bit** — 3.508 campioni su 3.512. Caveat assente dal §20.

E due elementi che lo rendono **più** solido di come era stato presentato: l'oracolo della metà
packed è **costruttivo** (432 freeware passati dentro 25 packer, etichetta dal nome della cartella,
nessun rilevatore coinvolto), quindi misurare DIE e YARA lì **non è circolare**; e per 2.757 coppie
esistono sia l'originale sia il derivato, cioè un disegno appaiato.

### 21.2 Deviazione dal protocollo, dichiarata

Il §5 prescrive uno split calibrazione (5 famiglie) / test (20) da eseguire **in sequenza**, con le
famiglie di test da non guardare prima di aver chiuso la calibrazione. Il campione V1 ha invece
estratto 8 file da **tutte e 25** le famiglie: la sequenzialità non è stata rispettata.

Non è fatale, perché la proprietà che il vincolo protegge è un'altra: **nessuna correzione è stata
applicata dopo aver visto un solo risultato di questo dataset**, quindi i numeri non sono
contaminati da taratura. Ma il protocollo non è stato seguito, e va scritto. Per una conferma
davvero cieca serve materiale ancora mai visto.

### 21.3 Il run completo

```
File analizzati: 3390 in 1098s | pacchettizzati: 3026 | puliti: 364
Parse_Status : lief_none=1, not_executable=2, ok=3387
Segnali forti per fonte: sezione=826, YARA=241, capa=0, DIE=2884, IAT=1195, strutturale=1140
```

I 270 di V1 sono stati saltati dallo storico per SHA-256 e conteggiati insieme: **3.508 binari
distinti**, 0 duplicati per contenuto.

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** (3.078) | **TP = 3.077** | **FN = 1** |

**Recall 0,9997.**

| gruppo | famiglie | rilevati |
|---|---|---|
| calibrazione | 5 | 598 / 598 |
| test | 20 | 2.479 / 2.480 |

### 21.4 Il numero da portare in tesi

| copertura da un prefisso di sezione | famiglie | rilevati |
|---|---|---|
| coperte | 7 | 865 / 865 |
| **scoperte** | **18** | **2.212 / 2.213** |

**La copertura è calcolata dai dati, non dedotta dal nome della famiglia**, e non coincide con la
lista a priori del protocollo §6.3:

| | famiglie |
|---|---|
| coperte nei fatti ma non nella lista | **Enigma Virtual Box** (`.enigma1`/`.enigma2`), **RLPack** (`.packed`) |
| nella lista ma non nei fatti | **NSPack**, **PECompact** — in questo dataset non producono le sezioni attese |

È una correzione al protocollo stesso: dedurre la copertura dal nome non è affidabile.

### 21.5 Il contributo delle firme, isolato

Il dataset è pubblico da anni ed è il corpus di addestramento di packing-box: non si può escludere
che parte dei match `named` venga da firme scritte conoscendolo (§6.4). Il numero che **non usa
nomi** è immune per costruzione:

- campioni senza alcun segnale forte da firma: **154**
- di questi, comunque segnalati packed: **153**

**Il caso che vale da solo: Enigma Virtual Box, 123/123 rilevati, e DIE non lo nomina mai.** Presi
tutti dal nome di sezione. È una famiglia che la firma di terzi manca per intero e che il
riconoscimento strutturale copre — lo stesso schema del VMProtect x86, su un'altra famiglia e un
altro meccanismo.

### 21.6 L'unico falso negativo, guardato a mano come prescrive il §9.1

```
amber_SmartDefragBootTime.exe        score 30 (2 segnali deboli su 3)
   import 53, export 0                entropia massima 6,63       overlay assente
   EP in .text a H 6,02, non W+X      nessuna sezione di dimensione anomala
   unica sezione sospetta: .02iME4m   DIE: solo "Generic"
```

**Nessuna compressione osservabile**: entropia da codice compilato normale, entry point nel posto
giusto, 53 import. Gli altri 151 campioni Amber sono riconosciuti da DIE come `cryptor: Amber`; su
questo DIE tace.

Classificazione secondo §9.2: **difetto del rilevatore**, e si conta. È però il caso che il
rilevatore per costruzione non può prendere: senza compressione e senza firma restano solo i nomi di
sezione, che da soli sono deliberatamente un segnale **debole**. Promuoverli produrrebbe falsi
positivi su ogni binario con sezioni non convenzionali — è la stessa ragione per cui B8 resta aperto.

### 21.7 Osservazione sugli originali, non metrica

7 dei 428 originali vengono segnalati: 4 installer, 3 con altro segnale forte. **Non sono falsi
positivi misurati.** Servono come insieme di sospetti da confrontare con i 10 che il gruppo terzo ha
isolato in `outliers/not-packed` — un controllo incrociato fra due selezioni indipendenti sullo
stesso materiale.

### 21.8 Riorganizzazione della documentazione

Tutti i documenti sono passati sotto `docs/`, numerati nell'ordine di lettura, con `git mv` per
preservare la storia dei cinque tracciati:

| prima | adesso |
|---|---|
| `PRESENTAZIONE_FASE1.md` | `docs/01_presentazione_fase1.md` |
| `FASE1_come_funziona.md` | `docs/02_fase1_riferimento_tecnico.md` |
| `SETUP.md` | `docs/03_setup_e_esecuzione.md` |
| `analisi_fase1_24092026.md` | `docs/04_fase1_log_sessioni.md` — la data nel nome era sbagliata, copre 24-28 |
| *(già presente)* | `docs/05_protocollo_validazione_esterna.md` |
| `status_aggiornamento_progetto.md` | `docs/storico/2026-09-23_status_progetto.md` |
| `AppuntiChat.md` | `docs/storico/appunti_chat.md` |
| `TEXT_STEPS_PROCEDURE.txt` | `docs/storico/procedura_passi.txt` |

**21 riferimenti incrociati** aggiornati fra documenti e `preflight.py`, zero residui. Aggiunto un
`README.md` alla radice: dopo lo spostamento il progetto non aveva più un punto di ingresso, e serve
a chi riceve lo zip.

---

## 22. Seconda classe negativa non-Microsoft — distribuzioni ufficiali (29 settembre 2026)

> **Questa sezione è scritta DOPO l'esecuzione**, a differenza di §14: il set è stato costruito e
> analizzato nella stessa sessione. L'unico impegno preso in anticipo, e mantenuto, è che **nessuna
> soglia e nessun segnale sono stati toccati dopo aver visto i risultati**: `header_elf_lief.py` non
> è stato modificato in questa sessione.

### 22.1 Perché, dopo pypi

Dopo §14 la classe negativa era a 2.393 campioni da quattro oracoli, ma **1.994 su 2.393 (83 %)
restavano firmati Microsoft**. L'obiezione "il rilevatore è tarato su una sola toolchain" era ancora
disponibile a un revisore. Serviva materiale di natura diversa, con lo stesso tipo di oracolo di
`pypi`: la **provenienza**, non un altro scanner.

Vincolo di perimetro dichiarato: **niente materiale da suite di reverse engineering** (FLARE VM e
simili contengono packer e offuscatori legittimi) e **niente installer**. Il secondo vincolo è meno
ovvio e conta di più: un `setup.exe` è *strutturalmente* compresso — `matrice_packed` usa Inno e NSIS
proprio **come packer** — quindi un installer benigno etichettato `clean` sarebbe un falso negativo
iniettato a mano nel ground truth. Per questo si scaricano solo archivi piatti (`.zip`, `.tar.xz`,
`.pkg.tar.zst`) di binari già compilati, mai gli installer che gli stessi progetti pubblicano.
Escluso anche Sysinternals: è goodware ma **è Microsoft**, già coperto da `authenticode-ms`.

### 22.2 Costruzione: `scripts/fetch_goodware_non_ms.py`

| sorgente | come si risolve la versione | digest upstream | archivi |
|---|---|---|---|
| `msys2_mingw64` | database pacman `mingw64.db` | `%SHA256SUM%` dal db | 31 |
| `msys2_msys` | database pacman `msys.db` | `%SHA256SUM%` dal db | 17 |
| `cygwin` | `setup.ini` del mirror sourceware/kernel.org | sha512 da `setup.ini` | 20 |
| `vlc` | indice di `get.videolan.org/vlc/last/win64/` | file `.sha256` upstream | 1 |
| `putty` | redirect di `/latest/` | `sha256sums` upstream | 1 |
| `notepadpp` | redirect di `/releases/latest` (non l'API REST: è rate-limited) | **assente** (solo hash sulla pagina) | 1 |
| `curl_for_win` | redirect di `latest.cgi` | **assente** (solo firma PGP) | 1 |

Nessun URL con versione cablata: si passa dal database o dal `latest` del progetto, così il set è
ricostruibile fra sei mesi senza toccare il codice. Dove il digest esiste viene **verificato prima**
di accettare l'archivio: se non combacia, il file viene cancellato. Dove non esiste, la riga di
manifest porta `archive_verified=no` — il limite è dichiarato per campione, non nascosto in una nota.

Estrazione: solo `.exe` e `.dll`, riconosciuti come PE leggendo `MZ` + `e_lfanew` -> `PE\0\0`, non
dall'estensione. I non-PE non vengono mai scritti su disco, quindi non c'è nulla da ripulire dopo.
Dedup per SHA-256 contro il manifest: i rerun sono incrementali.

**Risultato: 1.042 PE** (507 `.exe`, 535 `.dll`, 317 MB) in
`E:\DATASET\01_LABEL_CERTA\goodware_non_ms\`, in una sottocartella per sorgente. Digest upstream
verificato su **1.033 su 1.042**; i 9 restanti vengono dai due archivi che non pubblicano checksum
leggibili a macchina.

### 22.3 Tre difetti trovati e corretti prima di guardare i risultati

| difetto | come si è manifestato | correzione |
|---|---|---|
| il filtro anti-packer lavorava su **sottostringhe** | scartava `opj_compress.exe`, `opj_decompress.exe`, `compress.dll`, `libcompressor_plugin.dll` — perché *co-**mpress**-or* contiene `mpress` — e `install.exe` della coreutils GNU | confini di token nel regex (`(?<![a-z0-9])…(?![a-z])`); 6 file recuperati; test di regressione `test_skip_name_re_lavora_su_token` |
| manifest con **1.431 righe per 1.042 file** | il primo run non era morto: era morto il suo wrapper, e il processo continuava a scrivere mentre partiva il secondo. Due processi, due `seen` diversi, righe raddoppiate | lock file esclusivo (un run per volta) **più** `dedup_manifest()`, che riporta il file a una riga per hash: così il difetto si autoripara. 389 righe rimosse |
| gli archivi scaricati stavano **dentro** la cartella del dataset | `make_dataset_index.py` fa `os.walk` e avrebbe contato uno `.zip` come campione non etichettato | cache spostata nella temp di sistema |

Il file di label si rigenera **dal manifest**, non dalle righe del singolo run: un'interruzione a
metà non lascia più dataset e oracolo disallineati. È servito subito, per il run morto a metà.

### 22.4 Il risultato

`parameters_info.py --phase1-only` su 1.042 file (1.040 nuovi, 2 già a CSV), 413 s:

| | valore |
|---|---|
| classificati packed | **0** |
| classificati puliti | **1.042** |
| `Parse_Status` / `Yara_Status` / `Die_Status` | ok su 1.040 |
| decisioni con un tool in timeout | 0 |

**Zero falsi positivi su 1.042.** E il margine, che è il numero più informativo:

| segnali deboli raggiunti | file |
|---|---|
| 0 | 887 |
| 1 | 141 |
| **2 (a un passo dalla soglia)** | **14** |
| almeno un segnale forte | **0** |

DIE non ha nominato un packer su **nessuno** dei 1.042. I 14 a due segnali deboli sono binari
legittimamente ad alta entropia — `curl.exe` 7,90, `libcrypto-3-x64.dll` 7,80, un plugin di
resampling di VLC 7,69: tabelle crittografiche e coefficienti, non compressione — e sono
**esattamente i +14 falsi positivi** che compaiono nello sweep abbassando la soglia da 3 a 2
(150 -> 164). La soglia 3 non è larga per caso: il margine su materiale mai visto è di un segnale.

### 22.5 Effetto sulle metriche

| | prima | dopo |
|---|---|---|
| matrice | TP 378 · FN 0 · FP 0 · TN 2.393 | TP 378 · FN 0 · FP 0 · **TN 3.435** |
| campioni etichettati | 2.771 | **3.813** |
| oracoli della classe negativa | 4 | **5** |
| quota Microsoft della classe negativa | 83 % | **58 %** |
| limite superiore al 95 % sul tasso di FP | ~0,13 % | **~0,09 %** |

Due voci sono passate da `unknown` a `clean` per identità di hash: i due `b2sum.exe` erano già stati
analizzati in una run precedente e la Fase 1 li aveva già chiamati puliti — due veri negativi che
prima non si potevano contare.

**Un effetto collaterale da dichiarare:** 39 file già presenti altrove sul disco sono risultati
identici bit-per-bit a binari ufficiali appena scaricati — 33 in `flare_vm` (sono le coreutils Cygwin
che FLARE VM ridistribuisce), 2 in `legacy_misto`, 2 in `autopacked_vecchi`, 2 in `masters`. Hanno
ereditato la label per hash. `flare_vm` passa quindi da 112 a 145 file etichettati: il numero cambia
fra due capitoli, e questa è la ragione.

### 22.6 Cosa NON è stato fatto, e perché — ASPack, PECompact, Enigma

Valutata l'estensione della matrice packed a tre famiglie. **Nessuna aggiunta.** La verifica è stata
fatta eseguendo i tool, non leggendo la documentazione:

| packer | prova | esito |
|---|---|---|
| **ASPack 2.43** | invocato col path del file: apre la GUI e non esce (timeout, 0 byte cambiati). Anche `pcnsl.exe` è GUI | nessuna CLI, non automatizzabile |
| **Enigma** | non installato: in `E:\Tools` c'è solo `BruteForceEnigma.exe` della DidierStevensSuite | assente |
| **PECompact 3.00.2** | CLI funzionante (`PEC2.exe`, in place, rc=0, 451 KB -> 150 KB su un master x86), ma: `ABORT: PECompact can not yet compress PE+ (PE64) modules` e `Unregistered version. Your evaluation period ends in 1 days` | PE32-only e **irriproducibile dal 30/09/2026** |

Motivo che chiude il discorso anche per PECompact: **tutte e tre le famiglie sono già misurate al
100 % sul dataset esterno** (ASPack 118/118, PECompact 124/124, Enigma Virtual Box 123/123 — e Enigma
con 0 nominati da DIE, cioè preso solo dalla struttura). Aggiungerle non porterebbe informazione, e
metterebbe in `01_LABEL_CERTA` un artefatto generato da un trial scaduto, cioè non rigenerabile:
esattamente la proprietà che giustifica l'esistenza di quella cartella. Il buco reale resta il
**64 bit** (il dataset esterno è a 32 bit: 3.508 su 3.512) e nessuno dei tre lo copre.

---

## 23. I 152 campioni che erano fuori da ogni misura (30 settembre 2026)

### 23.1 Come sono venuti fuori, e cosa il protocollo diceva già

Domanda posta durante la revisione: *«non possiamo usare gli outlier del dataset scaricato che sono
puliti ma vengono scambiati per packed? e analizzare il dataset esterno solo per vedere i risultati,
senza immetterli nei nostri dati?»*

`E:\dataset-packed-pe-main\outliers\` contiene **152 file**, descritti dal README del dataset come

> *«samples we could identify as potentially disturbing our models, i.e. when they were sorted among
> the not packed samples while demonstrating characteristics of packed data»*

**Il protocollo firmato li conosceva.** Il §2.2 li elenca entrambi (`outliers/packed/` 142,
`outliers/not-packed/` 10) e annota che `outliers/` non è coperto da `labels.json`. Il §3.2 prescrive
il trattamento: *«`not-packed/` (432) e `outliers/` (152) entrano come **`unknown`**, tramite
`--scan`»*. Non è quindi una cartella sfuggita: è una cartella **mal classificata, e mai importata**.

Due cose sono andate storte, e vanno scritte entrambe:

1. **La prescrizione non è stata eseguita.** Nessuno dei 152 file ha una voce nella ground truth:
   lo `--scan` previsto non è mai stato lanciato. Erano già stati analizzati (152 su 152 nel CSV del
   run del 28/09) ma senza etichetta, quindi invisibili in ogni report.
2. **La prescrizione era sbagliata per metà.** I tre motivi con cui il §3.2 giustifica `unknown`
   riguardano tutti la metà *pulita*: la regola "una scansione non può dichiarare non-packed", il
   fork che ammette di aver rimosso UPX, i rilevatori della nostra stessa famiglia usati per
   ripulire. **Nessuno dei tre si applica a `outliers/packed/`**, che è organizzata per famiglia
   esattamente come `packed/` e ha lo stesso oracolo costruttivo — l'etichetta è il packer che è
   stato eseguito. Metterli fra gli `unknown` ha buttato 142 campioni misurabili per una ragione che
   riguardava gli altri 10.

Verificato prima di usarli:

| controllo | esito |
|---|---|
| hash distinti | 152 |
| sovrapposizione con `packed/` e `not-packed/` | **zero** — sono file in più, non copie |
| già presenti in `report_analisi_lief.csv` | **152 su 152** |
| presenti in `v2_chiave.csv` | **zero** |
| architettura | **x86 al 100 %** (campo `Machine` dell'header) |

### 23.2 La distinzione che autorizza l'uso

La risposta alla seconda domanda è che la linea non sta fra *analizzare* e *immettere*, ma fra
**analizzare** ed **etichettare**:

- analizzare non contamina niente, e lo avevamo già fatto su tutti e 3.664 i file esterni;
- etichettare richiede un oracolo, ed è il passo che decide se un file entra in una metrica;
- il protocollo §3.2 non vieta l'analisi: vieta di usare la metà `not-packed` per misurare i falsi
  positivi, e di tarare qualcosa sui risultati esterni.

I 142 file sotto `outliers/packed/` sono organizzati **per famiglia** esattamente come `packed/`,
quindi hanno lo **stesso oracolo costruttivo**: l'etichetta è il nome della cartella, cioè il packer
che è stato eseguito. Possono entrare nella misura del recall — nel tier esterno, non nella matrice
principale dei 378.

### 23.3 La chiave di risposta diventa riproducibile

`v2_chiave.csv` esisteva sul disco ma **nessuno script la produceva**: era l'unico artefatto non
riproducibile del progetto, e per di più l'oracolo con cui si misura il recall esterno.

Nuovo `scripts/make_external_key.py`: ricostruisce la chiave dall'albero delle cartelle, e con
`--verify` la confronta con quella esistente.

```
generate 3512 righe (senza outliers)
hash in comune: 3512 | differenze sui campi dedotti: 0
OK: il generatore riproduce v2_chiave.csv riga per riga.
```

**Zero differenze su 3.512 righe.** Solo dopo questa prova la chiave è stata estesa a
`v3_chiave.csv`, 3.664 righe (3.222 `packed`, 442 `not-packed`), con la nota di verifica manuale su
`Uninstall.exe` riportata invece che persa. `v2_chiave.csv` resta sul disco come record del run
firmato del 28/09.

### 23.4 Il risultato: 142 su 142

| sottoinsieme | campioni | rilevati | recall |
|---|---|---|---|
| `packed/`, le cartelle principali | 3.078 | 3.077 | 0,9997 |
| **`outliers/packed/`** | **142** | **142** | **1,0000** |
| totale | 3.220 | 3.219 | 0,9997 |

Tutti e 142 con evidenza `named`, tutte e 24 le famiglie al 100 %. Il numero che porta il risultato
in tesi — il recall sulle famiglie che nessun prefisso di sezione copre — passa da **2.212/2.213 a
2.318/2.319**. Il falso negativo resta uno solo, lo stesso di prima (Amber).

**Il valore non è l'aumento del recall**, che cambia alla quarta cifra. È che questi 142 sono i casi
difficili **selezionati da altri**: gli autori del dataset li hanno messi da parte proprio perché
sembravano non compressi. È la cosa più vicina a una selezione avversaria che questo corpus permette,
e non ne perdiamo nessuno.

Due limiti da dichiarare: non aggiungono famiglie (sono 24 delle 25 già presenti, aggiungono gli
esemplari più insidiosi di quelle), e sono **x86 al 100 %** — misurato sul campo `Machine`
dell'header — quindi il buco a 64 bit resta intatto.

### 23.5 Il controllo incrociato sui 10 `outliers/not-packed`

Qui la risposta alla prima domanda è diversa da quella che sembrava.

| | |
|---|---|
| segnalati da noi come packed | **8 su 10**, tutti con un packer **nominato** da DIE o YARA |
| non segnalati | 2 |

Gli 8 **non sono nostri falsi positivi**: sono file etichettati `not-packed` che sono probabilmente
compressi per davvero, ed è esattamente il motivo per cui i loro autori li hanno tirati fuori da
quella cartella. Due selezioni fatte con criteri diversi convergono sugli stessi file: è un
argomento a favore della rilevazione, non un errore da contare.

Quindi **non servono come classe pulita difficile**, che era la speranza iniziale. I 2 non segnalati
sì, ma solo dopo verifica manuale documentata:

- `powerMAX_x32.exe` — score 15, H 6,54, 683 import, un solo indizio debole (euristica DIE);
- `Start_Here_Win.exe` — score 15, H 6,69, 104 import, overlay di **16,9 MB a entropia 8,0**: quasi
  certamente un autoestraente, quindi probabilmente packed anche lui.

### 23.6 Un'ipotesi pre-registrata che risulta FALSA

È il risultato più importante della giornata, e non è un successo.

Il §8 del protocollo registrava, **prima del run**, tre ipotesi. La terza diceva:

> *«`outliers/not-packed/Start_Here_Win.exe` pesa 18 MB ed è un autoestraente: per la definizione del
> §4.2 **è `packed`, e segnalarlo è corretto**. Loro lo trattano come rumore da scartare, noi come
> vero positivo.»*

**Non lo segnaliamo.** Misurato adesso sulla sua riga di CSV:

| | |
|---|---|
| dimensione del file | 18,0 MB |
| sezioni PE vere | **703 KB** |
| overlay | **17,3 MB a entropia 8,0** — il 96 % del file |
| segnali forti | **nessuno** |
| segnali deboli | **uno**: `overlay grande ad alta entropia (16894 KB, H=8.0)` |
| DIE | `Microsoft Linker / Visual C++ / Windows Authenticode` — nessun packer |
| verdetto | **pulito**, `Packing_Evidence = none` |

Un file che per il 96 % è payload compresso riceve **un** indizio debole su tre. Per la definizione
strutturale del progetto quel file **è** packed, quindi questo è un mancato rilevamento vero — non
contabile come falso negativo, perché sta nella metà `not-packed` che non è un oracolo (§3.2), ma
reale.

Il valore dell'esercizio di oggi è qui: un'ipotesi scritta prima e poi verificata è l'unico tipo di
affermazione che può essere smentita, e questa lo è stata. I 142/142 confermano quello che già
sapevamo; questo singolo file dice qualcosa che non sapevamo.

**Candidato di modifica, NON applicato.** Un overlay che supera una frazione dominante del file con
entropia ≥ 7,8 potrebbe essere promosso a segnale forte, o valere due deboli. Non è stato toccato
nulla: il rilevatore è congelato (§4 del protocollo) e una modifica ai segnali va misurata su tutto
il corpus prima di essere adottata — è la disciplina che ha portato i falsi positivi da 23 a 0. Va
in Fase E come esperimento, con la contro-prova sui 3.435 puliti.

### 23.7 Una correzione al testo generato

La sezione sulla metà `not-packed` diceva *«servono come insieme di sospetti da confrontare con i 10
che il gruppo terzo ha isolato in outliers/not-packed»*. Ora quei 10 sono **dentro** i 438, quindi la
frase contraddiceva i propri dati: `validate_external.py` la sostituisce col controllo incrociato
misurato.

---

## 24. Controllo profondo prima del blocco della Fase 1 (1 ottobre 2026)

Obiettivo dichiarato: **congelare la Fase 1** per iniziare a scrivere la tesi. Non si aggiungono
dati e non si tocca il rilevatore; si riconferma quello che c'è, un test alla volta, e ogni test si
chiude con un numero prima di passare al successivo.

**Come è ancorato il congelamento, e perché non con il commit.** Un hash di commit cambia a
*ogni* commit del repository, anche quando riguarda la Fase 2: userebbe come ancora qualcosa che
si muove per ragioni estranee. L'ancora è quindi il **contenuto dei file che producono i verdetti**,
più l'ultimo commit che ha toccato il rilevatore — che si muove solo se si muove il rilevatore.

| voce | valore |
|---|---|
| `scripts/header_elf_lief.py` | `271744e0fc26f18cc4b8dd2eb471e1f1bcfc330d5820dac19a37aa6c01e35ba9` |
| `scripts/validate_phase1.py` | `601664307722d8d885bc4697286dd3c1313131ad301de8871a8a026a8338e12a` |
| `scripts/build_ground_truth.py` | `aab05282583873e573401c0ec9e6910f6cafa30a3b0917457aa48994c4385b35` |
| ultimo commit sul rilevatore | `d59264b` — *TEST FINALI* |

Verifica in un comando: `sha256sum scripts/header_elf_lief.py`.

**Due modifiche rispetto allo stato registrato nel protocollo esterno (`docs/05` §4), entrambe
verificate:**

- `header_elf_lief.py` — **ripiego .NET dello stub strutturale** (`managed_stub`, più le colonne
  `Has_CLR_Header` ed `Exec_High_Entropy_Sections`). Un assembly .NET ha `AddressOfEntryPoint = 0`
  per costruzione, quindi non ha una sezione dell'entry point su cui misurare l'entropia e il
  segnale forte non poteva scattare *mai*, qualunque fossero le sue sezioni. Il ripiego cerca la
  stessa proprietà senza ancorarsi all'EP. **Scatta su 1 binario in tutto il dataset**
  (`x64_msvc_3c4de3f013d4_VMProtect.exe`), già etichettato `packed` e già rilevato: cambia la
  qualità dell'evidenza, non il verdetto. Descritto in `docs/02`, tabella dei segnali.
- `build_ground_truth.py` — la guardia sui file di servizio del §24.1. Riguarda l'inventario, non
  la classificazione: non può cambiare un verdetto.

**La matrice non si è mossa: TP 378 · FN 0 · FP 0 · TN 3.435 su 3.813**, riverificata ricalcolandola
dal CSV. Il test 3 (§24.7) è stato rieseguito sul codice qui sopra e non ha trovato differenze.

Piano dei sette test: **0** riconciliazione dei conteggi · **1** ogni etichetta ha un oracolo ·
**2** il referto si rigenera identico · **3** determinismo del rilevatore · **4** zero decisioni
sotto timeout · **5** margine della classe negativa · **6** i casi limite uno per uno.

Il test **3** è l'unico che *scrive* — per misurare il determinismo bisogna rianalizzare, e questo
tocca il CSV — quindi va eseguito **per ultimo**: così i test 4-6 misurano l'artefatto congelato e
non uno già modificato.

### 24.1 Test 0 — riconciliazione dei conteggi

Tre numeri non tornavano fra disco, CSV e manifest. Nessuno dei tre toccava un risultato, ma ognuno
è del tipo che un esaminatore trova.

| scarto | causa, verificata |
|---|---|
| CSV 7.755 righe contro 7.750 misurate | i 5 duplicati per contenuto già noti (§16.6): 7 file, **2 binari** — `x64_MicrosoftEdge{BCHost,CP,DevTools}.exe` e `x86_dplaysvr.exe`/`dpnaddr.dll`/`dpnhpast.dll`/`dpnsvr.exe` |
| manifest 3.924 voci contro 3.923 agganciate | una voce era `gorust/manifest.csv`, un **file di servizio** entrato con una vecchia scansione |
| set esterno 3.664 file su disco contro 3.660 «binari distinti» nel referto | 4 strumenti Sysinternals (`Listdlls`, `ldmdump`, `ntfsinfo`, `portmon`) erano **già nel CSV** come `legacy_misto`, byte-identici: la deduplicazione per SHA-256 non li ha rianalizzati, quindi le loro righe portano il nome del dataset di allora |

**La catena dei numeri, chiusa:**

```
righe CSV                           7.755
- duplicati per contenuto              -5
= binari distinti analizzati        7.750   coincide col referto

voci nel manifest                   3.923   (dopo la rimozione del file di servizio)
- unknown                            -110
= usati per le metriche             3.813   = 378 packed + 3.435 clean
```

**Due correzioni applicate, entrambe alla causa e non al sintomo.**

1. *La voce di servizio.* `scan()` in `build_ground_truth.py` inventariava qualunque file, mentre
   `make_dataset_index.py` era già stato corretto per ignorare `.csv`, `.md`, `.json`… Due copie
   della stessa regola, e una sola corretta: è esattamente il modo in cui la voce è sopravvissuta
   alla correzione dell'indice (§16.4). `SERVICE_EXT` è stato spostato in `pipeline_utils.py` — il
   substrato che entrambi importano — e `scan()` ora salta i file di servizio. La voce è stata
   rimossa dal manifest, con backup.
2. *Il conteggio del set esterno.* `validate_external.py` selezionava le righe filtrando la colonna
   `Dataset`. Quella colonna registra il **run di prima analisi**, non l'appartenenza a un insieme:
   filtrarla faceva uscire dal conteggio i 4 binari già visti. Ora la selezione è per
   **appartenenza alla chiave di risposta**, e il referto dichiara sia la copertura (`3.664/3.664`)
   sia la provenienza delle righe. L'opzione `--dataset` è stata eliminata invece di essere estesa.

**Verifica:** dopo entrambe le correzioni `validation_phase1.md` si rigenera **identico byte per
byte**; il referto esterno cambia **solo** nella riga del conteggio. Nessuna metrica si muove.

### 24.2 Test 1 — ogni etichetta ha un oracolo scritto

Sui 3.813 campioni etichettati:

| regola | esito |
|---|---|
| nessun `clean`/`packed` creato da una scansione automatica | **0 violazioni** |
| nessuna etichetta senza fonte dichiarata | **0** |
| nessuna etichetta senza nota che spiega l'oracolo | **0** |

La regola di `build_ground_truth.py` — *una scansione può creare solo `unknown`* — non è stata
aggirata nemmeno una volta: tutte le 110 voci `auto-scan` sono `unknown` e restano fuori dalle
metriche.

**Il numero da riportare in tesi non è il numero di file.** I file dalla stessa fonte non sono
osservazioni indipendenti (lezione del §14.3, qui estesa ai 1.042 nuovi):

| oracolo | file | unità indipendenti |
|---|---|---|
| firma Authenticode Microsoft | 1.994 | 1 firmatario, 1 System32 |
| distribuzione ufficiale non-MS | 1.042 | **72 archivi upstream**, 7 progetti (vlc 365, msys2 478, cygwin 184, notepad++ 6, putty 6, curl 3) |
| wheel ufficiali PyPI | 341 | **28 pacchetti** (171 calib / 170 test) |
| libro PMA | 42 | 1 fonte editoriale |
| compilato in proprio | 16 | 8 profili di build, 2 toolchain |

Classe positiva: 378 = **355 dalla matrice** (53 master distinti × 8 celle: Themida 53, NSIS 53,
Inno 53, MPRESS 50, VMProtect 48, UPX 44, UPX+NSIS 44, UPX+MPRESS 10) + 13 manuali + 10 da `upx -t`.
Tracciabilità: **355 su 355 hanno `origin_sha256`**, nessun orfano.

**Questa tabella è anche la risposta a «perché serve il dataset esterno»:** la matrice in casa
poggia su **53 programmi diversi**, il set esterno su **472**. Il primo dimostra la correttezza con
etichetta certa, il secondo dimostra che non si stanno misurando 53 programmi.

### 24.3 Test 4 — zero decisioni prese sotto timeout

Verificato da **due fonti indipendenti**, che concordano.

**Dal CSV**, sulle 3.813 righe che producono la matrice:

| colonna | esito |
|---|---|
| `Die_Status` | **ok 3.813 / 3.813** |
| `Yara_Status` | **ok 3.813 / 3.813** |
| `Capa_Status` | `disabled` 3.813 / 3.813 |
| `Parse_Status` | ok 3.812, **`lief_none` 1** |

Nessuno dei quattro stati che indicano troncamento (`timeout`, `probe_timeout`, `no_banner_probe`,
`stopped_at_banner`) appare una sola volta.

**Dal log delle invocazioni** (`tool_diagnostics.jsonl`, 41.939 righe, **51 run di Fase 1**):

| tool | invocazioni | esito |
|---|---|---|
| yara | 20.551 | 20.550 ok, **1 errore** |
| die | 20.450 | **20.450 ok, zero timeout** |
| capa | 205 | 115 ok, 52 `probe_timeout`, 11 `timeout`, 21 `stopped_early`, 6 `rc_error` |

**Tutti e 63 i timeout della storia del progetto sono di capa**, e capa è `disabled` su tutte le
righe delle metriche: nessuno di quei timeout ha potuto toccare un verdetto della matrice.
Appartengono a run precedenti, sovrascritti dalla rianalisi del §19.3.

**Da dichiarare in tesi — la matrice è stata ottenuta senza capa.** `Capa_Status = disabled` su
3.813 righe su 3.813: i segnali `capa: packer nominato` (forte) e `capa: packing generico` (debole)
non hanno contribuito a un solo verdetto, e nella tabella per segnale capa non compare. Non è un
difetto, è un punto di forza: il risultato regge con **tre tool invece di quattro**, e quello spento
è il più caro (96 % del tempo di esecuzione) e il **solo** che abbia mai prodotto timeout. La
formula corretta è *disponibile, disattivato nel run misurato* — non «parte del rilevatore».

**Una riga decisa senza LIEF**, e il caso è didattico:

```
x86_mingw_9c5c58a524d5_UPX.exe
  Parse_Status : lief_none        LIEF non ha prodotto un oggetto
  label vera   : packed           oracolo: matrice, label certa
  predetto     : packed           evidenza: named
  segnale forte: DIE nomina UPX
```

È il ripiego progettato nel §13.8 che funziona su un campione reale: LIEF fallisce, il file **non
viene scartato**, la classificazione arriva da DIE. Un caso su 3.813, classificato correttamente.

Fuori dalle metriche: l'unico errore YARA del progetto è su un file del set esterno con il nome in
caratteri coreani (`winupack_PEViewer - 복사본.exe`, «copia»). Il file è stato comunque classificato
`packed` dagli altri segnali. Va nei limiti: un nome non ASCII può far fallire YARA senza fermare il
verdetto.

### 24.4 Test 5 — margine della classe negativa

`FP = 0` non dice se il risultato è solido o fortunato. Questo test misura **quanto manca** ai 3.435
puliti per superare la soglia di 3 segnali deboli.

| segnali deboli | campioni | quota |
|---|---|---|
| 0 | 2.767 | 80,6 % |
| 1 | 504 | 14,7 % |
| **2 — a un segnale dalla soglia** | **164** | **4,8 %** |
| ≥ 3 | **0** | 0 % |
| con almeno un segnale **forte** | **0** | 0 % |

Il margine peggiore è **2 su tutti e cinque gli oracoli**: nessuna classe negativa si avvicina più
di così.

| oracolo | n | 0 | 1 | 2 | peggiore |
|---|---|---|---|---|---|
| `authenticode-ms` | 1.994 | 1.610 | 243 | 141 | 2 |
| `dist-ufficiale-non-ms` | 1.042 | 887 | 141 | 14 | 2 |
| `wheel-pypi` | 341 | 226 | 113 | 2 | 2 |
| `manual` (PMA) | 42 | 34 | 7 | 1 | 2 |
| `compilato-in-proprio` | 16 | 10 | 0 | **6** | 2 |

**Riscontro incrociato con lo sweep della soglia**, calcolato in modo indipendente dal validatore: a
soglia 2 il referto dà `FP = 164`, a soglia 1 dà `FP = 668`. Qui 164 file stanno a 2 deboli e 504 a
1, e 164 + 504 = 668. Due calcoli indipendenti coincidono **esattamente**.

Nota sul tasso: `compilato-in-proprio` ha **6 file su 16 (37,5 %)** a due segnali, la quota più alta
di ogni oracolo. È coerente con il §16.2: un binario Go non stripped fa scattare da solo più indizi
deboli. La classe strutturalmente più vicina alla soglia è quella compilata in proprio, non il
malware.

### 24.5 La scoperta del test 5: 162 dei 164 dipendono dall'euristica di DIE

Guardando **quali** segnali formano le 164 coppie, la distribuzione non è uniforme:

| segnale | presenze fra i 164 |
|---|---|
| nomi sezione non standard | 94 |
| **DIE euristica: `packer: Generic`** | 91 |
| **DIE euristica: `protection: Generic`** | 61 |
| numero import basso | 49 |
| entropia sezione ≥ 7.2 | 21 |
| DIE euristica: `protection: Obfuscation` | 4 |

**162 dei 164 (98,8 %) hanno un'euristica DIE come uno dei due segnali.** Solo 2 file su 3.435
arrivano a due segnali **puramente strutturali**.

Sensibilità misurata togliendo l'euristica DIE dai deboli — solo misura, nessuna modifica al
rilevatore:

| | con euristica DIE | senza |
|---|---|---|
| puliti a 0 deboli | 2.767 | **3.193** |
| puliti a 1 debole | 504 | 240 |
| puliti a 2 deboli | **164** | **2** |
| falsi negativi introdotti | — | **4** |

Due letture, entrambe da scrivere in tesi:

1. **Il margine strutturale è più ampio di come appare.** Su struttura pura, 3.433 campioni puliti
   su 3.435 hanno **al massimo un** segnale, cioè distano due segnali dalla soglia e non uno.
2. **L'euristica di DIE è il componente che consuma quel margine**, ed è l'unico di terzi fra i
   deboli. È anche il segnale con la specificità peggiore: scatta sul 17 % dei puliti (588 file). Se
   una versione futura di DIE diventasse più aggressiva, i 162 sono i file esposti. Va dichiarato
   come limite, perché dipende da un database che non controlliamo.

**Dove quell'euristica è però determinante, e la correzione al caso Warbird.** I 4 falsi negativi
che si introdurrebbero togliendola sono `x64_ClipUp.exe`, `x64_GenValObj.exe`, `x64_sppsvc.exe` e
`x86_Windows.Media.Protection.PlayReady.dll`: tutti `weak_only` con esattamente 3 deboli, due
strutturali più l'euristica.

| file | deboli, uno per uno |
|---|---|
| `x64_ClipUp.exe` | entropia ≥ 7.2 · EP in sezione ad alta entropia (H 7.48) · DIE euristica `packer: Generic` |
| `x64_GenValObj.exe` | entropia ≥ 7.2 · EP in sezione ad alta entropia (H 7.70) · DIE euristica `packer: Generic` |
| `x64_sppsvc.exe` | EP in sezione ad alta entropia (H 7.19) · nomi sezione non standard · DIE euristica `protection: Generic; packer: Generic` |
| `x86_...PlayReady.dll` | entropia ≥ 7.2 · EP in sezione ad alta entropia (**H 7.96**, il massimo del set pulito) · DIE euristica `packer: Generic` |

Questo smentisce una frase scritta nel §4.2 e ripetuta in tre documenti — *«DIE non li segnala: il
rilevamento viene interamente dai segnali strutturali»*. La parte vera, e che resta il punto, è che
**nessuna firma li nomina**: `Die_Packer_Match = NO` e nome vuoto su tutti e quattro. La parte falsa
è *«interamente»*: l'euristica generica di DIE è il terzo indizio, e senza di essa i quattro file
passano sotto soglia. Corretto in `01_presentazione_fase1.md`, `02_fase1_riferimento_tecnico.md` e
nel §4.2 di questo documento.

Vale la pena notare la simmetria: la stessa euristica che avvicina 162 puliti alla soglia è ciò che
tiene dentro i 4 campioni più difficili della classe positiva. Non è un difetto da correggere, è un
compromesso da dichiarare con i suoi due numeri.

Per contrasto, i due `wextract.exe` dello stesso insieme sono `named` con score 100, perché su
quelli DIE **nomina** il contenitore (`sfx: Microsoft Cabinet`).

### 24.6 Test 6 — i casi limite, uno per uno

Quattro insiemi guardati singolarmente: i puliti più vicini alla soglia, i `packed` tenuti dentro
dai soli segnali deboli, il falso negativo del set esterno, e i rilevati per sola struttura.

**A. I due puliti più vicini alla soglia senza l'aiuto dell'euristica DIE.**

| file | i due segnali | lettura |
|---|---|---|
| `x64_BioIso.exe` | entropia ≥ 7.2 · nome sezione non standard (`.tPolicy`) | EP in `.text` a H **6.11** e 153 import: codice in chiaro. `.tPolicy` è una sezione legittima dei binari biometrici Microsoft, non un nome inventato da un packer |
| `x86_MLS6.dll` | entropia ≥ 7.2 · EP in sezione ad alta entropia (H 7.24) | **i due segnali vengono dallo stesso fatto** — vedi sotto |

**B. La coppia correlata: due segnali deboli che misurano un solo fatto.**

`entropia sezione >= 7.2` e `entry point in sezione ad alta entropia` sono contati separatamente,
ma quando **la sezione dell'entry point è anche la più calda del file** scattano entrambi da una
sola misurazione. Non è un difetto di implementazione: sono due proprietà diverse (quanto è calda la
sezione più calda; dove cade l'entry point) che in quella configurazione coincidono.

Quanto accade davvero, su tutto il dataset etichettato:

| | con la coppia | di cui un solo fatto | effetto |
|---|---|---|---|
| `packed` (378) | 4 | **4** | 3 scenderebbero sotto soglia se la coppia contasse 1 |
| `clean` (3.435) | 1 | **1** | `x86_MLS6.dll` sta a 2 segnali che sono 1 fatto |

**Cinque file su 3.813, lo 0,13 %** — ma si concentrano esattamente dove il margine è già sottile:

- `x64_ClipUp.exe`, `x64_GenValObj.exe` e `x86_Windows.Media.Protection.PlayReady.dll` raggiungono
  la soglia con **due fatti distinti**, non tre: l'entropia di `.text` (contata due volte) più
  l'euristica generica di DIE (§24.5). La formula «tre indizi indipendenti» non vale per loro.
- `x86_MLS6.dll`, firmato Microsoft ed etichettato `clean`, sta a due segnali prodotti da una sola
  misurazione: **basterebbe che l'euristica di DIE scattasse su di lui** per produrre un falso
  positivo su un unico fatto osservato. È il file più esposto dell'intera classe negativa.

**Non si corregge adesso, e non per pigrizia.** Far contare la coppia come un segnale introdurrebbe
**3 falsi negativi** sui campioni Warbird/PlayReady, e il rilevatore è congelato per la misura. Va
dichiarato come limite, con l'attenuante che è vera: il punto sottile cade sulla sottoclasse
*protezione del vendor*, che la pipeline **già dichiara fuori perimetro** — rilevata e dichiarata,
mai spacchettata. Se un giorno la soglia venisse ritarata, questa è la prima cosa da sistemare, e il
modo giusto è contare i *fatti* invece dei *segnali*.

**C. I 6 `packed` decisi dai soli segnali deboli.**

| file | packer | deboli (di cui strutturali) |
|---|---|---|
| `Lab18-02_…` (libro PMA) | FSG 1.0 | 6 (5) — robusto |
| `x64_SppExtComObj.Exe` | Warbird | 4 (3) — regge anche senza l'euristica DIE |
| `x64_ClipUp.exe` | Warbird | 3 (2) |
| `x64_GenValObj.exe` | Warbird | 3 (2) |
| `x64_sppsvc.exe` | Warbird | 3 (2) |
| `x86_…PlayReady.dll` | PlayReady DRM | 3 (2) |

**D. Il falso negativo del set esterno è un caso di definizione.**

```
amber_SmartDefragBootTime.exe                    famiglia: Amber
  entropia max 6.63  ·  EP in .text a H 6.02  ·  53 import  ·  overlay 0
  deboli: nomi sezione non standard (.02iME4m) | DIE euristica: protection: Generic
  DIE: nessun packer nominato
```

Entropia 6,63 con entry point a 6,02 è **codice in chiaro**. Amber non comprime e non cifra:
converte il PE in codice indipendente dalla posizione. L'alterazione strutturale che la Fase 1
cerca non c'è — resta solo un nome di sezione casuale, che da solo vale un segnale debole.

Classificato secondo il protocollo §9.2 come **caso di definizione**, non come difetto del
rilevatore. Si conta comunque fra i falsi negativi, il numero non si sconta. Era a **un segnale**
dalla soglia.

**E. I 23 rilevati per sola struttura sono tutti VMProtect, e tutti con lo stesso segnale.**

| evidenza | campioni |
|---|---|
| `named` | 349 |
| **`structural`** | **23** |
| `weak_only` | 6 |

I 23 `structural` sono **23 su 23 VMProtect**, e **23 su 23** portano il segnale forte «stub
strutturale» (EP in sezione ad alta entropia e sezione eseguibile svuotata o W+X). È la validazione
più pulita dell'architettura forte/debole che il dataset in casa possa produrre: l'unica sottoclasse
in cui un segnale forte **senza nome** porta il verdetto è esattamente il virtualizzatore su cui le
firme sono cieche. Coerente con le due misure già fatte — DIE 0/23 sulla matrice (§13.6), 10/56 sul
malware reale (§17.2).

### 24.7 Test 3 — determinismo del rilevatore

Misurato con **due metodi indipendenti**: uno a costo zero sui CSV già archiviati, uno rianalizzando
dal vivo col codice congelato. Il CSV ufficiale non è stato toccato: hash SHA-256 verificato prima e
dopo, identico.

**Metodo A — i due CSV archiviati, run a cinque giorni di distanza.**

`report_analisi_lief.csv.bak_20260928_084554` e `.bak_20260928_145240` hanno schema identico e
**3.051 binari in comune**. Confronto su tutte e 49 le colonne:

| | esito |
|---|---|
| colonne **identiche** su 3.051 binari | **40 / 49** |
| colonne che differiscono | 9, tutte spiegate |

Le 9 differenze, una per una:

| colonna | righe | causa |
|---|---|---|
| `Analyzed_At` | 3.051 | timestamp: cambia per costruzione |
| `Dataset` | 2.883 | riorganizzazione delle cartelle (§16.3): `DATASET_CLEAN_MS` → `system32` |
| `File` | 341 | sottocartelle `calib`/`test` di pypi (§14.3) |
| `Strong_Signals` | 105 | correzione del segnale «IAT minimale» (§19.1) — verificato: **tutte e 105** |
| `Suspicious_Sections` | 57 | `.itext`/`.didata` aggiunte alle sezioni standard (§19.1) |
| `Weak_Signals` | 56 | conseguenza della riga sopra |
| `Packing_Score_%` · `Is_Packed_Label` · `Packing_Evidence` | **3** | i tre cambi di verdetto voluti, vedi sotto |

**Sono identiche tutte le colonne di MISURA**, cioè l'output dei tre strumenti esterni invocati
3.051 × 2 volte: `Max_Entropy_No_Rsrc`, `EP_Section_Entropy`, `Overlay_Entropy`,
`Max_Section_Entropy` (entropie a due decimali), `Die_Detections`, `Die_All_Packers`,
`Die_Heuristic`, `Die_Packer_Name`, `YARA_Matches`, `Total_Imports`, `Total_Exports`,
`Imported_APIs`, `EP_Section`, `Anomalous_Size_Sections`, `Suspicious_IAT`, `Parse_Status`,
`Is_DotNet`, e tutti gli `*_Status`.

**I 3 cambi di verdetto sono esattamente i 3 falsi positivi del §17.3**, e questo è un riscontro che
non era stato fatto prima:

| binario | prima | dopo | correzione che lo ha mosso |
|---|---|---|---|
| `_senza_tag\1762139f…` | packed 85, `weak_only` | clean 30 | Delphi: EP in `.itext`, 188 import, H 6.73 — le sezioni Delphi aggiunte alle standard |
| `_senza_tag\8f985b77…` | packed 100, `structural` | clean 30 | 3 import, H 6.20, EP in `.text` — «IAT minimale» declassata |
| `_senza_tag\ff63d6c3…` | packed 100, `structural` | clean 30 | 3 import, H 5.45, EP in `.text` — idem |

L'affermazione del §19 — *«0 veri positivi persi»* — passa così da dichiarazione a **verifica per
diff**: fra i due run cambiano verdetto **tre binari e soltanto tre**, e sono i tre che le correzioni
dovevano sistemare.

**Metodo B — rianalisi dal vivo con il codice congelato.**

217 binari rianalizzati chiamando `analyze_with_lief` direttamente, senza passare dal CSV (nessuna
scrittura in `Pipeline_Reports`). Il campione **non è casuale**: contiene per costruzione tutti i
casi limite trovati dai test 4, 5 e 6, più una fetta a seme fisso per dataset.

| motivo della scelta | binari |
|---|---|
| `packed` `structural` — i 23 VMProtect (§24.6E) | 23 |
| `packed` `weak_only` — Warbird, PlayReady, FSG (§24.6C) | 6 |
| decisi senza LIEF (§24.3) | 3 |
| `clean` a 2 segnali strutturali (§24.6A) | 2 |
| fette a seme fisso: pma_book 47, matrice_packed 30, system32 30, goodware_non_ms 30, pypi 30, gorust 16 | 183 |

Esito su **217 binari in 815 s**:

> **Nessuna differenza su nessuna delle 50 colonne confrontate.** Le colonne che decidono —
> `Is_Packed_Label`, `Packing_Score_%`, `Packing_Evidence`, `Strong_Signals`, `Weak_Signals` —
> coincidono con il CSV congelato su 217 binari su 217.

**Un difetto trovato nel mio harness, non nella pipeline, e vale registrarlo.** Il primo giro del
confronto segnalava 9 binari su 217 diversi nella sola colonna `Imported_APIs`. Causa:
`analyze_with_lief` chiama già `_format_for_csv` alla fine (`header_elf_lief.py:1030`), e l'harness la
chiamava una seconda volta. La seconda passata non è idempotente, perché `_as_list()` filtra con
`if v` e quindi **scarta le voci vuote** — che sono gli import **per ordinale**, privi di nome —
spostando di conseguenza il troncamento a 10 elementi.

Quantificato: **551 righe su 7.752** del CSV contengono almeno un import per ordinale e cambierebbero
se formattate due volte. Nella pipeline non succede mai (la formattazione è chiamata una volta
sola), ma è una trappola per qualunque strumento di misura che rilegga e riformatti — incluso il
futuro `deep_check_fase1.py`. Dopo aver rimosso la doppia chiamata, le differenze sono **zero**.

**Cosa si può affermare in tesi, e cosa no.** Si può affermare che il rilevatore è **deterministico
sui campioni misurati**: le entropie a due decimali, l'output di DIE, i match YARA e i conteggi di
import si riproducono identici fra run diversi, a distanza di giorni, su 3.051 binari (metodo A) e
contro l'artefatto congelato su 217 (metodo B). Non si può affermare che lo sia *per costruzione*:
gli strumenti esterni restano processi separati, e la garanzia è una misura, non una proprietà
dimostrata.

### 24.8 Stato del controllo

| test | esito |
|---|---|
| 0 — riconciliazione dei conteggi | **superato**, 2 correzioni applicate |
| 1 — ogni etichetta ha un oracolo | **superato**, 0 violazioni |
| 2 — il referto si rigenera identico | **superato di fatto**: due rigenerazioni in sessione, diff vuoto |
| 3 — determinismo del rilevatore | **superato** (§24.7): 40/49 colonne identiche fra due run archiviati su 3.051 binari, e 0 differenze su 217 rianalizzati col codice congelato |
| 4 — zero decisioni sotto timeout | **superato**, con due precisazioni da portare in tesi |
| 5 — margine della classe negativa | **superato**, e ha prodotto la correzione del §24.5 |
| 6 — i casi limite uno per uno | **superato**, e ha prodotto il rilievo della coppia correlata (§24.6B) |

**Tutti e sette i test sono chiusi, e nessun numero della matrice si è mosso.**

I controlli non sono più script usa-e-getta: `scripts/deep_check_fase1.py` li riesegue tutti con un
comando, in ~15 secondi e senza scrivere nulla (`--live N` aggiunge la rianalisi del test 3). Non
codifica i numeri attesi — li stampa, e fallisce solo sugli **invarianti**, così aggiungere campioni
non rompe il controllo mentre perdere una proprietà sì. Riusa `validate_phase1.py` per la matrice,
perché due calcoli divergenti non dimostrerebbero niente sul referto.

Primo lancio: **7/7 superati**, con ogni numero identico a quelli riportati nelle sezioni qui sopra.
Un difetto trovato e corretto durante la scrittura: il confronto col referto leggeva la chiave
`confusion` invece di `cm`, e passava `None` — cioè sarebbe fallito a vuoto. È la ragione per cui lo
script ha una guardia sulle colonne attese: un controllo che non trova niente perché è rotto deve
**fallire**, non passare.

---

## Appendice — file toccati in questa sessione

| file | modifica |
|---|---|
| `scripts/pack_samples.py` | `pe_info()` + `_sec_name()` + `_already_packed()` + `_is_dotnet()`; `gather_candidates()`/`select_masters()` con diagnostica degli scarti; colonna `is_dotnet` nel manifest con backfill; commento `MULTILAYER` corretto |
| `scripts/build_ground_truth.py` | `import csv`; costante `MATRIX_MANIFEST`; funzione `import_packing_matrix()`; flag CLI `--import-packing-matrix` / `--matrix-csv`; riga d'uso nel docstring |
| `E:\DATASET_PACKED\` | 8 campioni cancellati (365 → 357); `manifest.csv` riscritto con la colonna `is_dotnet` |
| `Pipeline_Reports/ground_truth.json` | +356 voci `packed` certe (2.174 → 2.530) |
| `Pipeline_Reports/report_analisi_lief.csv` | +356 righe (2.179 → 2.535), schema invariato |
| `Pipeline_Reports/validation_phase1.{md,json}` | rigenerati: TP 382 / FN 0 / FP 0 / TN 2041 |
| `E:\DATASET_CLEAN_PYPI\` | nuovo set: 341 `.pyd` unici, split calib 171 / test 170 per pacchetto, `manifest.csv` |
| `scripts/make_dataset_index.py` | **nuovo**: genera `E:\DATASET\INDICE.md` dai fatti |
| `scripts/validate_phase1.py` | deduplicazione per SHA-256 prima del conteggio (§16.6) |
| `config/gorust_labels.json`, `config/pypi_labels.json` | **nuovi**: label versionate delle classi negative non-Microsoft |
| `E:\DATASET\` | **nuova radice**: 3.897 file riorganizzati in 3 gruppi per affidabilità della label |
| `02_fase1_riferimento_tecnico.md` | §7 riscritta (nuova struttura), §8/§9/§10/§11/§13 aggiornati |
| `03_setup_e_esecuzione.md` | **nuovo**: guida di installazione ed esecuzione per un'altra macchina |
| `requirements-fase1.txt` | **nuovo**: dipendenze minime con versioni fissate |
| `scripts/preflight.py` | **nuovo**: verifica dell'ambiente, dice cosa manca e dove correggerlo |
| `scripts/parameters_info.py` | import di Fase 2 reso ritardato: la Fase 1 gira senza qiling/unicorn |
| `docs/storico/` | **nuova**: AppuntiChat.md e TEXT_STEPS_PROCEDURE.txt archiviati |
| `scripts/header_elf_lief.py` | **correzioni ai segnali**: IAT minimale condizionale, `.itext`/`.didata` fra le sezioni standard |
| `scripts/tests/test_phase1_signals.py` | 1 test sostituito da 3: contro-prova permanente dei falsi positivi corretti |
| `01_presentazione_fase1.md` | presentazione della Fase 1, 13 sezioni (aggiunta la validazione esterna) |
| `scripts/validate_external.py` | **nuovo**, poi riscritto secondo il protocollo: una sola riga di matrice, recall per famiglia, copertura calcolata dai dati |
| `README.md` | **nuovo**: punto di ingresso alla radice |
| `docs/` | documentazione riorganizzata e numerata, 21 riferimenti incrociati aggiornati |
| `E:\DATASET_VALIDAZIONE_ESTERNA\` | **nuovo gruppo**: 270 campioni ciechi + chiave di risposta |
| `scripts/fetch_goodware_non_ms.py` | **nuovo** (§22.2): costruisce la classe negativa non-Microsoft da repository ufficiali, digest upstream verificato |
| `scripts/test_fetch_goodware_non_ms.py` | **nuovo**: self-check offline dei punti dove un bug sporcherebbe il dataset in silenzio |
| `config/goodware_non_ms_labels.json` | **nuovo**: 1.042 label `clean` versionate, oracolo `dist-ufficiale-non-ms` |
| `E:\DATASET\01_LABEL_CERTA\goodware_non_ms\` | **nuovo set**: 1.042 PE (507 exe, 535 dll) + `manifest.csv` |
| `scripts/make_dataset_index.py` | descrizione dei tre oracoli che risultavano `non documentato` in `INDICE.md` |
| `Pipeline_Reports/ground_truth.json` | +1.040 voci `clean`, 2 da `unknown` a `clean` (2.884 -> 3.924) |
| `Pipeline_Reports/report_analisi_lief.csv` | +1.040 righe (6.710 -> 7.750), schema invariato |
| `Pipeline_Reports/validation_phase1.{md,json}` | rigenerati: TP 378 / FN 0 / FP 0 / **TN 3.435** |
| `01_presentazione_fase1.md`, `02_fase1_riferimento_tecnico.md` | numeri della classe negativa e tabella degli oracoli aggiornati (5 oracoli, 3.435 puliti, ~0,09 %) |
| `scripts/make_external_key.py` | **nuovo** (§23.3): rigenera la chiave del dataset esterno dall'albero delle cartelle; `--verify` dimostra che riproduce `v2_chiave.csv` riga per riga |
| `scripts/validate_external.py` | chiave di default a `v3_chiave.csv`; sezione dedicata a `outliers/`; controllo incrociato sui 10 `outliers/not-packed` |
| `E:\DATASET\04_VALIDAZIONE_ESTERNA\v3_chiave.csv` | **nuova**: 3.664 righe (v2 + i 152 di `outliers/`). `v2_chiave.csv` resta come record del run firmato |
| `Pipeline_Reports/validation_external_dataset_packed_pe.md` | rigenerato: supporto 3.220, recall 0,9997, `outliers/packed` 142/142 |
| `04_fase1_log_sessioni.md` | questo documento |

**Non toccati:** `header_elf_lief.py`, `pipeline_utils.py`, `parameters_info.py`,
`subprocesses.py`, `validate_phase1.py`, `report_analisi_lief.csv`, `E:\DATASET_MASTERS`.

**Backup nello scratchpad di sessione:** `pack_samples.py.bak`, `build_ground_truth.py.bak`,
`manifest_prima_della_pulizia.csv`, `ground_truth_prima_import.json`.
