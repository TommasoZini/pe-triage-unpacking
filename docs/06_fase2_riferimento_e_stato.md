# Fase 2 — Unpacking automatico: come funziona, cosa manca

**Documento di riferimento e diario della Fase 2.** Spiega cosa fa la Fase 2, come è costruita, come
si misura, quali difetti ha e cosa resta da implementare. È il gemello di
`02_fase1_riferimento_tecnico.md`, tenuto separato perché le due fasi hanno maturità molto diversa:
la Fase 1 è chiusa e validata, la Fase 2 è in costruzione.

Aggiornato all'**11 ottobre 2026** (Fasi A-E concluse, più il set di controllo a 64 bit). Branch `unpacking`, cartella `Unpacking/Packing`.

> La diagnosi storica dei difetti di Qiling (settembre 2026) sta in
> `storico/2026-09-23_status_progetto.md` e non è replicata qui: questo documento descrive lo stato
> **attuale** del codice.

---

## Indice

1. [Cosa fa la Fase 2 (e cosa non fa)](#1-cosa-fa-la-fase-2-e-cosa-non-fa)
2. [Il perimetro: solo PE Windows](#2-il-perimetro-solo-pe-windows)
3. [L'architettura: la cascata multilayer](#3-larchitettura-la-cascata-multilayer)
4. [Il percorso di un singolo file, passo per passo](#4-il-percorso-di-un-singolo-file-passo-per-passo)
5. [Gli strumenti: cosa copre ciascuno](#5-gli-strumenti-cosa-copre-ciascuno)
6. [Come si decide che l'unpacking è riuscito](#6-come-si-decide-che-lunpacking-è-riuscito)
7. [Gli script, i parametri e il codice che decide](#7-gli-script-i-parametri-e-il-codice-che-decide)
8. [Come si esegue](#8-come-si-esegue)
9. [I risultati](#9-i-risultati)
10. [Problemi noti e difetti aperti](#10-problemi-noti-e-difetti-aperti)
11. [Cosa manca da implementare](#11-cosa-manca-da-implementare)
12. [Cosa la Fase 2 non sa fare (limiti dichiarati)](#12-cosa-la-fase-2-non-sa-fare-limiti-dichiarati)

---

## 1. Cosa fa la Fase 2 (e cosa non fa)

La Fase 2 riceve i file che la Fase 1 ha etichettato `Is_Packed_Label = 1` e, per ognuno, prova a
rispondere a una sola domanda:

> *Riesco a ricostruire il contenuto originale di questo file, senza intervento umano?*

Produce un file scompattato in `UNPACKED_SAMPLES/` e una riga di esito in `pipeline_state.json`.

**Non fa altro.** In particolare **non** dice se il file è un malware, **non** analizza il
comportamento del payload, e **non** ricostruisce la tabella degli import (vedi §12).

L'obiettivo dichiarato non è "spacchettare tutto": è **ridurre al minimo i casi che finiscono
sull'analisi manuale in IDA Free**, e sapere con precisione quanti sono.

---

## 2. Il perimetro: solo PE Windows

La Fase 2 tratta **eseguibili PE Windows (.exe e .dll)**. L'ELF è rinviato a sviluppo futuro:
è una scelta esplicita, non un'omissione.

Conseguenza nel codice: `get_binary_info()` ritorna `None` per qualunque file che non sia un PE, e
il chiamante lo salta registrando `final_status = "out_of_scope_not_pe"`. Prima il ripiego era
`(True, True)`, cioè "PE a 64 bit": un ELF o un file malformato veniva mandato all'emulatore e ci
bruciava fino a 600 secondi prima di fallire.

**Le DLL sono coperte solo in parte.** Gli unpacker statici (UPX in testa) le trattano
normalmente, ma il ramo emulato le salta: l'entry point di una DLL è `DllMain` e richiede
argomenti che l'emulazione come eseguibile non fornisce. Sul materiale su disco sono 16 file su
816, quindi l'impatto pratico è trascurabile — ma la frase "PE exe e dll" va sempre accompagnata da
questa precisazione.

---

## 3. L'architettura: la cascata multilayer

La Fase 2 è una **cascata**: tecniche a costo crescente, ognuna tentata solo se la precedente ha
fallito. Il criterio d'ordine è il costo, non l'eleganza: ogni tentativo evitato è tempo
guadagnato.

L'intera cascata si **ripete fino a 5 volte sullo stesso file**, usando l'output di un giro come
ingresso del successivo. Serve ai campioni con più strati di packing sovrapposti (per esempio UPX
esterno più un secondo packer interno), dove un solo passaggio lascia il payload ancora offuscato.

Il ciclo si ferma prima del limite se nessuno strumento rimuove un ulteriore strato, oppure se
`looks_still_packed()` non vede più segnali di packing sul file appena prodotto.

| | tecnica | costo | rischio |
|---|---|---|---|
| 1 | unpacking statico (UPX, AspackDie, InnoUnp) | secondi | nullo |
| 2 | emulazione (Unipacker a 32 bit, Qiling a 64 bit) | minuti | nullo, è emulazione |
| 3 | esecuzione reale (`mal_unpack`) | secondi | **alto, disattivato di default** |
| 4 | verifica con Ghidra headless | ~1 minuto | nullo |
| 5 | IDA Free, intervento umano | indefinito | nullo |

Lo step 3 esegue davvero il campione sulla macchina. È disattivato (`MAL_UNPACK_ENABLED = False`)
e va acceso solo dentro una VM isolata con rete spenta e snapshot pulito.

---

## 4. Il percorso di un singolo file, passo per passo

1. **Identificazione.** Il file è identificato dal suo SHA-256, non dal nome: un campione
   rinominato o duplicato resta lo stesso campione.
2. **Ripresa.** Se in una run precedente era già stato risolto, viene saltato — a meno di `--force`.
3. **Perimetro.** Se non è un PE, viene scartato con il motivo registrato.
4. **Instradamento.** Se la Fase 1 ha identificato il packer per nome (`Die_Packer_Name`), si prova
   subito lo strumento giusto invece di tentarli tutti in ordine.
5. **Cascata.** UPX (due tentativi: normale e forzato) → AspackDie → InnoUnp → emulazione →
   `mal_unpack` se abilitato.
6. **Ripetizione.** Se è stato rimosso uno strato e il file sembra ancora impacchettato, si
   ricomincia dal punto 4, fino a 5 giri.
7. **Verifica.** Ghidra headless analizza il risultato e conta le funzioni trovate.
8. **Esito.** Se la verifica convince, il file è chiuso come `unpacked_ok`. Altrimenti va alla
   revisione umana: IDA Free, oppure — con `--defer-ida` — la coda.
9. **Registrazione.** L'esito viene scritto in `pipeline_state.json`, e a fine batch forzato su
   disco.

---

## 5. Gli strumenti: cosa copre ciascuno

| strumento | copre | dove sta |
|---|---|---|
| **UPX** | il packer più diffuso; `-d` e `-d --force` per gli header alterati | `UPX_PATH` |
| **AspackDie** | ASPack 2000–2.12. Strumento grafico: su un file non-ASPack apre una finestra bloccante, quindi viene ucciso dopo 8 s | `ASPACKDIE_PATH` |
| **InnoUnp** | installer Inno Setup | `INNOUNP_PATH` |
| **Unipacker** | PE a **32 bit**: UPX, ASPack, PEtite, FSG, MEW, MPRESS, PECompact, YZPack, più un unpacker generico per packer sconosciuti | pacchetto pip |
| **Qiling** | PE a **64 bit**: emulazione dell'intero sistema operativo, con euristica OEP "scrivi-poi-esegui" | pacchetto pip |
| **mal_unpack** | qualunque packer, anche sconosciuto — ma **esegue davvero** il campione | `MAL_UNPACK_PATH`, spento |
| **Ghidra headless** | verifica automatica del risultato | `GHIDRA_HEADLESS_PATH` |
| **IDA Free** | ultima risorsa, manuale | `IDA_PATH` |

**Perché due emulatori e non uno.** Unipacker lavora solo a 32 bit ma conosce i packer classici per
firma, quindi è veloce e preciso dove arriva. Qiling emula un Windows a 64 bit completo e non
conosce nessun packer: trova l'entry point originale osservando il comportamento, il che lo rende
generico ma lento.

**L'euristica di Qiling, in parole semplici.** Un packer, per poter eseguire il programma originale,
deve prima scriverselo in memoria. Quindi: si tiene una fotografia della memoria all'avvio, e si
considera "punto d'ingresso originale" il primo indirizzo eseguito che si trova in una zona di
memoria **riscritta dal programma stesso** dopo l'avvio. Due filtri evitano i falsi allarmi: si
ignorano le primissime istruzioni (avvio del runtime) e si richiede che sia stata scritta una
quantità di memoria plausibile, non una singola correzione di pochi byte.

---

## 6. Come si decide che l'unpacking è riuscito

Questa è la parte rifatta il 29 settembre 2026, ed è la più importante.

### Il criterio vecchio, e perché non bastava

Fino a oggi l'unico giudice era Ghidra: se trovava almeno 5 funzioni nel file scompattato, l'esito
era "riuscito". Quel criterio ha già promosso a successo un file con la sezione del codice
**interamente a zeri** (`awk_C57F`: 1011 funzioni dichiarate, contenuto vuoto). Un criterio che
sbaglia in questo modo non produce numeri ottimisti: produce numeri **senza significato**.

### Il criterio nuovo: il confronto con l'originale

I campioni della matrice `matrice_packed` sono stati creati impacchettando file originali puliti, e
il manifest conserva l'impronta dell'originale (`origin_sha256`). I 53 originali sono tutti su
disco. Quindi si può fare la cosa ovvia: **confrontare il file scompattato con l'originale**.

Il confronto avviene sulle sole parti eseguibili, allineate per posizione in memoria, così non
dipende da come i due file sono organizzati su disco. Tre risposte, non due:

| esito | significato |
|---|---|
| **ricostruito** | il contenuto coincide con l'originale oltre il 95% |
| **parziale** | c'è del codice, ma non coincide (import non ricostruiti, indirizzi riposizionati, oppure ci si è fermati a uno strato intermedio) |
| **fallito** | la sezione è assente, o è tutta a zeri |

La categoria di mezzo è esattamente quella che il criterio Ghidra contava come successo.

### Il limite dichiarato sui protector

Su **Themida e VMProtect** l'identità con l'originale **non è il bersaglio** e non lo sarà mai:
quei due non comprimono il codice, lo riscrivono in una forma diversa. Su quei campioni `parziale`
è l'esito buono. Sono 101 dei 353, e sono riportati in una tabella separata che **non concorre** al
tasso di ricostruzione. L'identità stretta si rivendica sui 252 campioni con compressori e
installer.

### Come leggere i tre esiti: la distribuzione è bimodale

Le tre etichette suggeriscono una scala continua — ricostruito, poi parziale, poi fallito — e il
corpus dice il contrario. Sui 353 campioni della Fase E i 210 confronti effettivamente misurati si
ammassano ai due estremi:

| corrispondenza | campioni | chi sono |
|---|---|---|
| esattamente **1.0000** | 141 | UPX, 7-Zip, e la maggior parte di Qiling e Unipacker |
| 0.9990 – 0.9999 | 18 | ricostruiti |
| 0.9586 – 0.9989 | 19 | ricostruiti: rilocazioni applicate e IAT non ricostruita (A7) |
| 0.857 | **1** | un MPRESS a 32 bit con Unipacker: l'unico quasi-centro del corpus |
| 0.0370 – 0.1412 | 31 | 26 Themida a 64 bit, 2 catene UPX+MPRESS parziali, 3 falliti con sezione a zeri |

Fra 0.1412 e 0.857 non c'è **nessun** campione, e fra 0.857 e 0.9586 nemmeno. **In mezzo c'è un
file su 353.** Da qui quattro conseguenze su come vanno letti i numeri della fase.

**1. Quando la cascata funziona il risultato è byte-identico, non approssimato.** Il 71% non
significa "71% fatto imperfettamente": significa **71% fatto esattamente e 29% non fatto affatto**.
I 37 ricostruiti sotto 1.0000 sono l'unico degrado graduale di tutto il corpus, e ha una causa
sola: il dump è un'istantanea di memoria, dove le rilocazioni sono già applicate e la IAT no (A7).

**2. `parziale` su un protector va sempre accompagnato dal suo numero.** Scrivere che su Themida
`parziale` è l'esito buono è corretto ma si legge male: fa pensare a una ricostruzione quasi
riuscita. La corrispondenza mediana di quei 26 campioni è **0.0678**, con massimo 0.1412. I byte
originali non ci sono, perché Themida non li comprime: li sostituisce con bytecode per una propria
macchina virtuale. Quel 7% è sovrapposizione incidentale — allineamenti, boilerplate del
compilatore, stub del runtime. Su un protector `ricostruito` non è un obiettivo difficile, è un
obiettivo **mal posto**, e la rivendicazione corretta è "analizzabile", non "ricostruito".

**3. `fallito` quasi sempre significa "nessun file da confrontare", non "file sbagliato".** Dei 143
falliti, **140 portano la nota `nessun output prodotto`**: lo strumento si è rifiutato o si è
fermato prima, e l'oracolo non ha mai avuto niente fra le mani. Solo 3 — catene UPX+MPRESS — hanno
prodotto un file con la sezione eseguibile a zeri. Restano 2 `non_processato` e 1
`non_confrontabile` (output non riconosciuto come PE). Quindi i fallimenti della Fase 2 **non sono
errori di ricostruzione**: sono rifiuti a monte, ognuno con la sua causa già diagnosticata — 53
Inno (A2b), 48 VMProtect (A11), 27 Themida a 32 bit (Unipacker non copre Themida), 9 MPRESS e 3
catene (A3).

**4. I due rami della cascata falliscono per ragioni diverse, e nessuno dei due "lavora male".**
L'unpacker dedicato fallisce sul **formato**: riconosce la firma e inverte esattamente, oppure non
parte — UPX ricostruisce 85 file con corrispondenza mediana 1.0000, o non produce nulla.
L'emulatore fallisce sulle **difese**: deve far girare lo stub abbastanza perché finisca di
decomprimere, e VMProtect lo ferma col controllo di integrità mentre Themida lo lascia girare ma
non ha niente da restituire. Dove niente si oppone è preciso anche lui: 0.9997 mediano sui 24
MPRESS a 64 bit, e **zero fallimenti su tutto ciò che ha tentato**.

**Una precisazione che evita un malinteso ricorrente.** Che i campioni siano stati compilati e
impacchettati in casa **non aiuta lo spacchettamento**: la cascata non vede mai l'originale, lo
vede solo `validate_phase2.py` a cose fatte, per dare il voto. Avere l'originale rende il risultato
**verificabile**, non più facile da ottenere — è la differenza fra il metro e la cosa misurata. Ed
è anche il motivo per cui la Fase F (§11) serve: lì i packer non sono i nostri.

### Il metro verificato prima dell'uso

`validate_phase2.py --selftest` confronta un file con se stesso (deve dare 1.0) e con un file
diverso (deve dare molto meno). Se questi due numeri non tornano, non ha senso guardare gli altri.

---

## 7. Gli script, i parametri e il codice che decide

### 7.1 I file

| file | ruolo |
|---|---|
| `scripts/subprocesses.py` | tutta la Fase 2: cascata, strumenti, hook di Qiling, Ghidra, IDA |
| `scripts/parameters_info.py` | orchestratore: esegue Fase 1, poi Fase 2 sui file trovati impacchettati |
| `scripts/validate_phase2.py` | **l'oracolo**: confronto con l'originale, report, generazione del sottoinsieme di baseline |
| `scripts/ghidra_scripts/basic_info_report.py` | script Jython eseguito da Ghidra. La direttiva `# @runtime Jython` **deve** restare la prima riga del file |
| `scripts/tests/test_phase2_oracle.py` | 8 controlli, senza campioni reali e senza il disco dei dataset |

| output | contenuto |
|---|---|
| `UNPACKED_SAMPLES/` | i file scompattati |
| `Pipeline_Reports/pipeline_state.json` | esito per campione, indicizzato per SHA-256 |
| `Pipeline_Reports/validation_phase2.md` / `.csv` | il confronto con gli originali |
| `Pipeline_Reports/report_riepilogo_unpacking.json` | contatori della **singola run**, sovrascritti a ogni esecuzione: **non sono misure di corpus** (vedi A14) |
| `Pipeline_Reports/tool_diagnostics.jsonl` | una riga per ogni tentativo di ogni strumento, con durata ed esito |
| `GHIDRA_PROJECTS/` | progetti Ghidra temporanei |


### 7.2 Tutti i parametri in un posto solo

Ogni numero che governa la Fase 2 sta in testa a `scripts/subprocesses.py`, tranne le due soglie
dell'oracolo che stanno in `scripts/validate_phase2.py`. Nessuno di questi valori è scelto per
estetica: dove la colonna *perché* riporta una misura, quella misura è nel §9 o nel §10.

**Percorsi degli strumenti**

| costante | valore | riga |
|---|---|---|
| `UPX_PATH` | `E:\Tools\upx\upx-5.1.1-win64\upx.exe` | 53 |
| `IDA_PATH` | `C:\Program Files\IDA Free 9.4\ida.exe` | 54 |
| `ASPACKDIE_PATH` | `E:\Tools\UniExtract\UniExtract\bin\AspackDIE.exe` | 67 |
| `INNOUNP_PATH` | `E:\Tools\UniExtract\UniExtract\bin\innounp.exe` | 84 |
| `SEVENZIP_PATH` | `C:\Program Files\7-Zip\7z.exe` | 92 |
| `MAL_UNPACK_PATH` | `E:\Tools\mal_unpack\mal_unpack.exe` | 97 |
| `GHIDRA_HEADLESS_PATH` | `…\ghidra_12.0.4_PUBLIC\support\analyzeHeadless.bat` | 129 |
| `UNIPACKER_PATH` | **ricavato a runtime** dall'interprete in uso | 122 |

Unipacker è l'unico che non ha un percorso scritto a mano, e c'è una ragione misurata:

```python
# riga 122 — l'eseguibile sta in Scripts/ del venv, che NON e' nel PATH quando la pipeline
# viene lanciata invocando direttamente il python del venv: 50 tentativi su 50 finivano in
# "[WinError 2] file non trovato" in 0,0 s, cioe' Unipacker non era MAI stato eseguito.
UNIPACKER_PATH = os.path.join(os.path.dirname(sys.executable), "unipacker.exe")
if not os.path.exists(UNIPACKER_PATH):
    UNIPACKER_PATH = "unipacker"          # ripiego: installazione di sistema gia' nel PATH
```

**Tempi massimi concessi a ciascuno strumento**

| costante | valore | riga | perché |
|---|---|---|---|
| UPX (letterale) | 15 s | 351 | decompressione statica, non emula |
| `ASPACKDIE_TIMEOUT` | 8 s | 76 | è grafico: su un file non-ASPack apre una finestra bloccante |
| `INNOUNP_TIMEOUT` | 60 s | 85 | |
| `SEVENZIP_TIMEOUT` | 120 s | 93 | |
| `UNIPACKER_TIMEOUT` | 300 s | 126 | misurato: un MPRESS a 32 bit impiega ~100 s. I 30 s precedenti tagliavano l'emulazione a metà |
| `QILING_EMU_TIMEOUT_SEC` | 600 s | 179 | |
| `GHIDRA_ANALYSIS_TIMEOUT_PER_FILE` | 480 s | locale | limite interno di Ghidra |
| `GHIDRA_TIMEOUT` | 600 s | locale | timeout del processo Python: margine sopra il precedente |

**Soglie di decisione**

| costante | valore | riga | cosa decide |
|---|---|---|---|
| `MIN_FUNCTIONS_THRESHOLD` | 5 | 137 | quante funzioni deve trovare Ghidra perché l'esito convinca |
| `MULTILAYER_MAX_LAYERS` | 5 | 161 | quanti giri di cascata al massimo sullo stesso file |
| `MULTILAYER_ENTROPY_THRESHOLD` | 7.2 | 165 | sopra questa entropia il file sembra ancora impacchettato (stessa soglia della Fase 1) |
| `QILING_OEP_WARMUP_BLOCKS` | 200 | 185 | blocchi ignorati all'avvio: l'avvio del runtime non è un salto nel payload |
| `QILING_MIN_WRITTEN_BYTES` | 4096 | 188 | byte scritti minimi perché sia un payload e non una correzione di rilocazione |
| `QILING_MAX_LAYERS` | 4 | 190 | transizioni registrate in **una** emulazione |
| `MIN_VALID_DUMP_ENTROPY` | 1.0 | 203 | sotto questa, le sezioni del dump sono vuote: risultato scartato |
| `MIN_FREE_DISK_MB` | 500 | 144 | sotto questa soglia il batch si ferma invece di produrre dati corrotti |
| `MATCH_OK` | 0.95 | `validate_phase2.py` 64 | byte coincidenti per dichiarare `ricostruito` |
| `NONZERO_MIN` | 0.05 | `validate_phase2.py` 65 | sotto questa frazione di byte non-zero la sezione è vuota |

**Interruttori**

| costante | valore | riga | effetto |
|---|---|---|---|
| `MAL_UNPACK_ENABLED` | `False` | 112 | l'unico passo che **esegue davvero** il campione |
| `DEFER_IDA` | `False` | 136 | con `--defer-ida` diventa `True`: IDA non si apre e il batch prosegue |
| `QILING_RDTSC_BYPASS` | `False` | 192 | hook per istruzione: costoso, si accende solo se lo stub usa `rdtsc` |
| `QILING_USE_RAW_UC_HOOKS` | `True` | 202 | hook direttamente su Unicorn: il wrapper di Qiling costa molto di più |

---

### 7.3 Come viene invocato ogni strumento

La riga di comando effettiva, presa dal codice. È l'informazione che serve per rieseguire a mano
un singolo passo quando un campione si comporta in modo strano.

```python
# UPX — due tentativi, il secondo recupera gli header alterati apposta  (riga 341)
attempts = [
    ("standard",          ["-d", filepath, "-o", unpacked_path]),
    ("forzato (--force)", ["-d", "--force", filepath, "-o", unpacked_path]),
]

# AspackDie — nessuno switch silenzioso documentato: genera "unpacked.exe"
# nella stessa cartella dell'input                                       (riga 405)
command = [ASPACKDIE_PATH] + ASPACKDIE_ARGS + [filepath]

# InnoUnp — -d SENZA spazio dopo, -b batch, -y assume sì              (riga 492)
command = [INNOUNP_PATH, "-x", f"-d{extract_dir}", "-b", "-y", filepath]

# 7-Zip — estrazione in cartella dedicata                              (riga 544)
subprocess.run([SEVENZIP_PATH, "x", filepath, f"-o{extract_dir}", "-y"], ...)

# Unipacker — -d e' una CARTELLA, e il file esce come unpacked_<nome>  (riga 616)
subprocess.run([UNIPACKER_PATH, filepath, "-d", work_dir], ...)

# Ghidra headless — il postScript Jython scrive il report              (righe 1574, 1610)
command = [GHIDRA_HEADLESS_PATH, GHIDRA_PROJECTS_DIR, GHIDRA_PROJECT_NAME, "-import", filepath]
command += [
    "-scriptPath", GHIDRA_SCRIPTS_DIR,
    "-postScript", "basic_info_report.py", report_path,
    "-analysisTimeoutPerFile", str(GHIDRA_ANALYSIS_TIMEOUT_PER_FILE),
    "-deleteProject", "-overwrite",
]

# IDA Free — l'unica modalita' supportata dall'edizione gratuita       (riga 1677)
command = [IDA_PATH, filepath]
```

Qiling non ha una riga di comando: è una libreria, istanziata con la rootfs dell'architettura e
poi guidata dagli hook (§7.4).

---

### 7.4 Il codice che decide — tre estratti

Il resto del modulo è impalcatura. Queste tre decisioni sono il contenuto.

**L'instradamento: perché un installer non va emulato.** Si leggono **tutte** le rilevazioni di
DIE, non la sola principale — sui 53 campioni Inno la principale è `.NET Reactor`, che è un falso
positivo su binari senza header .NET (difetto A10).

```python
# subprocesses.py, riga 1845
is_installer = (hint_type in ("installer", "sfx")
                or "(installer)" in hint_all or "(sfx)" in hint_all)
```

**L'euristica OEP: scrivi-poi-esegui, senza osservare le scritture.** Un packer deve scrivere il
payload prima di poterlo eseguire. Osservare ogni scrittura costerebbe una callback Python per
byte; invece si tiene una fotografia dell'immagine e si guarda se i byte a quell'indirizzo sono
**cambiati** rispetto a essa.

```python
# subprocesses.py, dentro check_block()
probe = bytes(ql.mem.read(address, 16))
if probe == st["snap"][rel:rel + 16]:
    st["ok_blocks"].add(address)     # codice originale, non e' una transizione
    return
```

**L'oracolo: tre esiti, e l'ordine dei controlli conta.** La sezione vuota si verifica **prima**
della corrispondenza: un dump a zeri può avere una somiglianza alta per puro caso, e senza questo
controllo verrebbe promosso a `ricostruito`.

```python
# validate_phase2.py, riga 104
def verdict(match, nonzero):
    if nonzero < NONZERO_MIN:
        return "fallito"
    if match >= MATCH_OK:
        return "ricostruito"
    return "parziale"
```

---

## 8. Come si esegue

```bash
python scripts/validate_phase2.py --selftest                              # il metro funziona?
python scripts/validate_phase2.py --make-baseline BASELINE --per-group 5  # sottoinsieme di misura
python scripts/parameters_info.py --dir "<cartella>" --yes --defer-ida    # Fase 1 + Fase 2
python scripts/validate_phase2.py                                         # quanto è stato ricostruito
python scripts/tests/test_phase2_oracle.py                                # i controlli
```

**`--defer-ida` è obbligatorio su qualunque batch non sorvegliato.** Senza, al primo file dubbio
IDA apre una finestra e il processo resta fermo finché un umano non la chiude: su centinaia di file
la run non finisce mai. Con il flag, i file da rivedere restano in `pipeline_state.json` con stato
`needs_manual_review` — che è già la coda.

**`--force`** ignora la ripresa e rifà anche i file già risolti. Serve dopo ogni cambio di logica,
altrimenti i vecchi esiti vengono scambiati per risultati del codice nuovo.

### Il corpus di misura

`E:\DATASET\01_LABEL_CERTA\matrice_packed` — **353 campioni** da **53 originali distinti**, con
l'originale pulito recuperabile per ciascuno:

| packer | campioni | | architettura | campioni |
|---|---|---|---|---|
| Themida | 53 | | x86 (32 bit) | 174 |
| NSIS | 53 | | x64 (64 bit) | 179 |
| Inno | 53 | | | |
| MPRESS | 50 | | **multistrato reale** | **52** |
| VMProtect | 48 | | | |
| UPX | 44 | | | |
| UPX + NSIS | 44 | | | |
| UPX + MPRESS | 8 | | | |

`BASELINE/` è il sottoinsieme stratificato per la misura rapida: 5 campioni per ogni coppia
(packer, architettura), **75 file**. Sui 353 interi una run costa giorni, per via dei tempi di
attesa dell'emulatore sui campioni a 64 bit protetti.

---

## 9. I risultati

### Misura di partenza — 29 settembre 2026, 75 campioni

Eseguita con il codice **così com'era**, difetti compresi. È la riga zero: ogni correzione
successiva si confronta con questa tabella.

`BASELINE/`, 75 campioni (5 per ogni coppia packer/architettura). Durata totale **49 minuti**, di
cui 33 negli strumenti di unpacking e 19 in Ghidra.

**Quanti file hanno prodotto un risultato: 19 su 75 (25%).** I restanti 56 sono finiti in coda per
la revisione manuale.

#### Il giudizio dell'oracolo

| esito | campioni | |
|---|---|---|
| **ricostruito** | 14 | contenuto identico all'originale |
| **parziale** | 5 | codice presente, non identico |
| **fallito** | 56 | **tutti** per "nessun output prodotto" |
| falsi successi | **0** | |

L'ultima riga è il dato più importante: nessun file è stato dichiarato riuscito senza esserlo.
Tutti i 56 fallimenti sono fallimenti onesti — nessuno strumento ha prodotto niente — non dump
vuoti spacciati per successi. Il difetto che aveva motivato l'oracolo non si è ripresentato.

#### Per famiglia di packer

Sui 55 campioni con compressori e installer, dove l'identità con l'originale **è** il bersaglio:

| packer | x86 | x64 | lettura |
|---|---|---|---|
| UPX | **5/5** | **5/5** | l'unico caso completamente risolto |
| MPRESS | 0/5 | **4/5** | Qiling funziona a 64 bit; a 32 bit manca Unipacker |
| Inno | 0/5 | 0/5 | InnoUnp non riconosce questi installer (vedi A2) |
| NSIS | 0/5 | 0/5 | nessun estrattore presente |
| UPX + NSIS | 0/5 | 0/5 | lo strato esterno è NSIS: si blocca subito |
| UPX + MPRESS | 0/5 | — | lo strato esterno è MPRESS: serve Unipacker |

**14 su 55 (25%).**

Sui 20 campioni con protector, dove l'identità **non** è attesa:

| packer | x86 | x64 |
|---|---|---|
| Themida | 0/5 | **5/5 parziale** |
| VMProtect | 0/5 | 0/5 |

I 5 Themida a 64 bit danno `parziale`, che per un protector è l'esito buono: il codice c'è ed è
analizzabile, e non poteva essere identico all'originale.

#### Dove va il tempo

| strumento | tentativi | successi | minuti | % del tempo | minuti persi |
|---|---|---|---|---|---|
| qiling | 20 | 9 | 28,2 | **84%** | 4,5 |
| aspackdie | 39 | 0 | 5,2 | 16% | **5,2 (tutti)** |
| upx | 86 | 16 | 0,1 | 0% | 0,1 |
| innounp | 39 | 0 | 0,0 | 0% | 0,0 |
| unipacker | 50 | 0 | 0,0 | 0% | 0,0 |
| **totale** | **295** | **25** | **33,5** | | |

Due letture:

- **Qiling non è più il problema che era.** Consuma l'84% del tempo, ma con 9 risultati su 20
  tentativi e solo 4,5 minuti persi in attese inutili. Nello storico era l'86% del tempo con il
  51% buttato: il lavoro sugli hook ha funzionato.
- **AspackDie è puro spreco: 39 tentativi, 0 successi, 5,2 minuti interamente persi**, sempre
  esattamente 8 secondi ciascuno, cioè sempre il timeout. Sui 353 campioni sarebbero 25 minuti per
  niente.

### Fase B — Unipacker corretto, 40 campioni a 32 bit — 29 settembre 2026

Stesso corpus della misura di partenza, limitato ai 40 campioni a 32 bit, rieseguito con `--force`.

| | prima | dopo |
|---|---|---|
| file con un risultato | 5 | **15** |
| di cui confermati dall'oracolo | 5 | **7** |
| ricostruiti sul totale della matrice | 14 | **16** |

Unipacker passa da **0 a 10 risultati prodotti**. Il giudizio dell'oracolo su quei 10 però è
molto meno lusinghiero del conteggio grezzo, ed è il punto interessante di questa fase.

#### I 10 risultati di Unipacker, uno per uno

| campione | packer | corrispondenza | esito |
|---|---|---|---|
| `5f9adb4d5005_MPRESS` | MPRESS | **99,4%** | ricostruito |
| `ccb252113dd7_MPRESS` | MPRESS | **99,8%** | ricostruito |
| 5 campioni `_Inno` | Inno | 2,6% – 6,3% | parziale |
| `3598ad3754ce_UPX-MPRESS` | UPX + MPRESS | 9,7% | parziale |
| `5f9adb4d5005_UPX-MPRESS` | UPX + MPRESS | 12,8% | parziale |
| `ccb252113dd7_UPX-MPRESS` | UPX + MPRESS | 9,4%, byte non-zero 0% | fallito |

**Il caso Inno è la dimostrazione sul campo del perché serviva l'oracolo.** Unipacker, non
riconoscendo il formato, applica il suo unpacker generico all'installer: emula lo stub, produce un
file, e quel file contiene del codice vero — **ma è il codice dell'installer stesso, non il
payload**. Ghidra lo ha approvato tutte e 5 le volte (più di 5 funzioni trovate). Con il solo
criterio precedente avremmo scritto in tesi *"Inno: 5 su 5 risolti"*. Il confronto con l'originale
dice 2,6%: non è il programma che cercavamo.

**Il conto complessivo di quella run: Ghidra ha approvato 15 file, l'oracolo ne conferma 7.** Il
criterio vecchio, da solo, avrebbe sbagliato su più della metà dei casi.

#### Cosa ha funzionato davvero

- **MPRESS a 32 bit: 2 su 5 ricostruiti** al 99,4% e 99,8%. Prima erano zero.
- **La cascata multilayer ha rimosso due strati per la prima volta**, su 2 campioni UPX+MPRESS:
  UPX toglie lo strato esterno, Unipacker il MPRESS sottostante. Il meccanismo funziona; è il
  risultato finale a non essere ancora corretto (vedi A3, i dump quasi vuoti).

#### Uno spreco trovato e corretto

Dopo un successo, Unipacker veniva **rilanciato sul file che aveva appena prodotto**, perché il
dump conserva i nomi di sezione dello stub (`.MPRESS1`) e quindi risultava "ancora impacchettato".
Ogni volta 300 secondi buttati fino al timeout. Corretto con la stessa guardia che Qiling aveva
già: i propri dump non si ri-emulano.

### Fase C — instradamento dalla Fase 1, 75 campioni — 30 settembre 2026

Stessa baseline, rieseguita per intero con `--force`. Durata: **circa un'ora e mezza di lavoro
effettivo** (42 minuti negli strumenti, il resto in Ghidra), più una pausa di sistema di 14,9 ore
perché la macchina è andata in sospensione durante la notte — il dato è nel log e non va confuso
con il costo della fase.

#### Il quadro della giornata sui 75 campioni

| | mattina (misura di partenza) | sera (dopo Fase B e C) |
|---|---|---|
| file con un risultato | 19 | **44** |
| **ricostruiti** (identici all'originale) | **14** | **36** |
| parziali | 5 | 7 |
| falliti | 56 | 32 |
| di cui falsi successi approvati da Ghidra | 0 → poi 5 in Fase B | **0** |

Sui 55 campioni con compressori e installer, dove l'identità con l'originale è il bersaglio:
**36 su 55, il 65%**. Erano 14 su 55, il 25%.

#### Per famiglia, prima e dopo

| packer | mattina | sera | cosa è cambiato |
|---|---|---|---|
| UPX | 10/10 | 10/10 | già risolto |
| NSIS | 0/10 | **10/10** | 7-Zip, strumento già presente sulla macchina |
| UPX + NSIS | 0/10 | **10/10** | 7-Zip apre l'involucro, UPX sbuccia il payload sotto |
| MPRESS | 4/10 | **6/10** | Unipacker ora funziona a 32 bit |
| UPX + MPRESS | 0/5 | 0/5 | dump quasi vuoti, resta aperto (A3) |
| Inno | 0/10 | 0/10 | nessun estrattore libero supporta Inno Setup 6.7 (A2b) |
| Themida x64 | 5 parziali | 5 parziali | esito corretto per un protector |
| Themida x86, VMProtect | 0 | 0 | resta aperto |

#### Le due verifiche della fase, entrambe superate

La Fase C aveva due criteri, e il secondo contava quanto il primo:

1. **gli NSIS dovevano passare da `fallito` a `ricostruito`** — fatto, 20 campioni su 20 fra NSIS
   puri e catene UPX+NSIS, tutti identici all'originale;
2. **gli Inno dovevano passare da `parziale` a `fallito`** — fatto. In Fase B, Unipacker produceva
   su di essi un file che Ghidra approvava e che somigliava all'originale per il 2,6%: cinque falsi
   successi. Ora la pipeline riconosce il contenitore, prova gli estrattori, non ci riesce e si
   ferma dichiarandolo. **Un fallimento dichiarato vale più di un successo falso.**

#### Il multistrato ha iniziato a funzionare

10 campioni hanno richiesto più di un giro di cascata, per un totale di **54 strati rimossi** (erano
0 alla misura di partenza). Le catene UPX+NSIS sono il caso pulito: 7-Zip apre l'installer, UPX
decomprime il payload che c'era dentro, e il risultato è identico all'originale.

#### Un difetto introdotto e corretto in giornata

Il primo tentativo di Fase C è morto a metà batch con un `KeyError: 'sevenzip'`: il dizionario dei
contatori non conosceva il nuovo strumento. 7-Zip aveva funzionato, ma la run è andata persa.
Corretto alla radice — il contatore ora usa `.get()`, così aggiungere uno strumento alla cascata
non può più far cadere un batch.

### Fase D — Qiling, 15 campioni a 64 bit — 1 ottobre 2026

**Sui numeri: nessun cambiamento, in nessuna direzione.** Confronto con il riferimento di Fase C
preso da git, sugli stessi campioni: **10 su 10 identici** per MPRESS e Themida, VMProtect resta
0 su 5. La Fase D non ha migliorato il tasso di ricostruzione.

Il valore della fase sta altrove: ha chiuso una domanda aperta da settembre e ha tolto di mezzo tre
difetti che avrebbero falsato tutte le misure successive.

#### La diagnosi di VMProtect (chiude il punto 6 del documento storico)

Nel documento storico `FatalExit(ExitCode=0xdeadc0de)` era annotato come *"lo stub si suicida
(controllo anti-analisi) - da investigare"*. **Non e' un controllo anti-analisi.** La catena reale,
letta con il verbose di Qiling acceso su un singolo campione:

```
ZwOpenFile        -> non implementata in Qiling
ZwCreateSection   -> non implementata in Qiling
ZwMapViewOfSection(SectionHandle = 0x2020202020202020, ...)   <- spazi ASCII: stack non inizializzato
ZwClose(...) = 0xc0000008                                      <- STATUS_INVALID_HANDLE
ZwRaiseHardError -> FatalExit(0xdeadc0de)                       <- a 0,2 secondi dall'avvio
```

Lo stub apre un file, ne crea una sezione e la mappa. Le prime due non esistono in Qiling 1.4.11,
quindi l'handle restava memoria di stack non inizializzata e lo stub si accorgeva dell'incoerenza.
E' la **stessa classe di difetto** gia' risolta per `ZwOpenSection`/`ZwMapViewOfSection` su Themida,
su una variante diversa delle stesse API.

Implementate entrambe in `_install_qiling_compat_hooks`, sul modello delle esistenti. Ora la catena
funziona: `ZwOpenFile` ritorna `STATUS_SUCCESS`, `ZwCreateSection` riceve l'handle giusto,
`ZwMapViewOfSection` mappa. **Lo stub muore comunque**, e il motivo e' ora visibile:

```
ZwOpenFile -> '\??\C:\Windows\System32\x64_msvc_c5fa570bede6_VMProtect.exe'
```

**Apre il proprio file eseguibile**: e' un controllo di integrita' su se stesso. Mappa il proprio
file da disco e lo confronta con l'immagine in memoria. Il nostro hook gli restituisce una copia
dell'immagine **in memoria**, non i byte del **file**, il confronto non torna e lo stub si suicida.

Il payload non viene mai decompresso: 0 blocchi eseguiti, 0 pagine modificate. Il dump di ripiego
ha fatto la cosa giusta rifiutandosi - non c'era niente da salvare.

**Quanto costerebbe chiuderlo e quanto varrebbe.** Servirebbe far mappare all'hook i byte reali del
file quando l'handle punta al campione stesso: una decina di righe, piu' due o tre giri di verifica.
Varrebbe al massimo **5 esiti `parziale`** (48 su 353 nel corpus completo): VMProtect virtualizza il
codice come Themida, quindi `ricostruito` non e' raggiungibile per costruzione. Sospeso: si rivaluta
dopo la Fase E, quando si sapra' quanto pesa davvero sul totale.

#### Il dump di ripiego, e il `raise` che lo rendeva irraggiungibile

Aggiunto un dump a fine emulazione per i casi in cui lo stub decomprime il payload ma non ci salta
dentro entro il tempo concesso. Alla prima misura non e' **mai** scattato: nel gestore attorno a
`ql.run()` c'era

```python
if not (state_counters["layer"] >= 1 and os.path.exists(unpacked_path)):
    raise
```

Quando l'emulazione muore senza aver registrato nessuna transizione - che e' esattamente il caso di
VMProtect - l'eccezione veniva rilanciata e il controllo saltava al gestore esterno, senza passare
dal codice del ripiego. Ora si registra l'eccezione e si prosegue.

#### Due difetti che riempivano il disco

La prima misura di Fase D e' morta a meta' con `No space left on device`, e il confronto che ne e'
uscito era contaminato (un dump scritto vuoto, letto poi come `non_confrontabile`). Cause:

| | difetto | effetto | correzione |
|---|---|---|---|
| D1 | `Qiling(..., verbose=QL_VERBOSE.DEFAULT)` | una riga su stdout per **ogni** chiamata API emulata. Uno stub finito in un ciclo di `ZwEnumerateKey` ha prodotto **203 MB in 13 campioni** | `QL_VERBOSE.DISABLED`. Stessa run: **556 KB**, 370 volte meno. La diagnostica che usiamo (ring buffer `api_trace`, riga `[END]`, `tool_diagnostics.jsonl`) e' nostra e resta |
| D2 | copie residue nelle Temp delle rootfs | **227 MB in 39 file**. `unpack_with_qiling` rimuove la propria copia nel `finally`, ma se il processo muore prima la copia resta. Difetto gia' noto dal documento storico | `_sweep_qiling_temp()`, una passata a inizio batch |

#### Euristica OEP: parametri espliciti, nessuna regressione

`QILING_OEP_WARMUP_BLOCKS = 200` e `QILING_MIN_WRITTEN_BYTES = 4096` sostituiscono la soglia
implicita di 2 pagine. Il warmup usa i **blocchi** e non le istruzioni perche' gli hook sono per
blocco: 200 blocchi coprono abbondantemente le 200 istruzioni richieste. La soglia scende da 8 KB a
4 KB, quindi il filtro e' piu' permissivo: era il rischio principale, e la verifica dice **0
regressioni su 10 campioni**.

Aggiunti anche `IsDebuggerPresent` e `CheckRemoteDebuggerPresent` decorati con `@winsdkapi`, quindi
hook veri e non no-op come i precedenti. Non sono loro a sbloccare VMProtect.

Rimosso il codice morto: `hook_rdtsc` (usava la vecchia API `ql.reg`) e l'import `UC_X86_INS_RDTSC`
mai usato. Il bypass `rdtsc` resta agganciato con `hook_code` come previsto, e resta disattivato di
default perche' e' per-istruzione e costa.

### Fase E — misura finale sui 353 campioni — 10 ottobre 2026

Corpus completo `matrice_packed`, **353 campioni su 353 processati**. Eseguita in due tronconi: il
2 ottobre ne ha fatti 239 prima che il processo morisse (causa non accertata: il log stava in una
cartella temporanea poi ripulita - da qui la regola di tenere i log del batch dentro
`Pipeline_Reports/`); la ripresa del 9-10 ottobre ha completato i restanti in **57 minuti**.

#### Il risultato

| | |
|---|---|
| **ricostruiti** (identici all'originale) | **178 / 252 = 71%** |
| escludendo i 53 campioni Inno (vedi A2b) | **178 / 199 = 89%** |
| parziali | 29 (3 compressori + 26 Themida) |
| **falsi successi** | **0** |
| file che richiedono ancora revisione umana | 142 / 353 |
| multistrato | **43 file, profondità massima 2, 254 strati rimossi** |

> ⚠️ **Correzione del 22 ottobre 2026.** Questa riga diceva «11 file, 66 strati rimossi». Era
> sbagliata: quei due numeri sono `multilayer_rilevati` e `layer_totali_rimossi` di
> `report_riepilogo_unpacking.json` al commit `fd6f30d`, cioè i contatori della **sola run di
> ripresa del 9-10 ottobre** (`processati: 196`, `saltati_resume: 156`), non una misura sui 353.
> I numeri per campione vengono da `pipeline_state.json`, campo `layers_removed`: **140** file a
> zero strati, **168** a uno, **43** a due, nessuno oltre, e `layer_limit_reached` falso su tutti.
> 168 × 1 + 43 × 2 = **254** rimozioni. Due controlli incrociati: 168 + 43 = 211 = i file con
> `unpack_success`, e i 140 a zero strati sono gli stessi 140 fallimenti senza output.
>
> ⚠️ **`report_riepilogo_unpacking.json` tiene contatori per-run, non per-corpus, e viene
> sovrascritto a ogni esecuzione**: la copia attuale è della run su `v1_misto`, e la versione
> Fase E esiste solo in git a `fd6f30d`. Non copiare numeri da quel file in tesi: per il corpus
> interno valgono `validation_phase2.csv` (esiti dell'oracolo) e `pipeline_state.json` (stato per
> campione).

Alla misura di partenza del 29 settembre il tasso era **25%** su un sottoinsieme di 75 campioni.

#### Per famiglia

| famiglia | ricostruiti | nota |
|---|---|---|
| NSIS | **53 / 53** | 7-Zip, deterministico |
| UPX + NSIS | **43 / 44** | 7-Zip apre l'involucro, UPX sbuccia il payload sotto |
| UPX | **42 / 44** | |
| MPRESS | **40 / 50** | 24 a 64 bit via Qiling, 16 a 32 bit via Unipacker |
| UPX + MPRESS | 0 / 8 | 2 parziali: Unipacker non chiude la catena (A3) |
| Inno | 0 / 53 | nessun estrattore libero supporta Inno Setup 6.7 (A2b) |
| Themida | 0 / 53 | **26 parziali** a 64 bit: e' l'esito massimo per un protector |
| VMProtect | 0 / 48 | controllo di integrita' su se stesso (A11) |

#### Per strumento, su tutti i 353

| strumento | file gestiti | ricostruito | parziale | fallito |
|---|---|---|---|---|
| UPX | 85 | 85 | 0 | 0 |
| 7-Zip | 54 | 53 | 0 | 0 |
| Qiling | 50 | 24 | 26 | 0 |
| Unipacker | 22 | 16 | 3 | 3 |

**Come leggere questa tabella.** UPX e 7-Zip fanno 138 dei 178 ricostruiti, cioe' il 78%: il
risultato numerico viene in gran parte dall'aver **instradato correttamente** verso strumenti
statici e deterministici, non dall'emulazione. Ma fermarsi qui e' fuorviante: **Qiling e' l'unico
che ottiene qualcosa da Themida**, e quei 26 parziali nessuno strumento statico potrebbe produrli
per costruzione. I due emulatori fanno meno numeri, su terreno che e' solo loro. Nota anche che
Qiling non ha prodotto **nessun** fallimento su cio' che ha tentato.

#### Valutazione critica del risultato

**Quello che regge:**

- **zero falsi successi su 353.** Ogni ricostruzione dichiarata e' verificata byte per byte contro
  l'originale. Nessun numero di questa sezione poggia su "Ghidra ha trovato abbastanza funzioni",
  che e' il criterio che in passato aveva promosso a successo dei dump vuoti;
- **i fallimenti sono spiegati**, ognuno con una diagnosi verificata: 53 Inno (versione
  dell'installer), 48 VMProtect (controllo di integrita'), 27 Themida a 32 bit (Unipacker non copre
  Themida), 15 fra MPRESS e catene;
- **carico manuale ridotto del 60%**: da 353 file a 142. Era l'obiettivo dichiarato della fase.

**Quello su cui essere prudenti:**

- **l'89% va sempre accompagnato dalla sua etichetta.** Escludere Inno e' difendibile - e' un
  difetto del corpus, non della pipeline - ma il numero da mettere in tabella resta **71%**, con
  l'89% come lettura secondaria motivata, mai al suo posto;
- **il corpus e' facile e omogeneo.** 353 campioni da 53 originali, 6 packer, una sola versione per
  packer, tutti impacchettati da noi. Il 71% dice "sappiamo disfare i packer che abbiamo applicato
  noi": il malware reale usa varianti modificate e packer custom. E' il motivo per cui la Fase F
  non e' un extra ma il completamento della misura;
- **la meta' protector e' sostanzialmente irrisolta**: 0 ricostruiti su 101. La rivendicazione
  corretta e' **26 su 101 "analizzabili", 0 "ricostruiti"**. La corrispondenza mediana
  di quei 26 parziali e' **0.0678** (vedi §6): qui `parziale` non significa "quasi
  ricostruito";
- **"ricostruito" non significa "eseguibile funzionante"**: la tabella degli import non viene
  ricostruita (A7). I byte del codice coincidono, le chiamate alle API restano indirizzi grezzi.

### Set di controllo a 64 bit su programmi esterni — 11 ottobre 2026

**Non è una validazione esterna, ed è importante non chiamarla così.** I packer restano i nostri,
nelle stesse versioni. Quello che cambia sono i **programmi originali**.

#### La domanda a cui risponde

I 353 campioni della matrice partono da 53 programmi compilati in casa. Un'obiezione legittima al
71% è: *quel numero dipende dal fatto che gli originali sono programmini di prova vostri?* Software
reale è più grande, ha più import, viene da toolchain diverse e ha un layout di sezioni meno
regolare — tutte cose che potrebbero mettere in difficoltà sia gli unpacker sia l'euristica OEP.

`scripts/build_set64_esterno.py` costruisce il controllo: prende eseguibili dalla classe pulita
`goodware_non_ms` — **VLC, MSYS2/MinGW64, Cygwin, Notepad++, PuTTY, curl**, già nella ground truth
con oracolo di provenienza — e li impacchetta con i nostri packer. Lo script **riusa le funzioni di
`pack_samples.py` importandolo**, senza modificarlo.

I master sono filtrati per essere x64, senza Control Flow Guard (UPX rifiuta i file con CFG) e non
.NET, e scelti a rotazione fra i progetti perché 10 binari dello stesso progetto non sarebbero
varietà. Inno è escluso di proposito: darebbe 0 per costruzione (A2b).

**10 master da 6 progetti × 5 packer = 48 campioni** (50 attesi; MPRESS ne ha rifiutati 2).
Tutti a **64 bit**, quindi questo set esercita Qiling — che la validazione esterna della Fase F,
interamente a 32 bit, lascia scoperto.

#### Il risultato: 28 su 28

| famiglia | set esterno (x64) | Fase E, stessa famiglia a x64 |
|---|---|---|
| UPX | **10 / 10** | 24 / 25 |
| NSIS | **10 / 10** | 26 / 26 |
| MPRESS | **8 / 8** | 24 / 25 |
| **totale compressori/installer** | **28 / 28 = 100%** | 74 / 76 = 97% |
| Themida | 10 / 10 **parziali** | 26 / 26 parziali |
| VMProtect | 0 / 10 | 0 / 26 |

Per strumento: UPX 10 ricostruiti, 7-Zip 10, **Qiling 8 ricostruiti più 10 parziali, zero
fallimenti su ciò che ha tentato**. Durata: 1 ora e 27 minuti per 48 campioni.

#### Lettura

**L'obiezione cade.** Su software vero la pipeline si comporta come sui nostri programmi, anzi
leggermente meglio. Il 71% della Fase E non è gonfiato dalla semplicità degli originali: i suoi
limiti veri sono altrove — Inno, VMProtect, e i packer mai applicati.

**Le due diagnosi note si confermano su campioni nuovi.** Themida dà sistematicamente `parziale`,
che per un protector è l'esito massimo; VMProtect dà sistematicamente zero, e il controllo di
integrità su sé stesso (A11) si comporta allo stesso modo su binari mai visti.

**La distribuzione bimodale del §6 si riproduce su un corpus indipendente.** I 10 Themida
danno corrispondenza fra **0.0501 e 0.0903** (mediana 0.0784): la stessa fascia misurata in
Fase E (mediana 0.0678, da 0.0370 a 0.1412), su programmi diversi e con una sola architettura.
Dei 28 ricostruiti, **21 hanno corrispondenza esattamente 1.0000** e il minimo è 0.9902. Fra
0.0903 e 0.9902 non cade nessun campione: anche qui il risultato è byte-identico o assente,
mai approssimato. La forma descritta al §6 non era dunque un artefatto della matrice interna.

**I limiti di questo numero, da riportare accanto ad esso:**

- **non misura packer di terzi** — è la Fase F a farlo, ed è un asse diverso;
- **28 campioni su 3 famiglie sono pochi** per un 100%: la formulazione onesta è *"nessun
  fallimento su 28"*, non *"funziona sempre"*;
- i due protector non concorrono al tasso, come nella Fase E.

**Questo numero non va sommato né messo nella stessa tabella del 71%:** corpus diverso, scopo
diverso. Va presentato come controllo di robustezza, non come misura principale.

### Fase F — validazione esterna su packer di terzi — 14-15 ottobre 2026

Protocollo `07_protocollo_fase2_esterna.md`, firmato sul commit `7379138` **prima** di eseguire,
con due restrizioni di ambito registrate al §13 anch'esse prima del run: niente verifica manuale
dei 30 campioni, e livello 2 limitato a `v1_misto`. Cosa costano è scritto in fondo a questa
sottosezione.

Corpus: `v1_misto`, 270 file da `packing-box/dataset-packed-pe`, di cui **208 etichettati packed
dalla Fase 1** — esattamente il numero previsto al §2 del protocollo. Run del 14/10/2026,
208/208 processati in 1h36'. Nessuno snapshot e nessuna cerimonia di sicurezza: `v1_misto` non è
malware, è costruito come la matrice interna — programmi puliti impacchettati da terzi, che è il
motivo per cui 29 dei suoi packed hanno l'originale pulito dentro lo stesso dataset.

#### Livello 1 — oracolo forte, 29 coppie, 20 famiglie di cui 17 mai viste

Stesso oracolo, stesse soglie, stesso codice della Fase E.

| | |
|---|---|
| **ricostruiti** | **6 / 26 = 23%** |
| parziali | **0** |
| falliti | 23, **tutti con `nessun output prodotto`** |
| protector (3 Themida) | 0 / 3, riportati a parte come in Fase E |
| confronti effettivamente eseguiti | **6 su 29** |

Cinque dei sei ricostruiti hanno corrispondenza **esattamente 1.0000**, il sesto 0.9940 — che è
anche il valore con cui `upx -d` aveva verificato l'accoppiamento di quella coppia il 10/10.

#### La struttura del risultato conta più del tasso

| | |
|---|---|
| coppie su famiglie **con** un unpacker dedicato | **6 / 8 ricostruite** |
| coppie su famiglie **senza** | **0 / 21** |

Le sei famiglie coperte nativamente — UPX, ASPack, FSG, MEW, MPRESS, PECompact — erano nominate
nel protocollo **prima** del run, nell'ipotesi 1. Hanno funzionato tutte tranne PECompact, e una
delle due coppie FSG. Fuori da quell'elenco: zero su ventuno.

**L'unpacker generico e il ramo di emulazione non hanno contribuito nulla su famiglie mai viste.**
La portata esterna della pipeline non misura la qualità dell'instradamento ma l'**inventario degli
strumenti**: aggiungere una famiglia significa aggiungere un tool, non riprogettare la cascata.

Sulle 17 famiglie mai incontrate in Fase E il tasso è **3 / 23** (ASPack, FSG, MEW).

#### Due cose che questa misura chiarisce

**La distribuzione bimodale del §6 qui è estrema.** Zero parziali, zero sezioni a zeri: o il
packer viene invertito esattamente, o non esce alcun file. Terza conferma indipendente dopo
matrice interna e set64.

**L'ambiguità dichiarata al §3.2 del protocollo non morde.** Quel paragrafo avvertiva che un
`fallito` su una delle 18 famiglie il cui accoppiamento non è verificabile sarebbe stato ambiguo
fra "la pipeline non ce l'ha fatta" e "l'accoppiamento era sbagliato". Ma **tutti e 23 i
fallimenti sono senza output**: nessun confronto è avvenuto, quindi l'assunzione
sull'accoppiamento non può aver inquinato il numero. Resta dichiarata, non pesa.

**L'ipotesi 1 era sbagliata.** Prevedeva fra il 30% e il 50%. Il §9 del protocollo aveva già
fissato come leggerlo: un risultato sotto la Fase E non è un fallimento del lavoro, è la misura di
quanto il corpus interno fosse facile.

#### Livello 2 — criterio proxy, non correttezza

Sui 179 packed restanti di `v1_misto`, esclusi i 29 del livello 1.

| | |
|---|---|
| con un output valutabile | **40 / 179 (22%)** |
| senza alcun output | 139 |
| `plausibile` (tutte e quattro le condizioni del §3.3) | **13** |
| sui soli valutabili | 13 / 40 = 32% |
| sul totale | 13 / 179 = 7% |

Il criterio non è mai stato validato contro un giudizio umano, quindi è **copertura con un filtro
di qualità**, mai un tasso di ricostruzione.

**Quale condizione decide.** Entry point non a zeri e Ghidra passano su 40 su 40, l'entropia
scarta 6, e la quarta — Fase 1 rieseguita sull'output — ne scarta **27 su 40**. Tre condizioni su
quattro non discriminano quasi nulla su questo corpus e la quarta fa tutto il lavoro: è
esattamente l'argomento per cui servivano tutte e quattro invece del solo conteggio di Ghidra.

**Per strumento, ed è il risultato più serio di tutta la fase.** UPX 6 su 6 plausibili, 7-Zip 7 su
8, **Unipacker 0 su 26**. Fuori dalle famiglie che supporta nativamente, Unipacker **non
fallisce: restituisce un file che non è il payload**. È il modo di fallire peggiore che uno
strumento di questa cascata possa avere — ogni altro o riesce o non produce niente — ed è
contenuto solo dall'oracolo, non dallo strumento.

#### Cosa costano le due restrizioni, dichiarato

- **niente verifica manuale (§6 del protocollo decaduto):** il numero del livello 2 non ha alcun
  accordo misurato col giudizio umano. Va riportato come copertura e basta;
- **145 campioni di malware reale non processati (§13.2):** **nulla in questo lavoro è misurato su
  malware vero.** L'ipotesi 4 del protocollo — che il tasso proxy crollasse ulteriormente sul
  malware reale — resta una previsione mai messa alla prova, e in tesi va scritta così.

Report: `Pipeline_Reports/validation_phase2_esterna.{md,csv}` per il livello 1 e
`validation_fase_f_livello2.{md,csv}` per il livello 2. Non toccano `validation_phase2.*`, che
resta la misura della Fase E, come impone il §3.4.

## 10. Problemi noti e difetti aperti

### Risolti il 29 settembre 2026

| # | difetto | effetto | correzione |
|---|---|---|---|
| R1 | `state.flush()` mai chiamato a fine Fase 2 | il salvataggio dello stato è a blocchi di 50 file: **ogni run più corta di 50 file spariva senza traccia**, in silenzio e con codice di uscita 0 | una riga a fine batch, più un test di regressione |
| R2 | ripiego `(True, True)` per i file non-PE | ELF e file malformati mandati all'emulatore, fino a 600 s bruciati per file | scarto esplicito con motivo registrato |
| R3 | IDA bloccante dentro il ciclo | nessuna run batch poteva arrivare in fondo, quindi nessun numero aggregato esisteva | `--defer-ida` |
| R4 | nessuna misura per strumento | l'86% del tempo stava in Qiling e il 51% in attese senza risultato, ma il dato è emerso solo rileggendo i log a mano | una riga in `tool_diagnostics.jsonl` per ogni tentativo |
| R5 | pausa di 1 secondo dopo ogni file | 6 minuti buttati su 353 campioni | rimossa |

### Aperti

| # | difetto | gravità | nota |
|---|---|---|---|
| A1 | ~~Unipacker non viene nemmeno lanciato~~ **RISOLTO in Fase B** | — | **due cause sovrapposte**, scoperte con la baseline. (1) 50 tentativi su 50 finiscono in `[WinError 2] Impossibile trovare il file specificato` in **0,0 secondi**: l'eseguibile `unipacker.exe` sta in `.venv/Scripts/` ma quella cartella non è nel PATH quando la pipeline gira invocando direttamente il Python del venv. Va indicato con il percorso assoluto, come si fa già per UPX e IDA. (2) Solo dopo si arriverà al secondo difetto: l'opzione `-d` è una **cartella** e il file esce come `unpacked_<nome>` dentro di essa, mentre noi le passiamo un percorso di file e poi cerchiamo un file con il nome della cartella. Riguarda i tre quarti dei campioni su disco |
| A2 | ~~NSIS scoperto~~ **RISOLTO in Fase C** | — | 97 campioni (53 NSIS + 44 UPX+NSIS) non hanno alcuno strumento dedicato. **7-Zip li risolve ed è già installato**: verificato su un campione, il payload estratto è identico all'originale byte per byte. Da collegare in Fase C |
| A2b | **Inno non estraibile su questo corpus** | media | I campioni sono `Inno Setup Setup Data (6.7.0)`, prodotti da `E:\Tools\Inno Setup 6\ISCC.exe`. **Verificato con entrambi gli strumenti esistenti:** innounp **0.50** risponde *"The setup files are corrupted or made by incompatible version"*; innoextract **1.9** dichiara esplicitamente il proprio limite — *"Extracts installers created by Inno Setup 1.2.10 to 6.0.5"* — e fallisce con *"Could not determine setup data version!"*. 7-Zip su Inno risponde `ERROR`. **Non e' un difetto della pipeline ma del corpus**: i nostri installer usano una versione piu' recente di qualunque estrattore libero. Nel corpus completo i campioni con traccia Inno sono 54, di cui **53 sono i nostri e 1 solo e' reale**: aggiungere innoextract alla cascata costerebbe tempo su ogni file per coprire un campione. Scelte possibili: dichiararlo come limite (preferita), oppure rigenerare i 53 con un Inno Setup <= 6.0.5 |
| A3 | **dump quasi vuoti di Unipacker** (non di Qiling) | media | riassegnato in Fase D: i 2 `parziale` con byte non-zero fra l'8% e il 12% sono `UPX + MPRESS` a 32 bit, gestiti da **Unipacker**. Su Qiling il secondo dump a fine emulazione e' stato implementato e non serviva a questo |
| A4 | `Die_Packer_Type` e `Packing_Evidence` non usati | media | 118 campioni `installer`/`sfx` e 785 `protector` non vengono instradati; l'evidenza debole non riduce il tempo speso |
| A5 | `looks_still_packed()` sui protector | media | l'entropia delle sezioni `.boot`/`.themida` è sempre sopra soglia, quindi il file risulta "ancora impacchettato" anche quando non lo è: si sprecano giri |
| A6 | ~~AspackDie è puro spreco~~ **RISOLTO in Fase C** (chiamato solo se la Fase 1 nomina ASPack) | — | misurato sulla baseline: **39 tentativi, 0 successi, 5,2 minuti interamente persi**, sempre esattamente 8 s ciascuno cioè sempre il timeout. Strumento grafico senza modalità silenziosa. Sui 353 campioni sarebbero 25 minuti buttati. Va chiamato **solo** quando la Fase 1 dice ASPack, mai alla cieca |
| A7 | tabella degli import non ricostruita | media | vedi §12: è un limite di rivendicazione, non solo una funzione mancante |
| A11 | **VMProtect: controllo di integrita' su se stesso** | media | diagnosi completa in §9. Due API mancanti implementate; resta che lo stub mappa il proprio file da disco e lo confronta con la memoria. Sospeso dopo la Fase E: al massimo 5 esiti `parziale`, mai `ricostruito` |
| A9 | ~~Unipacker produce risultati plausibili ma sbagliati sugli installer~~ **RISOLTO in Fase C** | — | il suo unpacker generico emula lo stub di un installer Inno e produce il codice dell'installer, non il payload (corrispondenza 2,6%–6,3%). Ghidra lo approva. Senza l'oracolo sarebbero 5 falsi successi. Rimedio in Fase C: gli installer vanno instradati agli estrattori e **non** devono mai arrivare all'emulazione |
| A10 | **la Fase 1 sceglie male la rilevazione principale** | media | *difetto della Fase 1, trovato dalla Fase 2.* Sui 53 campioni Inno DIE riporta `.NET Reactor (protector); Inno Setup Module (installer)` e la Fase 1 prende la prima come `Die_Packer_Name`/`Die_Packer_Type`. È un **falso positivo**: quei file non hanno header .NET (`Is_DotNet = NO`, `Has_CLR_Header = NO`). La Fase 2 lo aggira leggendo `Die_All_Packers` invece della sola principale, ma la colonna principale resta sbagliata nel CSV e in qualunque analisi la usi. Rimedio in Fase 1: non eleggere a principale un protector .NET su un binario senza CLR |
| A8 | ~~riproducibilità non versionata~~ **RISOLTO il 15 ottobre 2026** | — | erano **due difetti sotto lo stesso numero**, chiusi separatamente. (1) *I report*: `Pipeline_Reports/` era esclusa in blocco e il README affermava che le metriche fossero ricalcolabili senza i binari, cosa non vera. Ora **15 file sono tracciati** con `git add -f`, fra cui tutti i report di misura (`validation_phase2`, `validation_set64`, `validation_phase2_esterna`, `validation_fase_f_livello2`), quindi ogni cifra di questo documento si ricalcola dal repository. (2) *I sorgenti dei master*: la riga `Build_samples` nel `.gitignore` di radice escludeva anche `Build_Samples/`, perché git su Windows confronta i path senza distinguere le maiuscole; spariva così la catena che ricostruisce i 53 master. Entrati **55 file per 69 KB** - sorgenti Go e Rust, `Cargo.lock`, `go.sum`, i due script di build e il README - mentre i 136 MB di artefatti restano esclusi dal `.gitignore` già presente dentro la cartella, che non aveva mai avuto effetto |
| A12 | `ghidra_verified` registra la cosa sbagliata | bassa | nello stato il campo vale `ghidra_ok`, cioè **"Ghidra ha girato e il report e' leggibile"**, non "ha approvato": la decisione vera e' `esito_affidabile` (`subprocesses.py` riga 2037), che include la soglia `MIN_FUNCTIONS_THRESHOLD`. Conseguenza misurata: tutti e 295 i campioni con un output hanno `ghidra_verified = True`, **compreso l'unico che la soglia ha respinto** (`x86_mingw_9c5c58a524d5_UPX-NSIS.exe`, 1 funzione, finito in `needs_manual_review`). Chi contasse quel campo scriverebbe un numero sbagliato. Nessuna misura di questo lavoro ne e' toccata: l'oracolo non lo legge e il punteggiatore del livello 2 usa `ghidra_func_count`. Rimedio: rinominarlo in `ghidra_report_ok` e aggiungere `ghidra_threshold_ok` |
| A13 | la verifica Ghidra rende quasi nulla | bassa | **misurato dopo la Fase F:** gira su tutti i 295 campioni che hanno prodotto un output, a **28 s di mediana** (~2,3 ore complessive), e ne ha respinto **uno**. Mediana delle funzioni trovate **480** contro una soglia di **5**: la soglia non discrimina. Non e' un difetto di correttezza - da quando c'e' l'oracolo, Ghidra non giudica piu' la correttezza - ma un passo che costa e non filtra. Tenuto come controllo di sanita' e per non invalidare il confronto fra le run cambiando la cascata a misura in corso. Su un corpus piu' grande sarebbe da togliere o da rendere condizionale. Dichiarato nei limiti del testo di tesi (`09` §7) |
| A14 | `report_riepilogo_unpacking.json` tiene contatori per-run | bassa | i suoi campi contano la **singola esecuzione**, non il corpus, e il file viene **sovrascritto** a ogni run: la copia su disco e' sempre dell'ultima, le precedenti esistono solo nella storia di git. **Ha gia' prodotto un errore in tesi:** `multilayer_rilevati: 11` e `layer_totali_rimossi: 66` erano finiti nella tabella della Fase E come se descrivessero i 353, mentre sono i contatori della sola run di ripresa del 9-10 ottobre (`processati: 196`, `saltati_resume: 156`). I valori veri sui 353, da `pipeline_state.json`, sono **43 file multistrato e 254 strati rimossi** (vedi la correzione al §9). Rimedio: scrivere un file per run con il nome del target e un timestamp, invece di sovrascriverne uno solo. Fino ad allora, **non citare quel file in tesi**: per il corpus interno valgono `validation_phase2.csv` e `pipeline_state.json` |

---

## 11. Cosa manca da implementare

Le fasi vanno eseguite **in quest'ordine**, con una misura fra l'una e l'altra. L'ordine non è
negoziabile su un punto: la misura di partenza viene prima di tutto, altrimenti le correzioni
successive si confrontano con niente.

### Fase A — la misura di partenza — **FATTA il 29 settembre 2026**

Risultati in §9. In sintesi: 19 file su 75 producono un risultato, 14 sono ricostruiti davvero,
**zero falsi successi**. Ha prodotto anche due diagnosi che non si avevano prima (A1 e A2, vedi
sopra): senza la misura si sarebbe corretto il difetto sbagliato di Unipacker.

### Fase B — Unipacker — **FATTA il 29 settembre 2026**

Tre correzioni: percorso assoluto dell'eseguibile ricavato dall'interprete in uso (era la causa
vera: non veniva mai lanciato), contratto corretto dell'opzione `-d` (è una cartella, il file esce
come `unpacked_<nome>` al suo interno), tempo di attesa da 30 a 300 secondi — misurato, un MPRESS a
32 bit impiega circa 100 secondi. Più la guardia contro la ri-emulazione dei propri dump.

Risultati in §9. Ha prodotto anche il difetto A9, che da solo giustifica l'esistenza dell'oracolo.

### Fase C — instradamento dalla Fase 1 — **FATTA il 30 settembre 2026**

Quattro difetti chiusi insieme: 7-Zip per gli installer NSIS (A2), gli installer non arrivano più
all'emulazione (A9), AspackDie solo se la Fase 1 nomina ASPack (A6), il tipo della Fase 1 usato per
instradare (A4). Più una correzione non prevista: l'appartenenza a `installer` si legge da
**tutte** le rilevazioni di DIE, non dalla sola principale, perché su Inno la principale è sbagliata
(vedi A10).

Risultati in §9: ricostruiti da 14 a 36 sui 75 campioni, e i cinque falsi successi della Fase B
tornati a fallimenti dichiarati.

### Fase D — Qiling — **FATTA il 1 ottobre 2026**

Risultati in §9. Sui numeri non cambia nulla; chiude la diagnosi di VMProtect (punto 6 dello
storico) e tre difetti che falsavano le misure: il verbose che riempiva il disco, i residui nelle
rootfs, e il `raise` che rendeva irraggiungibile il dump di ripiego.

**A3 resta aperto ma cambia padrone:** i dump quasi vuoti sono quelli di `UPX + MPRESS` a 32 bit,
prodotti da **Unipacker**, non da Qiling. Il criterio di verifica che questo documento riportava per
la Fase D era sbagliato.

### Fase E — misura finale — **FATTA il 10 ottobre 2026**

Risultati e valutazione critica in §9. 353 campioni su 353, **71% di ricostruzione** (89%
escludendo Inno), zero falsi successi.

### Fase F — validazione su dataset esterno — **FATTA il 14-15 ottobre 2026**

I 353 campioni della matrice sono impacchettati **da noi**: l'oracolo e' perfetto ma il corpus e'
omogeneo. Il completamento della misura e' passare in Fase 2 i campioni di Fase 1 che **non**
vengono da noi — 208 da `v1_misto`, 114 da MalwareBazaar, 16 malware reali, 9 di misto storico,
6 dal libro *Practical Malware Analysis*: **353 esterni**, coincidenza numerica con la matrice
interna e nessun significato.

Il protocollo sta in `07_protocollo_fase2_esterna.md`, redatto prima di qualunque esecuzione e
**non ancora firmato**. Vale lo stesso vincolo della Fase 1: se quello che c'e' scritto viene usato
per tarare qualcosa, cessa di essere una misura esterna.

**La struttura e' a due livelli, e la ragione e' che l'originale pulito esiste solo per una parte
del corpus.** Era una semplificazione dire che non esiste affatto:

- **livello 1, oracolo forte — 29 campioni.** `v1_misto` ha due meta', 200 packed e 70 puliti, e
  `v1_chiave.csv` conserva il `nome_originale`: parte dei packed sono versioni compresse di
  programmi che stanno **non compressi** nella meta' pulita. `scripts/build_fase_f_pairs.py`
  ricostruisce l'accoppiamento in `config/fase_f_coppie.csv` — **29 coppie su 20 famiglie, di cui
  17 mai viste in Fase E**. Su queste si applica `validate_phase2.py` invariato, con le stesse
  soglie (0.95 / 0.05): e' **l'unico numero di questa fase confrontabile con il 71%**. Tutte a 32
  bit, quindi il ramo Qiling non viene esercitato — ed e' il motivo per cui serviva il set di
  controllo a 64 bit del §9;
- **livello 2, criterio proxy — i restanti ~324.** Qui l'originale davvero non esiste e
  `validate_phase2.py` non e' applicabile. Il §3.3 del protocollo definisce **in anticipo** quattro
  condizioni che devono valere **tutte**: sezione dell'entry point non a zeri (non-zero >= 5%),
  entropia massima di sezione sotto 7.2, Ghidra con almeno 5 funzioni, e la Fase 1 rieseguita
  sull'output che passa `Is_Packed_Label` da 1 a 0. L'esito si chiama **`plausibile`** e mai
  `ricostruito`: misura plausibilita', non correttezza. Nessuna delle quattro condizioni basta da
  sola — la terza e' esattamente il criterio che in Fase B aveva promosso 5 falsi successi, e la
  quarta e' parzialmente circolare perche' e' lo stesso rilevatore che aveva detto "packed".

**I due livelli non si sommano e non vanno nella stessa tabella.** I report escono in
`Pipeline_Reports/validation_phase2_esterna.{md,csv}` e non toccano `validation_phase2.{md,csv}`,
che resta la misura della Fase E.

**Cosa mancava per partire, e come e' stato chiuso** (risultati al §9):

1. le tre decisioni del §12 del protocollo, prese il 14/10/2026: firmare (il codice congelato e'
   invariato da `46a2cfd`, verificato file per file sulla cascata); **chi** esegue la verifica
   manuale dei 30 campioni del §6, senza cui il livello 2 va riportato come sola copertura; se
   accettare l'assunzione sulle 18 famiglie il cui accoppiamento non e' verificabile (provato solo
   su UPX, match 0.9940 e 1.0000);
2. due script, nessuno dei quali tocca la cascata: il ponte che presenta le 29 coppie all'oracolo
   nel formato che si aspetta (manifest con `origin_sha256` piu' una cartella di master), e il
   punteggiatore delle quattro condizioni del livello 2;
3. **e' il primo corpus con malware reale.** `MAL_UNPACK_ENABLED` resta `False`, ma 7-Zip estrae
   payload veri su disco invece di emularli: snapshot della macchina virtuale, rete disattivata, e
   `UNPACKED_SAMPLES/` da trattare come cartella infetta.

La deduplicazione e' gia' verificata (§3.5 del protocollo): zero sovrapposizioni di SHA-256 fra i
29 esterni e la matrice interna, e zero fra i 29 puliti esterni e i 53 master interni.

### Rifiniture, quando il resto è chiuso

- difetto A8: decidere se tracciare i risultati in git o correggere il README;
- ricostruzione della tabella degli import (difetto A7), oppure scalare la rivendicazione in tesi;
- `mal_unpack`, solo dopo aver verificato l'isolamento della macchina virtuale;
- ELF, sviluppo futuro dichiarato.

---

## 12. Cosa la Fase 2 non sa fare (limiti dichiarati)

**Non ricostruisce la tabella degli import.** Il commento nel codice lo dice: *"import directory
dello stub, IAT non ricostruita"*. Un file con entry point corretto, sezioni riallineate e
riposizionamento disattivato è **codice leggibile da un disassemblatore**, non il file originale
identico: le chiamate alle funzioni di sistema restano indirizzi grezzi invece di nomi. In tesi la
rivendicazione corretta è *"ripristinare la leggibilità statica del payload"*, non *"ricostruire
l'eseguibile originale"* — a meno di implementare la ricostruzione, che è un lavoro a sé.

**Non garantisce niente sui protector.** Themida e VMProtect trasformano il codice in una forma che
non è più il codice originale. Il massimo ottenibile è arrivare al punto in cui il codice
trasformato è visibile e analizzabile.

**Non esegue i campioni**, salvo attivare esplicitamente `mal_unpack`. Tutto il resto è analisi
statica o emulazione.

**Non copre le DLL nel ramo emulato** (§2).

**Non sostituisce l'analisi umana**: la riduce. IDA Free resta l'ultima risorsa, e il numero di
casi che ci finiscono è il vero indicatore di successo della Fase 2.
