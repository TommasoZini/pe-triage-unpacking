# Protocollo di validazione esterna su `dataset-packed-pe`

**Stato: FIRMATO il 28/09/2026, prima del run. ESEGUITO il 30/09/2026.**
Esito in `Pipeline_Reports/validation_external_dataset_packed_pe.md`, riletto e riconciliato
il 01/10/2026 (§24.1 del log di sessione). Il testo delle sezioni 1-12 è quello firmato: non è
stato modificato dopo aver visto i risultati, ed è questa la ragione per cui vale come
registrazione preventiva.

> **Sulle cifre citate nel corpo.** Le sezioni 1-12 riportano lo stato della ground truth **al
> momento della firma** — `2.393 clean + 378 packed = 2.771`, quattro classi negative. Dal
> 29/09/2026 la classe negativa comprende anche i 1.042 binari da distribuzioni ufficiali non
> Microsoft, quindi lo stato corrente e' `3.435 clean + 378 packed = 3.813` su cinque oracoli.
> I numeri qui sotto **non sono stati aggiornati di proposito**: sono quelli su cui il protocollo
> e' stato firmato. Lo stato corrente e il margine per oracolo stanno nel §24 di
> `04_fase1_log_sessioni.md`.
Data di redazione: 28/09/2026.

Questo documento si firma **prima** di lanciare l'analisi. Serve a un solo scopo: rendere il
risultato non negoziabile dopo averlo visto. Vale lo stesso vincolo del protocollo sui `.pyd`
(§14.4 dell'analisi Fase 1): se quello che segue viene usato per tarare qualcosa, cessa di essere
una misura esterna.

---

## 1. La domanda a cui questo run risponde

**Una sola:** quanti eseguibili realmente compressi o protetti la Fase 1 riesce a segnalare, su
famiglie di packer che non ha mai visto, e **quale parte del merito è dei segnali strutturali
invece delle firme**.

Domande a cui questo run **NON** risponde, e che non vanno chieste ai suoi numeri:

- quanti falsi positivi produce la Fase 1 — la metà "pulita" del dataset non è un oracolo (§3.2);
- come si comporta su file a 64 bit — il dataset è a 32 bit (§2.3);
- come si comporta su malware reale — qui non c'è malware, sono utility freeware compresse;
- come si comporta su .NET, Go o Rust — assenti.

---

## 2. L'oggetto: cosa è questo dataset, verificato

Fonte: `https://github.com/packing-box/dataset-packed-pe`, commit **`45bf915f`** (13/07/2024).
Fork *sanitizzato* di `chesvectain/PackingData` (2019), il cui README contiene solo il titolo.
**Nessuna licenza dichiarata: si cita, non si ridistribuisce.**

Copia locale: `E:\dataset-packed-pe-main`.

### 2.1 Come sono nate le etichette — il punto che autorizza tutto il resto

432 programmi freeware (Sysinternals, NirSoft, PortableApps, 7-Zip) sono stati passati dentro
25 packer. I nomi conservano l'origine: `upx_ADExplorer.exe` è `ADExplorer.exe` passato dentro UPX,
e `ADExplorer.exe` sta nella cartella accanto.

Lo script `labels/generate-category-labels.py` assegna l'etichetta come
`sha256(file) -> categoria dedotta dal nome della cartella`. **Nessun rilevatore partecipa
all'etichettatura della classe positiva.**

Conseguenza metodologica: l'oracolo è **costruttivo** — "è compresso perché è stato compresso" —
cioè della stessa natura dell'oracolo di `pack_samples.py`. Quindi **misurare DIE, YARA e capa su
questo insieme non è circolare**. Un mancato rilevamento è un falso negativo vero, non un'etichetta
da mettere in dubbio come i 6 casi del §17.5.

### 2.2 Composizione

| cartella | file | contenuto |
|---|---|---|
| `packed/` | 3.080 | 25 packer, 115-152 campioni ciascuno |
| `not-packed/` | 432 | gli originali, **non verificati** |
| `outliers/not-packed/` | 10 | originali che "mostrano caratteristiche di dati compressi" |
| `outliers/packed/` | 142 | compressi scartati dai loro modelli |
| `labels.json` | 3.512 voci | chiave SHA-256, valore = nome packer oppure `null` |

`outliers/` **non è coperto** da `labels.json`.

### 2.3 Verifiche di integrità già eseguite (28/09/2026)

| controllo | esito |
|---|---|
| file presenti sul disco | 3.664 (3.080 / 432 / 152) |
| SHA-256 ricalcolati e assenti da `labels.json` | **0** |
| etichette incoerenti con la cartella di provenienza | **0** |
| architettura | **3.508 x86 su 3.512** (1 x64 in `not-packed`, 1 in `packed`) |
| file in `packed/` privi di magic `MZ` | **2**: `FSG/fsg_livekd.exe`, `FSG/fsg_Snap2HTML.exe` |

I 2 file FSG rotti vengono scartati dal filtro magic **prima** dell'analisi
(`Parse_Status = not_executable`). Vanno riportati come **non analizzabili, non come falsi
negativi**. Supporto reale: **3.078**.

Nessun file è stato rimosso dall'antivirus. Il controllo va **ripetuto immediatamente prima del
run** e il suo esito allegato, perché Defender può intervenire in qualunque momento su una cartella
di 1,35 GB di eseguibili protetti.

### 2.4 Struttura interna, e cosa vieta

- **472 basi distinte** nella cartella `packed`, **0 packate da tutti i 25 packer**, **183 basi
  presenti con un solo packer**. Non è un prodotto cartesiano.
  **Divieto:** il recall per packer si riporta come **descrittivo**, mai come classifica fra
  packer. Un confronto "recall su Themida contro recall su FSG" qui è confuso con la composizione
  delle basi. Quel confronto lo può fare solo la matrice di `pack_samples.py`, che è cartesiana.
- **109 basi su 472 non hanno l'originale** in `not-packed/`: il confronto accoppiato (§7) è
  possibile su **2.757 coppie / 363 basi**.
- Ogni packer ha 115-152 campioni su 472 basi possibili: sono solo i file su cui il packer **è
  riuscito**. I campioni presenti sono i più facili. Da dichiarare come selezione di
  sopravvivenza, con lo stesso argomento del §9.4.

---

## 3. Mappatura delle etichette nella ground truth

### 3.1 Cosa entra, e come

```
packed/<Packer>/<file>  ->  label    "packed"
                            source   "dataset-packed-pe@45bf915f"
                            dataset  "external_packed_pe"
                            packers  ["<Packer>"]      # strato singolo, mai multilayer
                            tier     "external"        # campo NUOVO
                            notes    "packato da terzi: cartella di provenienza; versione del
                                      packer ignota; non riproducibile in locale"
```

Chiave: SHA-256 ricalcolato in locale **e verificato contro `labels.json`**. Se un file non
combacia è corrotto: si scarta, non si analizza.

**Non si importano le categorie del dataset** (`compressor`, `cryptor`, `protector`,
`virtualizer`, `bundler`) come etichette. Sono una proprietà del *packer*, mentre
`named` / `structural` / `weak_only` è una proprietà della *nostra rilevazione*. Restano come
colonna descrittiva nella tabella dei risultati, e servono a leggere §6.3.

### 3.2 Cosa NON entra come `clean` — regola vincolante

`not-packed/` (432) e `outliers/` (152) entrano come **`unknown`**, tramite `--scan`.

Tre motivi, in ordine di forza:

1. Vale la regola già scritta in `build_ground_truth.py`: **una scansione non può dichiarare "non
   packed"**. È la disciplina che ha evitato i 15 finti falsi positivi di `TEST_BIN_PULITI`.
2. **Il fork ammette di aver rimosso da quella cartella campioni compressi con UPX.** La cartella
   conteneva file compressi: chi l'ha costruita ha assunto che freeware scaricato = non compresso.
3. Per ripulirla sono stati usati rilevatori della **stessa famiglia dei nostri** (PEiD
   reimplementato, Bintropy per l'entropia, PyPackerDetect, REMINDer per l'entry point). I casi
   difficili sono già stati tolti. Misurare `FP = 0` là sarebbe **in parte una tautologia**, e
   sarebbe un bias *ottimistico* — il tipo che in tesi fa più danno.

**Conseguenza dichiarata in anticipo: da questo dataset non si calcolano precision, tasso di falsi
positivi, accuracy né F1.** Si produce **una sola riga di matrice di confusione**, e si scrive che
è una sola.

> **Nota del 30/09/2026, aggiunta dopo la firma e senza toccare il testo sopra.** Questa regola
> mette `outliers/` **interi** fra gli `unknown`, ma i tre motivi che la giustificano riguardano
> tutti la metà *pulita*. Non si applicano a `outliers/packed/` (142 file), che è organizzata per
> famiglia come `packed/` e ha lo **stesso oracolo costruttivo**: l'etichetta è il packer eseguito,
> nessun rilevatore partecipa. Quei 142 rientrano quindi nel §3.3 come tier `external` — recall sì,
> falsi positivi no — e sono stati aggiunti alla chiave il 30/09 (`v3_chiave.csv`), con esito
> **142/142**. I 10 di `outliers/not-packed/` restano `unknown`, dove questa regola li vuole.
> Va inoltre registrato che la prescrizione `--scan` di questo paragrafo **non era mai stata
> eseguita**: nessuno dei 152 file aveva una voce nella ground truth. Dettagli in §23 del log.

### 3.3 Separazione dalle metriche principali — vincolo tecnico

`validate_phase1.py` deve leggere il campo `tier` e **tenere `external` fuori dalla matrice
principale**, che resta inchiodata a **2.393 clean + 378 packed = 2.771** da oracoli verificabili.

> **Nota del 29/09/2026, aggiunta dopo la firma e senza toccare il testo sopra.** La matrice
> principale è cresciuta a **3.435 clean + 378 packed = 3.813** con l'aggiunta di `goodware_non_ms`
> (§22 del log di sessione). Il vincolo di questo paragrafo non cambia — `external` resta fuori —
> cambia solo il numero a cui è inchiodata.

È lo stesso principio della colonna "metriche" del §16.9 (`tutte` / `mai valutata` /
`qualitativa`), con un quarto valore: **`separata`**.

Senza questo campo, 3.078 campioni di composizione diversa coprirebbero numericamente i 378
attuali, e la matrice principale smetterebbe di dire quello che dice oggi.

### 3.4 Deduplicazione obbligatoria

`flare_vm` e `legacy_misto` contengono strumenti Sysinternals e NirSoft: è attesa sovrapposizione
byte-identica con `not-packed/`. Dopo la lezione del §16.6 (7 file su disco, 2 binari distinti) la
deduplicazione per SHA-256 fra insiemi non è opzionale. I file già presenti nel CSV **non vengono
rianalizzati**, e il conteggio dei collassi va registrato.

---

## 4. Il rilevatore congelato

**Non si tocca una riga fra la firma di questo documento e la fine del run.**

| voce | valore |
|---|---|
| commit | `ff228c37c3584c4634f079cce576d3daf245b800` |
| albero tracciato | pulito, 0 modifiche |
| `scripts/header_elf_lief.py` | `d15285f4a6badffb09412c93afbcd871e7559c63ee047e8a0dd3854073ec9eff` |
| `scripts/validate_phase1.py` | `601664307722d8d885bc4697286dd3c1313131ad301de8871a8a026a8338e12a` |
| `scripts/build_ground_truth.py` | `52adc4feed6a780083753a108cb7d678fb0080ceccb953ecd211d8ba6c465d95` |

> **Emendamento del 11/10/2026 — i valori qui sopra NON sono stati riscritti.** Questo documento è
> una registrazione preventiva: riscriverne la tabella a posteriori ne distruggerebbe il senso.
> Due dei tre file sono oggi diversi — il ripiego .NET in `header_elf_lief.py` e la guardia sui
> file di servizio in `build_ground_truth.py` — e lo stato corrente, con l'effetto misurato di
> entrambe le modifiche, è registrato nel §24 di `04_fase1_log_sessioni.md`. La matrice è invariata.

Configurazione, inclusa la coppia di correzioni del §19 già applicata e committata:

| parametro | valore |
|---|---|
| `WEAK_SIGNALS_REQUIRED` | 3 |
| `EP_ENTROPY_THRESHOLD` | 7.0 |
| soglia entropia di sezione | 7.2 |
| `PACKING_THRESHOLD` | 70 (cosmetico) |
| `EXPORTS_REAL_API` | 10 |
| `ENTROPY_EXCLUDED_SECTIONS` | `.rsrc` |
| "IAT minimale" | segnale forte **solo se corroborata** (§19.1) |
| `.itext` / `.didata` | fra le sezioni standard (§19.1) |

**Unica eccezione consentita a `validate_phase1.py`:** l'aggiunta del campo `tier` e delle tabelle
di §6. È codice di *misura*, non di *decisione*, e non può cambiare un solo verdetto. Va committato
**prima** del run, con il suo hash registrato qui.

Le versioni dei tool esterni (LIEF, DIE, capa, YARA-Forge) si leggono dalla riga `phase1_start` di
`tool_diagnostics.jsonl` del run e si incollano nel referto. In questa finestra non si aggiorna
nessun tool: `update_yara.py` **non va lanciato**.

---

## 5. Divisione calibrazione / test, dichiarata prima

Il problema: se emerge un difetto sistematico, correggerlo richiede di guardare i campioni, e a
quel punto l'intero dataset diventa materiale di taratura — restando senza misura esterna.
La soluzione è quella del §14.4, applicata sull'asse che conta qui: la **famiglia di packer**,
perché la generalizzazione che si rivendica è per famiglia.

**Scelta fatta prima di aver visto un solo risultato.**

| gruppo | famiglie | campioni |
|---|---|---|
| **calibrazione** (5) | UPX, MPRESS, Themida, FSG, Molebox | 600, di cui 598 analizzabili |
| **test** (20) | Alienyze, Amber, ASPack, BeRoEXEPacker, Enigma Virtual Box, Eronana Packer, Exe32pack, EXpressor, JDPack, MEW, Neolite, NSPack, Packman, PECompact, PEtite, RLPack, TELock, WinUpack, Yoda-Crypter, Yoda-Protector | 2.480 |

Criterio della scelta, dichiarato: in calibrazione vanno le 3 famiglie **già presenti** nella
matrice in casa (UPX, MPRESS, Themida), quindi le meno informative come novità, più due casi attesi
come difficili e strutturalmente diversi fra loro — **FSG**, che produce PE minimali e contiene i
2 file rotti, e **Molebox**, che impacchetta invece di comprimere.

Regole:

1. Si lancia **prima** la sola calibrazione.
2. Il gruppo di test si lancia **una volta sola, alla fine**, e il numero che produce va in tesi.
   **Qualunque esito abbia.**
3. Le 20 famiglie di test **non si guardano** prima di aver chiuso la calibrazione.

---

## 6. Le misure da produrre — forma decisa in anticipo

### 6.1 Riga di matrice (una sola)

Su 3.078 campioni etichettati `packed`: **TP** e **FN**. Nessun'altra cella. Scomposta per gruppo
(calibrazione / test) e per famiglia.

### 6.2 Tabella 25 x 4 — è l'artefatto principale

Righe: le 25 famiglie, con la categoria dichiarata dal dataset come colonna descrittiva.
Colonne: `named` / `structural` / `weak_only` / `none`, più **"DIE nomina il packer atteso"**,
nella stessa forma della tabella del §17.1.

### 6.3 Il taglio che porta il risultato in tesi

Incrociando le 25 famiglie con `PACKER_SECTION_PREFIXES`:

| copertura firma-sezione | famiglie |
|---|---|
| **coperte** (7) | UPX, MPRESS, Themida, ASPack, NSPack, PECompact, PEtite |
| **scoperte** (18) | Alienyze, Amber, BeRoEXEPacker, EXpressor, Enigma Virtual Box, Eronana Packer, Exe32pack, FSG, JDPack, MEW, Molebox, Neolite, Packman, RLPack, TELock, WinUpack, Yoda-Crypter, Yoda-Protector |

Il numero da riportare è il **recall sulle 18 famiglie scoperte, con l'evidenza scomposta**. Su
quelle la tabella dei prefissi di sezione non ha una riga: il verdetto può venire solo da una firma
di terzi (DIE/YARA) o dai segnali strutturali. È il test diretto del livello che la tesi rivendica,
su etichette certe.

Nel gruppo di **test** le famiglie scoperte sono **16 su 20**.

### 6.4 Circolarità residua, e come si neutralizza

Non c'è circolarità nell'etichettatura (§2.1), ma questo dataset è il corpus di addestramento del
progetto packing-box ed è in circolazione da anni. Le firme DIE e le regole YARA-Forge sono
mantenute contro corpora pubblici. **Non si può escludere che una parte dei match `named` provenga
da firme scritte conoscendo questi campioni.**

Mitigazione, già disponibile e senza costo: **si riporta il recall `structural`-only separato**.
È la mossa del §13.6 e del §17.2 — su VMProtect reale DIE nomina 10 campioni su 56, la Fase 1 ne
segnala 52, di cui 34 per soli segnali strutturali. Il numero `structural`-only è immune a questa
contaminazione **per costruzione**, perché non usa nomi.

---

## 7. Confronto accoppiato — come si usa la metà "pulita" senza fidarsene

Per 2.757 coppie (363 basi) esistono sia l'originale sia il derivato compresso. Si analizzano anche
i 432 originali e si misura la **differenza dei segnali** fra originale e derivato.

La differenza è attribuibile al packing **qualunque sia la vera etichetta dell'originale**:
l'oracolo dubbio esce dall'equazione. Non serve chiamare `clean` un solo file.

Cosa si registra:

1. **Differenza nulla su un campione compresso** → quel packer non ha alterato la struttura in modo
   osservabile. Atteso su **Enigma Virtual Box** e **Molebox**, che impacchettano invece di
   comprimere. Va classificato come **caso di definizione**, distinto dai falsi negativi veri, e
   discusso — non nascosto.
2. **Originali che fanno già scattare 3 o più segnali deboli** → insieme di sospetti prodotto dal
   nostro rilevatore, da confrontare con i **10 file** che il gruppo terzo ha isolato in
   `outliers/not-packed`. È un controllo incrociato fra due selezioni indipendenti sullo stesso
   materiale.
3. `outliers/not-packed/Start_Here_Win.exe` pesa 18 MB ed è un autoestraente: per la definizione
   del §4.2 **è `packed`, e segnalarlo è corretto**. Loro lo trattano come rumore da scartare, noi
   come vero positivo. Questa divergenza va in tesi come paragrafo sulla definizione, non come nota
   a piè di pagina: è un caso in cui la definizione strutturale dà la risposta giusta dove una
   definizione basata sull'intento non ce l'ha.

Il confronto accoppiato è **interamente qualitativo**. Non produce metriche.

---

## 8. Ipotesi registrate prima del run

Si scrivono ora perché uno scostamento sia visibile invece di essere razionalizzato dopo.
**Sono previsioni, non requisiti: se cadono, cade la previsione — non si aggiusta lo strumento.**

| # | ipotesi | fondata su |
|---|---|---|
| H1 | Sulle 7 famiglie coperte da firma di sezione il recall è circa 100 % e l'evidenza è quasi tutta `named` | UPX/MPRESS/Themida al 100 % sulla matrice; UPX 97 % sul set wild |
| H2 | Sulle 18 scoperte il recall resta alto ma l'evidenza si sposta in massa su `structural` | §17.2: 34 su 52 VMProtect reali presi per sola struttura |
| H3 | I falsi negativi, se ci sono, si concentrano su **Enigma Virtual Box** e **Molebox** | impacchettano senza comprimere il codice originale; §17.5, il dropper con overlay da 63 MB |
| H4 | "DIE nomina il packer atteso" resta **molto sotto** il recall della Fase 1 sulle famiglie scoperte | §13.6 e §17.2 |
| H5 | Fra i 432 originali un numero **diverso da zero** supera la soglia, e sono i file tipo installer o portable | `PortableWinCDEmu-4.0.exe`, `grepWin-1.9.0_portable.exe`; e il fork ha già dovuto togliere file UPX da quella cartella |

H5 merita una precisazione vincolante: **se accade, non è un falso positivo.** Va verificato a mano
e, se il file è davvero un autoestraente o un installer, è un **vero positivo su un'etichetta
sbagliata del dataset** — e va riportato così, con l'evidenza.

---

## 9. Regole di interpretazione, decise prima di vedere i numeri

1. Ogni **falso negativo** si guarda a mano prima di essere contato: DIE, sezioni, entropia per
   sezione, import. Come per i 15 `_senza_tag` del §17.3.
2. Un falso negativo si classifica in una di tre categorie, decise sull'evidenza del file e non
   sulla convenienza:
   - **difetto del rilevatore** — la struttura è alterata e non l'abbiamo vista. Si conta come FN.
   - **caso di definizione** — il packer non ha alterato la struttura (bundler che accoda).
     Si conta **comunque** come FN e si discute separatamente: il numero non si sconta.
   - **file non analizzabile** — magic non valido. Fuori dal perimetro, come i 2 file FSG.
3. Se emerge un difetto sistematico, si corregge **la causa strutturale, mai il campione** — nello
   stesso modo in cui `ntdll` è stato risolto con "0 import ma 2.433 export" e non con una lista di
   esclusione.
4. **Una correzione applicata dopo aver visto la calibrazione obbliga a rianalizzare la
   calibrazione e lascia il gruppo di test intatto.** Una correzione applicata dopo aver visto il
   test brucia il test: da quel momento questo dataset è materiale di taratura e va dichiarato
   tale, senza scorciatoie.
5. Nessun numero di questo run entra nella matrice principale. Nessuna eccezione.

---

## 10. Esecuzione — sequenza

1. Rieseguire la verifica di integrità di §2.3 e allegarne l'esito.
2. Committare l'aggiunta del campo `tier` (misura, non decisione) e registrarne l'hash in §4.
3. `--scan` dei 432 originali e dei 152 `outliers` come `unknown`.
4. Importare `packed/` con `tier: "external"`, verificando ogni SHA-256 contro `labels.json`.
5. Fase 1 sulle **5 famiglie di calibrazione** (598 file).
6. Analisi a mano dei falsi negativi di calibrazione; eventuale correzione strutturale; se
   applicata, rianalisi della sola calibrazione.
7. Fase 1 sulle **20 famiglie di test** (2.480 file) — **una volta sola**.
8. Fase 1 sui 432 originali e sui 152 outliers, per il confronto accoppiato.
9. Tabelle di §6, referto, e paragrafo di tesi separato dalle metriche principali.

Costo stimato sul throughput misurato (168 file in 157 s, cioè 0,93 s per file): **circa 50 minuti**
per i 3.078, più i 584 fra originali e outliers. La cartella `Themida` però è 379 MB su 123 file,
quindi entropia, DIE e capa costeranno più della media: **mettere in conto 1-2 ore**.

---

## 11. Come va scritto in tesi

Paragrafo **separato** dalle metriche principali, con questa intestazione di onestà:

> Validazione esterna su un corpus di terzi con etichetta costruttiva. 3.078 eseguibili PE a 32 bit
> ottenuti passando 472 utility freeware dentro 25 packer distinti. L'etichetta deriva
> dall'operazione di packing e non da alcun rilevatore, quindi la misura di DIE, YARA e capa su
> questo insieme non è circolare. Il corpus **non** contiene malware, file a 64 bit, assembly .NET,
> binari Go o Rust, e la sua metà non compressa non costituisce un oracolo: da esso si riporta
> **il solo recall**, e non precision né tasso di falsi positivi.

Il valore aggiunto da rivendicare, con il suo perché: oggi nella classe `packed` della ground truth
gli installer (NSIS, Inno, UPX+NSIS) sono **150 su 378, circa il 40 %**, mentre l'oggetto della tesi
sono i packer di terzi. Questo corpus aggiunge **3.078 campioni di soli packer, protector, cryptor
e virtualizer, su 22 famiglie mai provate** — e chiude il problema di composizione che il §4.2
segnalava come la fragilità retorica più urgente.

---

## 12. Decisioni che servono prima di procedere

1. **Divisione calibrazione/test di §5**: approvata così, oppure si lancia tutto in una volta
   accettando di non avere più margine di correzione?
2. **Nome del quarto gruppo di cartelle**: `04_LABEL_ESTERNA` o altro. Vale la regola del §16.3 —
   la cartella corrisponde all'oracolo, non all'etichetta binaria.
3. **Spostamento fisico dei file** sotto `E:\DATASET\`, oppure si lascia il dataset dov'è
   (`E:\dataset-packed-pe-main`) agganciandolo da `make_dataset_index.py` tramite `EXTRA_DIRS`?
   Oggi `EXTRA_DIRS` è vuota, e il §16.9 la considera un risultato da preservare.
4. **I 432 originali**: si analizzano solo per il confronto accoppiato di §7 (raccomandato), oppure
   si vuole anche verificarne a mano un campione per promuoverli a `clean` e ottenere una quinta
   classe negativa? Oggi le classi negative sono quattro e coprono 2.393 campioni: il guadagno
   sembra basso rispetto al costo di verifica.

   > **Risposta, 29/09/2026.** La quinta classe negativa è arrivata per un'altra strada, senza
   > verifica manuale: `goodware_non_ms`, 1.042 PE scaricati dai repository ufficiali di MSYS2,
   > Cygwin, VideoLAN, PuTTY, Notepad++ e curl, con il digest upstream verificato dove pubblicato
   > (§22 del log). Costo: un comando e sei minuti di download. I 432 originali del dataset esterno
   > restano quindi non promossi, e la valutazione di questo punto — guadagno basso rispetto al
   > costo — resta valida.
