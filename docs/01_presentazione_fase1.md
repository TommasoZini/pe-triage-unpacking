# Fase 1 — Triage statico per il rilevamento del packing

**Framework automatizzato a cascata per l'analisi statica, il de-offuscamento e l'unpacking di
eseguibili PE/DLL**

Presentazione della prima fase · 28 settembre 2026

---

## 1. Il problema

Un **packer** prende un eseguibile e ne produce un altro in cui il codice originale è compresso o
cifrato, più un piccolo programma (**stub**) che al momento dell'avvio lo ricostruisce in memoria.
Il risultato: l'analisi statica non vede il codice vero.

Il framework è una **cascata**: si prova a ricostruire il codice originale con strumenti sempre più
costosi, dall'unpacker dedicato fino all'emulazione e all'analisi manuale.

**Il problema di scala.** Spacchettare un singolo file costa minuti — emulazione con Qiling, analisi
con Ghidra, a volte intervento manuale. Passare *tutti* i file alla cascata è insostenibile.

### Cosa fa la Fase 1

Riceve una cartella di eseguibili e, per ciascuno, risponde a **una sola domanda**:

> *Questo file è stato pacchettizzato, sì o no?*

Costa **meno di un secondo per file** ed è il filtro che decide su cosa vale la pena spendere i
minuti della Fase 2.

**Cosa non fa:** non spacchetta, non esegue i file, non dice se il file è un malware. L'analisi è
puramente **statica** — il file viene letto, mai eseguito. È una scelta di sicurezza, dato che il
dataset contiene malware reale, oltre che di velocità.

---

## 2. Terminologia

| termine | significato |
|---|---|
| **PE** | *Portable Executable*: il formato di `.exe` e `.dll` di Windows |
| **Sezione** | blocco interno del file con nome e permessi: `.text` il codice, `.data` i dati, `.rsrc` le risorse |
| **Entry point (EP)** | indirizzo della prima istruzione eseguita. In un programma normale cade in `.text` |
| **Entropia (Shannon, 0–8)** | misura del disordine dei byte. Codice compilato: 5,5–6,5. Dati compressi o cifrati: > 7,0 |
| **IAT / import** | elenco delle funzioni di sistema che il programma usa. Un programma normale ne importa decine o centinaia |
| **Overlay** | dati in coda al file, fuori da ogni sezione |
| **W+X** | sezione scrivibile *ed* eseguibile: inusuale nel software normale, tipica di uno stub che si decomprime |
| **Ground truth** | la risposta di riferimento: senza di essa non esiste la nozione di "errore" |
| **Oracolo** | chi garantisce una label. Vale solo se **non guarda le stesse cose** che il rilevatore valuta |

---

## 3. La scelta centrale: definizione operativa di "packed"

> **Un eseguibile è `packed` quando presenta un'alterazione strutturale — compressione, cifratura,
> offuscamento, wrapping SFX/installer o protezione applicata dal vendor — che rende il codice
> originale non direttamente analizzabile tramite analisi statica.**
>
> La classificazione dipende **solo dalla struttura del file**: mai dal fatto che il software sia
> malevolo o legittimo, né dalle intenzioni di chi ha applicato la trasformazione.

### Perché

Se un malware comprime il proprio codice per eludere l'analisi e un installer lo comprime per
occupare meno spazio, **il file risultante è alterato allo stesso modo** e fa scattare le stesse
metriche. Una regola che volesse distinguerli dovrebbe conoscere l'*intenzione*, che non è scritta
da nessuna parte nel file.

Il vantaggio è che la regola resta **uniforme**: nessuna eccezione ritagliata su un produttore.
La stessa misura che intercetta Themida intercetta Warbird, la protezione che Microsoft applica ai
propri binari di licensing.

### Il prezzo, e come si paga

La classe `packed` diventa eterogenea. Per questo i risultati vanno **sempre scomposti**:

| sotto-classe | esempi | destino in Fase 2 |
|---|---|---|
| packer/protector di terze parti | UPX, MPRESS, Themida, VMProtect | emulazione o unpacker dedicato |
| installer / SFX | NSIS, Inno Setup, `wextract.exe` | **estrazione**, non emulazione |
| protezione del vendor | `sppsvc.exe`, `ClipUp.exe` (Warbird) | fuori perimetro: rilevati e dichiarati |

### Il caso che valida la definizione

Quattro binari di licensing di Windows hanno `.text` con entropia **7,19–7,70** contro **6,28** di
`notepad.exe` sulla stessa macchina, e `sppsvc.exe` ha quattro sezioni chiamate `?g_Encry…`, un nome
che nessun compilatore produce. Sono protetti con **Warbird**.

**Detect It Easy non li nomina**: non restituisce nessun nome di packer. Il verdetto arriva da tre
indizi deboli — due strutturali (entropia di `.text`, entry point in sezione ad alta entropia o nomi
di sezione non standard) più l'euristica *generica* di DIE, che segnala «qualcosa di anomalo» senza
dire cosa. È la prima dimostrazione che le firme non bastano: nessuna li identifica, e servono le
misure strutturali per vederli.

---

## 4. Come decide: due livelli logici

```
esiste almeno UN segnale FORTE           →  packed
altrimenti, almeno 3 segnali DEBOLI      →  packed
altrimenti                                →  pulito
```

### I segnali forti (uno basta)

| segnale | cosa significa |
|---|---|
| nome di sezione tipico di packer | il file ha `UPX0`, `.vmp0`, `.themida`… Non è probabilistico: *è* quel packer |
| YARA con nome di packer | una regola che identifica un packer specifico |
| DIE nomina un packer/protector/installer | idem, da uno strumento indipendente |
| IAT minimale **con compressione osservata** | importa solo `LoadLibrary`+`GetProcAddress`, *e* c'è entropia alta o sezioni anomale |
| **stub strutturale** | l'EP è in una sezione a entropia ≥ 7,0 **e** (quella sezione è W+X **oppure** un'altra sezione eseguibile è svuotata) |
| **stub strutturale, ripiego .NET** | un assembly .NET ha `AddressOfEntryPoint = 0` per costruzione, quindi il segnale sopra non può scattare. Il ripiego cerca la stessa proprietà senza ancorarla all'EP |

L'ultimo è l'unico che funziona **senza conoscere il packer**, ed è quello che ha salvato i casi più
difficili (§7).

### I segnali deboli (ne servono 3 concordanti)

Entropia ≥ 7,2 · sezioni di dimensione anomala · EP in sezione non standard / ad alta entropia /
W+X / fuori da ogni sezione · overlay grande e compresso · nomi di sezione non standard · pochi
import · euristica DIE · sezioni stripped · header non parsabile.

### Perché non un punteggio percentuale

La prima versione sommava punti con soglia al 70 %. È stata abbandonata per tre ragioni:

1. **i pesi erano inventati, non misurati.** Misurando dopo: l'entropia distingue packed da puliti
   con 85 % contro 0 %; YARA generico distingue **al contrario** (12 % packed, 45 % clean). Un
   sistema additivo li sommava nella stessa valuta;
2. **il modello additivo è falso rispetto al fenomeno.** `UPX0` in una sezione *è* UPX, non "20
   punti su 100 di probabilità";
3. **non era tarabile.** Con due livelli il parametro da regolare è **uno solo**, e il suo effetto è
   misurabile.

### La qualità della prova

Oltre a sì/no, ogni file riceve `Packing_Evidence`, che dice **quanto è solida** la decisione e
serve a instradare la Fase 2:

| valore | significato | Fase 2 |
|---|---|---|
| `named` | il packer è riconosciuto **per nome** | può usare l'unpacker dedicato |
| `structural` | è packed, ma nessuno strumento sa dire quale | deve emulare |
| `weak_only` | 3+ indizi deboli, nessuna prova forte | caso incerto, spenderci poco |
| `none` | pulito | non passa alla Fase 2 |

---

## 5. Gli strumenti, e il ruolo di ciascuno

Quattro strumenti, nessuno sufficiente da solo.

| strumento | versione | ruolo |
|---|---|---|
| **LIEF** | 1.0.0 | legge la struttura: sezioni, EP, import/export, overlay. Non "riconosce" niente: fornisce i numeri |
| **Detect It Easy** | 3.21 (CLI `diec.exe -j -u`) | database di firme: nomina il packer. Fonte di segnale forte |
| **YARA-Forge** | yara 4.5.4 | regole di pattern pubbliche. Forte **solo** se la regola nomina un packer |
| **capa** | 9.4.0 | **disattivato per default** |

### Due decisioni motivate da misure

**`-d` (deep scan) di DIE rimosso.** Su 46 file non aggiungeva nemmeno un rilevamento nominato sui
packed, ma faceva dire *"protector: VMProtect"* a **9 binari puliti**. Un'opzione che aggiunge
rumore e nessuna informazione va tolta.

**capa disattivato.** Su 189 file consumava **1.539 s su 1.599 (96 %)**, produceva **0 segnali
forti** e cambiava **0 verdetti**. La causa è strutturale: capa scrive il nome del packer nel JSON
solo *alla fine*, mentre il banner di packing compare *all'inizio*. Fermando il processo al banner
per risparmiare tempo si perde il nome; lasciandolo finire si pagano minuti per file. Resta
disponibile con `--capa-mode full` per un confronto fra strumenti su un sottoinsieme.

**Effetto complessivo:** 189 file da **1.599 s a 57 s**, e decisioni prese con uno strumento
interrotto da timeout **da 73/189 (39 %) a 0**. Il secondo numero conta più del primo: la velocità
non è stata comprata tagliando analisi a metà.

---

## 6. Il dataset

### Il principio organizzativo

I dataset sono raggruppati per **affidabilità della label** al primo livello e per **oracolo** al
secondo. Non per label binaria: quattro sorgenti contengono label miste (System32 contiene 7 file
*packed* — Warbird, SFX, PlayReady), e un nome per label sarebbe falso.

```
E:\DATASET\
├── 01_LABEL_CERTA\        oracolo esterno verificabile — produce le metriche
│   ├── matrice_packed\    353   packer eseguito da noi
│   ├── system32\         1990   firma Authenticode Microsoft
│   ├── goodware_non_ms\  1042   distribuzioni ufficiali non-Microsoft
│   ├── pypi\              341   wheel ufficiali PyPI
│   ├── pma_book\           48   dichiarazione del libro PMA
│   └── gorust\             16   compilati in proprio
├── 02_MATERIA_PRIMA\
│   └── masters\            56   originali puliti per il packing, mai valutati
└── 03_NON_ETICHETTATI\    analisi qualitativa, mai metriche
    ├── flare_vm\          800   hard set
    ├── wild_malwarebazaar\181   malware reali, label proposte dai tag
    ├── legacy_misto\      125
    ├── malware_reali\      16
    └── autopacked_vecchi\  15
```

### Gli oracoli, in ordine di forza

| oracolo | come funziona | campioni |
|---|---|---|
| **Compilazione in proprio** | i binari Go/Rust li abbiamo compilati noi, comando registrato | 16 `clean` |
| **Esecuzione del packer** | la label non è un'inferenza: abbiamo eseguito il packer | 353 `packed` |
| **`upx -t`** | è UPX stesso a confermare di poter decomprimere | 10 `packed` |
| **Firma Authenticode Microsoft** | il file è firmato digitalmente da Microsoft | 1.994 `clean` |
| **Wheel ufficiali PyPI** | provenienza: installate via `pip` dal `requirements.txt` | 341 `clean` |
| **Distribuzioni ufficiali non-Microsoft** | provenienza: MSYS2, Cygwin, VLC, PuTTY, Notepad++, curl scaricati dai repository upstream, digest verificato dove pubblicato | 1.042 `clean` |
| **Libro PMA** | l'appendice dichiara la natura di ogni campione | 48 |
| **Verifica manuale documentata** | Warbird, SFX, PlayReady: analizzati a mano con motivazione scritta | 13 |

I primi due sono **certezze**: sappiamo cosa è stato fatto al file perché l'abbiamo fatto noi.

> **Regola non negoziabile:** una scansione automatica può creare **solo** voci `unknown`. "Non è
> packed" è un'affermazione che richiede una verifica, non l'assenza di segnalazioni.

Questa regola ha evitato un errore reale: una cartella chiamata `TEST_BIN_PULITI` conteneva
campioni del libro PMA (malware) e materiale FLARE VM, e **15 file che sembravano falsi positivi
erano in realtà veri positivi**.

### La matrice di campioni packed

Il pezzo centrale: **6 packer × 56 master puliti**, più due combinazioni a due strati.

| layer | campioni | | layer | campioni |
|---|---|---|---|---|
| Themida | 53 | | UPX | 44 |
| NSIS | 53 | | UPX + NSIS | 44 |
| Inno Setup | 53 | | UPX + MPRESS | 8 |
| MPRESS | 50 | | | |
| VMProtect | 48 | | **totale** | **353** |

Tre proprietà di progetto:

- **generazione deterministica**: seed fisso, la selezione dei master è riproducibile;
- **disegno appaiato**: ogni campione conserva `origin_sha256`, l'hash dell'originale pulito, quindi
  si può confrontare lo **stesso identico binario** prima e dopo;
- **mai in place**: ogni combinazione parte dal master intatto. L'alternativa — impacchettare sul
  posto e poi spacchettare per tornare indietro — avrebbe fatto dipendere la correttezza del dataset
  dalla correttezza di ciò che la tesi deve misurare. **Circolarità metodologica.**

### Un vincolo imposto dallo strumento, da dichiarare

UPX rifiuta i file con **Control Flow Guard** (`GUARD_CF enabled PE files are not supported`).
Misurato: **solo il 5 % di System32 è impacchettabile con UPX** (93 file su 1.990) contro il **94 %
dei binari MinGW** (88 su 94). I master sono quindi in maggioranza di toolchain più datate: è una
restrizione dello strumento, non una scelta di comodo.

---

## 7. I risultati

### Matrice di confusione

| | predetto packed | predetto pulito |
|---|---|---|
| **realmente packed** | **378** | **0** |
| **realmente pulito** | **0** | **3.435** |

Su **3.813 campioni etichettati**. Precision 1,000 · Recall 1,000 · F1 1,000.
**0 decisioni prese mentre uno strumento era in timeout.**

### Come vanno letti — la lettura asimmetrica

- **0 falsi positivi su 3.435 puliti**, da **cinque oracoli indipendenti** → limite superiore al
  95 % sul tasso di falsi allarmi: **~0,09 %**.
- **Quel numero è però in parte in-sample, e va detto.** Le 16 correzioni che hanno portato i falsi
  positivi da 23 a 0 sono state ricavate **guardando System32**, che resta nella misura e vale 1.994
  dei 3.435. L'argomento indipendente è un altro, e non è uno split: le eccezioni erano già scritte
  quando la classe negativa era il **solo System32**, e **1.383 campioni puliti sono entrati nel
  corpus dopo** — 341 wheel PyPI e 1.042 binari da distribuzioni ufficiali non Microsoft, questi
  ultimi analizzati a rilevatore congelato. Su nessuno dei 1.383 è scattato un segnale forte, e
  **nessuno ha prodotto un falso positivo** (1.399 contando anche i 16 Go/Rust compilati in
  proprio).
- Di quei puliti, **1.042 non sono Microsoft** (MSYS2, Cygwin, VLC, PuTTY, Notepad++, curl:
  MinGW-w64, Cygwin, MSVC di terze parti, llvm-mingw). Prima la classe pulita era all'83 % firmata
  Microsoft, ora al 58 %: l'obiezione "è tarato su una sola toolchain" non regge più. Su quei 1.042
  file **nessun segnale forte è scattato** e solo **14** hanno raggiunto 2 segnali deboli su 3.
  Quei 14 sono il contributo di questa classe ai **164** falsi positivi che comparirebbero se la
  soglia scendesse a 2.
- **0 falsi negativi su 378 packed** → in tesi si scrive *"nessun falso negativo osservato su 378
  campioni"*, **mai** "recall del 100 %". La misura vale per le **sei famiglie della matrice
  generata** (UPX, NSIS, Inno, MPRESS, Themida, VMProtect: 355 dei 378 campioni); le altre sette
  presenti — Warbird, SFX Microsoft, PlayReady, FSG, PECompact, ASPack, (Win)Upack — hanno da 1 a 4
  campioni ciascuna e non reggono nessuna affermazione statistica.

### Come si è arrivati a zero falsi positivi

All'inizio erano **23**. Risolti in due modi, e la distinzione è il punto metodologico:

**16 su 23 con correzioni al codice**, basate su una proprietà **generale**:

| causa | n | correzione |
|---|---|---|
| binari kernel-mode e boot (`ntoskrnl`, `ntdll`, `winload`…) | 13 | nomi di sezione del kernel (`PAGE*`, `INIT*`) riconosciuti come standard; eccezione al segnale "pochi import" per i driver e per i binari con export table consistente. Motivazione: *ntdll ha 2.433 export e 0 import per costruzione* — non *"escludi ntdll"* |
| entropia nelle **risorse**, non nel codice | 3 | `.rsrc` escluso dal calcolo dell'entropia che alimenta il segnale: le risorse contengono PNG e tabelle di testo, già compressi per natura |

**7 su 23 erano label sbagliate**, non errori del rilevatore: `wextract.exe` e i cinque binari
Warbird/PlayReady **sono** pacchettizzati secondo la definizione del §3.

**Nessuna correzione ha mai perso un vero positivo.**

### La soglia dei 3 segnali deboli

| soglia | falsi positivi | falsi negativi |
|---|---|---|
| 1 | 668 | 0 |
| 2 | **164** | 0 |
| **3 (in uso)** | **0** | **0** |
| 4 | 0 | 4 |
| 5 | 0 | 5 |

Calcolata su 3.435 puliti e 378 packed. I **164** della soglia 2 sono esattamente i puliti che oggi
stanno a due segnali deboli, e i **668** della soglia 1 sono quelli a due piu' quelli a uno
(164 + 504): la tabella del margine e lo sweep sono due calcoli indipendenti che coincidono.

**Nota metodologica.** *Prima* delle correzioni la stessa tabella indicava 4 come valore migliore.
Alzare la soglia avrebbe **mascherato segnali difettosi al prezzo del recall**; correggere le cause
ha reso 3 l'ottimo. Un iperparametro va usato come diagnostico, non come cerotto.

---

## 8. Il risultato originale: VMProtect a 32 bit

Sui campioni generati internamente — quindi con label certa al 100 %:

| | campioni | DIE lo riconosce |
|---|---|---|
| VMProtect a **64 bit** | 26 | **25 (96 %)** |
| VMProtect a **32 bit** | 23 | **0 (0 %)** |

Stesso programma, stessa versione 3.10.6, stesse impostazioni. VMProtect 3.x **randomizza i nomi
delle sezioni**, quindi le firme che cercano `.vmp0` fallliscono.

**Quei 23 campioni sono stati intercettati solo dal segnale "stub strutturale"**: EP in una sezione a
entropia 7,82 con le sezioni eseguibili svuotate.

> Senza i segnali strutturali sarebbero **23 falsi negativi**. È la giustificazione sperimentale
> dell'architettura forte/debole, su campioni la cui label non è contestabile perché li abbiamo
> prodotti noi.

---

## 9. Verifica su malware reale

Ultima verifica, su materiale che non viene né dalla matrice né da System32: **168 malware reali**
da MalwareBazaar, con i tag di packer dichiarati da terzi.

| tag | campioni | segnalati packed *(stato attuale)* | DIE nomina il packer atteso |
|---|---|---|---|
| `upx` | 43 | **42 (97 %)** | 42/43 (98 %) |
| `vmprotect` | 56 | **52 (92 %)** | **10/56 (18 %)** |
| `themida` | 9 | **8 (88 %)** | 7/9 (78 %) |
| `_senza_tag` | 60 | 12 (20 %) | — |

**Su VMProtect reale DIE nomina 10 campioni su 56; la Fase 1 ne segnala 52, di cui 34 solo grazie
ai segnali strutturali.**

È la stessa cosa osservata sulla matrice generata in casa, ora riprodotta su materiale reale
etichettato da altri. Una previsione ottenuta da campioni controllati che si verifica *in the wild*.

### Il contro-campione: misurare la distorsione di selezione

I 60 file `_senza_tag` esistono per un motivo preciso: un file è taggato `fsg` solo perché
**qualcuno l'ha riconosciuto**. I campioni non riconosciuti non sono taggati e non entrano mai nel
campione, gonfiando artificialmente il recall.

I segnalati erano inizialmente 15, **tutti verificati a mano** uno per uno: **12 veri positivi**
(6 con packer nominato da DIE — `.NET Reactor`, SFX Microsoft, NSIS — quindi packer veri che
nessuno aveva taggato) e **3 falsi positivi**.

Le cause dei 3 sono state individuate, corrette nel codice e la Fase 1 è stata rieseguita: ora i
segnalati sono **esattamente 12**, cioe' i 12 che l'analisi manuale aveva giudicato veri positivi.

| causa del falso positivo | correzione | costo misurato |
|---|---|---|
| **Risoluzione dinamica degli import** (2 campioni): il segnale forte "IAT minimale" scattava su malware che importa solo `LoadLibrary`+`GetProcAddress` per risolvere il resto a runtime. È evasione, non compressione: `.text` a entropia 5,45–6,20 è codice in chiaro | il segnale diventa forte **solo se corroborato** da entropia alta o sezioni anomale; altrimenti è declassato a debole, non scartato | **0 veri positivi persi**: "IAT minimale" non era mai l'unico segnale forte, e dopo la correzione resta forte su tutti e 64 i packed che l'avevano |
| **Nomi di sezione Delphi** (1 campione): `.itext` e `.didata` sono prodotte dal compilatore Delphi ma non figuravano fra le sezioni standard | aggiunte a `STANDARD_SECTIONS`, come già fatto per le famiglie kernel `PAGE*`/`INIT*` | **0 veri positivi persi**: 53 packed hanno quelle sezioni (sono gli installer Inno, che è un programma Delphi) ma hanno tutti segnali forti |

Entrambe sono della stessa natura delle 16 correzioni che avevano portato i falsi positivi da 23 a 0
su System32: **si corregge la causa strutturale, non il campione**. È la terza iterazione dello
stesso metodo.

> **Come va riportato:** questo è un'**analisi di accordo con i tag**, non una misura di recall.
> Le label hanno **circolarità** (molti tag nascono da strumenti della famiglia di DIE e YARA) e
> **distorsione di selezione**. Non sono state importate nella ground truth, per non contaminarla.

---

## 10. Validazione su dataset esterno

Le misure dei paragrafi precedenti hanno un limite che va dichiarato: **il dataset l'abbiamo
costruito noi**. Il 93 % dei campioni packed è auto-generato e la classe negativa è materiale
raccolto da noi, sul quale le correzioni ai falsi positivi sono state tarate.

Per chiudere il cerchio serve un banco di prova che non abbiamo toccato.

### Il dataset

**`packing-box/dataset-packed-pe`** — dataset pubblico, 3.664 campioni, 25 famiglie di packer,
analizzato **per intero**.
È un fork già sanificato di `chesvectain/PackingData`: gli autori dichiarano di aver rimosso i
campioni UPX trovati per errore nella cartella `not-packed` e deduplicato gli hash fra cartelle.

| cartella | campioni | |
|---|---|---|
| `packed/` | 3.080 | 25 famiglie |
| `not-packed/` | 432 | goodware: 7-Zip, Sysinternals, NirSoft, tool .NET |
| `outliers/` | 152 | *"campioni classificati not-packed ma con caratteristiche da packed"* — parole degli autori |

**Diciannove delle 25 famiglie non erano nel nostro dataset**, incluse FSG, ASPack, PECompact e
Petite: esattamente i punti ciechi che avevamo dichiarato perché non automatizzabili o non
reperibili con provenienza citabile.

### Verifica preliminare delle loro label

Prima di misurarsi contro un'etichettatura altrui bisogna verificarla, altrimenti si attribuiscono
al proprio rilevatore gli errori di chi ha etichettato. Tre controlli sui 442 `not-packed`, tutti
**indipendenti** dai segnali che la Fase 1 valuta:

| controllo | esito |
|---|---|
| `upx -t` (è UPX stesso a rispondere) | 0 positivi |
| nomi di sezione da packer noti | 1 |
| sovrapposizione col nostro corpus | 5 (verrebbero saltati) |

**441 su 442 puliti.** L'unico segnalato è `Uninstall.exe`, un disinstallatore NSIS: `.ndata` vuota
(`raw = 0`), `.text` a entropia 6,46, otto DLL importate. Non è un errore loro — è una **divergenza
di definizione**, su cui si torna più avanti.

### Il protocollo, firmato prima

Il protocollo è in `docs/05_protocollo_validazione_esterna.md`, redatto e firmato **prima** di
lanciare l'analisi. Serve a un solo scopo: rendere il risultato non negoziabile dopo averlo visto.

Tre vincoli che ne discendono, e che cambiano la forma di ciò che si può riportare:

**1. Da questo dataset non si calcolano precision, tasso di falsi positivi, accuracy né F1.**
La metà `not-packed` **non è un oracolo**: il fork ammette di aver rimosso da quella cartella
campioni compressi con UPX, e per ripulirla sono stati usati rilevatori della **stessa famiglia dei
nostri** — PEiD reimplementato, Bintropy, PyPackerDetect, REMINDer, tutti progetti dello stesso
gruppo. I casi difficili erano già stati tolti: misurare FP = 0 là sarebbe in parte una
**tautologia**, e un bias *ottimistico*, cioè il tipo che in tesi fa più danno.

Si riporta **una sola riga di matrice**, e si scrive che è una sola.

**2. L'oracolo della metà packed è invece costruttivo, e questo autorizza tutto il resto.**
432 programmi freeware (Sysinternals, NirSoft, PortableApps, 7-Zip) sono stati passati dentro 25
packer; l'etichetta è il nome della cartella di destinazione. **Nessun rilevatore partecipa
all'etichettatura.** È della stessa natura dell'oracolo di `pack_samples.py` — "è compresso perché
è stato compresso" — quindi misurare DIE e YARA su questo insieme **non è circolare**, e un mancato
rilevamento è un falso negativo vero.

**3. I file non analizzabili non sono falsi negativi.** Due campioni FSG non hanno magic `MZ`:
vengono esclusi dal triage e contati a parte.

### Il risultato

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** (3.220) | **TP = 3.219** | **FN = 1** |

**Recall 0,9997** — 3.219 su 3.220 campioni analizzabili, su 3.664 binari distinti.

### La sottoparte `outliers/`, che nessuno aveva contato

Il dataset contiene una cartella `outliers/` che il suo README descrive come i campioni *«potentially
disturbing our models … sorted among the not packed samples while demonstrating characteristics of
packed data»*: i **casi difficili scelti da altri, non da noi**. Sono 152 file che non stanno né in
`packed/` né in `not-packed/` (sovrapposizione misurata: zero), erano fuori dalla chiave di risposta
e quindi da ogni misura, pur essendo già stati analizzati. Il protocollo li conosceva — li elenca al
§2.2 — ma li metteva **tutti e 152** fra gli `unknown`, con una motivazione che vale solo per la metà
pulita; e quella prescrizione non era mai stata eseguita. I 142 sotto `outliers/packed/` sono
organizzati per famiglia esattamente come `packed/`, quindi hanno lo **stesso oracolo costruttivo**.

| sottoinsieme | campioni | rilevati | recall |
|---|---|---|---|
| `packed/`, le cartelle principali | 3.078 | 3.077 | 0,9997 |
| **`outliers/packed/`** | **142** | **142** | **1,0000** |

Tutti e 142 con evidenza `named`. Non aggiungono famiglie — sono 24 delle 25 già presenti — ma
aggiungono gli esemplari che qualcun altro ha giudicato i più insidiosi, ed è la cosa più vicina a
una selezione avversaria che questo corpus permette.

| gruppo | famiglie | rilevati |
|---|---|---|
| calibrazione | 5 | 598 / 598 |
| test | 20 | 2.479 / 2.480 |

La divisione calibrazione/test era dichiarata prima del run, sull'asse che conta qui — la famiglia
di packer — perché è per famiglia che si rivendica la generalizzazione.

### Il numero che porta il risultato in tesi

Non è il recall complessivo: è il recall sulle famiglie **che nessuna firma di sezione copre**.

| copertura | famiglie | rilevati |
|---|---|---|
| coperte da un prefisso di sezione | 7 | 901 / 901 |
| **scoperte** | **18** | **2.318 / 2.319** |

Su quelle 18 la tabella dei prefissi non ha una riga: il verdetto può venire **solo** da una firma
di terzi o dai segnali strutturali. È il test diretto di ciò che la tesi rivendica, su etichette a
oracolo costruttivo.

> **Un dettaglio metodologico da non nascondere.** La lista delle famiglie coperte era stata
> stabilita a priori nel protocollo deducendola dal nome; misurata sui dati **non coincide**.
> Enigma Virtual Box e RLPack risultano coperte (producono `.enigma1`/`.enigma2` e `.packed`, che
> un prefisso intercetta); NSPack e PECompact **non** lo sono, perché in questo dataset non
> producono le sezioni attese. I numeri sopra usano la copertura misurata, non quella dedotta.

### Il contributo delle firme, isolato

Questo dataset è pubblico da anni ed è il corpus di addestramento del progetto packing-box. **Non
si può escludere che parte dei match per nome venga da firme scritte conoscendo questi campioni.**

La mitigazione è riportare il numero che **non usa nomi**, immune a quella contaminazione per
costruzione:

- campioni senza alcun segnale forte da firma: **154**
- di questi, comunque segnalati packed: **153**

Un caso vale da solo: **Enigma Virtual Box, 123 campioni su 123 rilevati, e DIE non lo nomina mai.**
Vengono presi tutti dal nome di sezione `.enigma1`/`.enigma2`. È un esempio di famiglia che una
firma di terzi manca completamente e che il riconoscimento strutturale copre.

### L'unico falso negativo, guardato a mano

Il protocollo impone di esaminare ogni falso negativo prima di contarlo, e di classificarlo come
**difetto del rilevatore** oppure **caso di definizione** — entrambi si contano, il numero non si
sconta.

```
amber_SmartDefragBootTime.exe
   score 30 (2 segnali deboli su 3)     import 53      export 0
   entropia massima 6,63                 overlay assente
   EP in .text a entropia 6,02, non W+X  nessuna sezione di dimensione anomala
   unica sezione sospetta: .02iME4m      DIE: solo "Generic"
```

Il file **non presenta compressione osservabile**: entropia da codice compilato normale, entry point
nel posto giusto, cinquantatré import. L'unico indizio è un nome di sezione casuale. Gli altri 151
campioni Amber vengono riconosciuti da DIE come `cryptor: Amber`; su questo DIE tace.

Va contato come falso negativo. Ed è il tipo di caso che il rilevatore, per come è costruito, non
può prendere: senza compressione e senza firma non restano che i nomi di sezione, e da soli sono un
segnale debole — deliberatamente, perché promuoverli produrrebbe falsi positivi su ogni binario con
sezioni non convenzionali.

### Gli originali segnalati: osservazione, non metrica

Quindici dei 438 originali vengono segnalati — 7 SFX, 5 installer, 3 con altro segnale forte. **Non sono
falsi positivi misurati**, perché quella metà non è un oracolo. Servono come insieme di sospetti da
confrontare con i 10 che il gruppo terzo ha isolato in `outliers/not-packed`: un controllo
incrociato fra due selezioni indipendenti sullo stesso materiale.

Fra questi ricade la stessa divergenza di definizione già vista: un archivio auto-estraente è
`packed` per la definizione del §3 e `not-packed` per la loro, senza che nessuno dei due abbia
torto.

### Cosa questo misura, e cosa no

**Misura**: il recall su 25 famiglie, di cui 19 mai rappresentate nel nostro dataset, con etichette
a oracolo costruttivo. E quantifica quanto del merito è delle firme e quanto della struttura.

**Non misura**: falsi positivi, comportamento a 64 bit (**il dataset è a 32 bit**: misurato sul
campo `Machine` dell'header, 3.660 campioni su 3.664 sono x86, 2 sono x64 e 2 non hanno magic `MZ`;
anche i 142 `outliers/` sono x86 al 100 %, quindi non riducono questo limite), comportamento su malware reale (sono utility freeware compresse), comportamento su .NET, Go
o Rust (assenti).

**Una deviazione dal protocollo, da dichiarare.** Il §5 prescriveva di eseguire prima la sola
calibrazione e di non guardare le 20 famiglie di test fino a quel momento. Un campione preliminare
di 270 file ne ha invece estratti 8 da tutte e 25 le famiglie, quindi la sequenzialità non è stata
rispettata. La proprietà che conta resta però intatta: **nessuna correzione è stata applicata dopo
aver visto un solo risultato di questo dataset**, quindi i numeri non sono contaminati da taratura.
Per una conferma davvero cieca serve materiale ancora mai visto.

---

## 11. I limiti, dichiarati

Un limite documentato vale più di una funzionalità fatta a metà.

| limite | stato |
|---|---|
| **Offuscamento dell'IL .NET** | i packer che riscrivono l'IL non producono le firme strutturali cercate. Limite più stretto del previsto: i *crypter* .NET che incorporano un payload cifrato **vengono intercettati** dall'entropia, misurato su 5 campioni reali |
| ~~**Packer non testati** (FSG, ASPack, PECompact, Petite)~~ | ✅ **risolto dal dataset esterno** (§10): 8 campioni per ciascuna di queste famiglie, tutti rilevati. Restano non testati solo i packer assenti anche da lì (kkrunchy, Enigma classico) |
| **Un punto cieco residuo delle firme** | il campione `Lab18-02` del libro PMA resta un FSG su cui né DIE né YARA producono un nome: le firme coprono le versioni note di un packer, non tutte |
| **Taratura in-sample su System32** | le 16 correzioni che hanno azzerato i falsi positivi sono state ricavate da System32, che resta nella validazione e vale 1.994 dei 3.435 puliti. Il `FP = 0` complessivo è quindi **in parte in-sample**. L'argomento indipendente è cronologico e non uno split: **1.383** puliti (341 PyPI + 1.042 distribuzioni ufficiali) sono entrati nel corpus **dopo** che le eccezioni erano scritte, e non hanno prodotto alcun falso positivo. Le due correzioni successive (§12) vengono invece dai 168 malware reali, che **non sono nella matrice** |
| **Due segnali deboli non indipendenti** | «entropia ≥ 7.2» e «EP in sezione ad alta entropia» scattano da una sola misurazione quando la sezione dell'EP è la più calda. Succede su **5 file su 3.813**: 3 campioni Warbird/PlayReady raggiungono la soglia con due fatti invece di tre, e `x86_MLS6.dll` (pulito, firmato Microsoft) è il file più esposto della classe negativa. Correggerlo introdurrebbe 3 falsi negativi, quindi è dichiarato e non corretto |
| **ELF** | supporto presente ma incompleto |
| **File MSI** | non sono PE (contenitori OLE): esclusi dal perimetro |
| **Nessun punteggio continuo** | l'output è binario: **non si può tracciare una curva ROC/PR** |
| **Riproducibilità** | percorsi degli strumenti come costanti negli script. Mitigato da `preflight.py`, che dice cosa manca e dove correggerlo |

### Classi ancora assenti

Goodware non-Microsoft ampio (MSYS2/Cygwin, installer legittimi reali) · assembly .NET offuscati
con ConfuserEx · packer a 64 bit di terze parti oltre ai quattro della matrice.

---

## 12. Riproducibilità

Non è un dettaglio accessorio: è ciò che rende i numeri verificabili.

| meccanismo | cosa garantisce |
|---|---|
| **chiave = SHA-256 del contenuto** | il nome file non identifica un campione. Nel progetto esistevano due file omonimi di 268.800 e 627.466 byte: con lo storico basato sul nome si coprivano a vicenda e 15 file non venivano mai analizzati |
| `tool_diagnostics.jsonl` | una riga per **ogni invocazione** di strumento, con versioni, durate ed esito. È ciò che permette di affermare "0 decisioni sotto timeout" invece di sperarlo |
| CSV incrementale con flush per riga | un'interruzione non perde il lavoro fatto |
| controllo `BATCH INCOMPLETO` | se le righe scritte non corrispondono ai candidati lo dice: un CSV parziale non passa per valido |
| **44 test automatici** | uno è `expectedFailure` di proposito: documenta un difetto noto, con la motivazione nella docstring |
| `E:\DATASET\INDICE.md` generato | la mappa dei dataset è **calcolata**, non scritta a mano: un indice redatto va fuori sincrono al primo file aggiunto |
| label manuali in file versionati | `config/*_labels.json`, non comandi una tantum |

---

## 13. In sintesi

La Fase 1 legge un eseguibile senza eseguirlo, ne misura la struttura, la confronta con le firme di
due strumenti indipendenti, e applica una regola a due livelli: **una prova forte basta, altrimenti
servono tre indizi deboli concordanti**.

È stata misurata su tre livelli, con affidabilità decrescente della label e indipendenza crescente
dal nostro lavoro:

| banco di prova | campioni | esito |
|---|---|---|
| **corpus interno**, cinque oracoli verificabili | 3.813 | 378 packed tutti riconosciuti, 3.435 puliti nessuno segnalato |
| **malware reale** da MalwareBazaar, tag di terzi | 168 | accordo 97 % UPX, 92 % VMProtect, 88 % Themida |
| **dataset pubblico esterno**, 25 famiglie | 3.220 | **recall 0,9997** — 1 solo falso negativo (solo recall: vedi §10) |
| di cui gli **`outliers/`**, i casi difficili scelti dagli autori del dataset | 142 | **142 / 142**, tutti `named` |

**Il risultato che conta non è lo zero, sono due numeri che si contraddicono solo in apparenza.**

Sul dataset esterno il rilevamento è dominato dalle firme: 195 dei 200 packed sono riconosciuti per
nome, e senza DIE se ne perderebbero 8. Su VMProtect a 32 bit accade il contrario: **DIE nomina 0
campioni su 23 generati da noi e 10 su 56 malware reali**, e sono i segnali strutturali a prenderli.

Le firme coprono bene i packer noti e vecchi; falliscono sistematicamente sui protector moderni che
randomizzano la propria struttura. Nessuna delle due famiglie di segnali basta da sola, e la Fase 1
misura con dati quanto vale ciascuna. **È questa la tesi che dimostra.**

### Prossimo passo: Fase 2

Prendere i file marcati `packed` e provare a ricostruirne il codice originale. La Fase 1 produce già
l'informazione per instradarli: `Packing_Evidence` dice se serve un unpacker dedicato o
l'emulazione, e `Die_Packer_Type` distingue gli **installer**, che vanno *estratti* e non emulati.

---

### Documenti di riferimento

| file | contenuto |
|---|---|
| `02_fase1_riferimento_tecnico.md` | documentazione tecnica completa: flusso, segnali, dataset, 51 colonne del CSV |
| `03_setup_e_esecuzione.md` | installazione ed esecuzione su un'altra macchina |
| `04_fase1_log_sessioni.md` | log delle sessioni: ogni difetto trovato, come è stato misurato, come è stato corretto |
| `Pipeline_Reports/validation_phase1.md` | metriche rigenerate a ogni run |
| `E:\DATASET\INDICE.md` | mappa dei dataset, generata |
