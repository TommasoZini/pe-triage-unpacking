# Fase 1 — Triage statico: come funziona, passo passo

**Documento di riferimento del progetto.** Spiega cosa fa la Fase 1, perché è fatta così, quali
dataset esistono e cosa contengono, quali script la compongono e come si esegue.
Scritto per essere leggibile da chi apre il progetto per la prima volta.

Aggiornato al **27 settembre 2026**. Branch `unpacking`, cartella `Unpacking/Packing`.

> Per **installare ed eseguire** su un'altra macchina: **`03_setup_e_esecuzione.md`**. Questo documento spiega
> cosa fa la Fase 1 e perché è fatta così; quello spiega come metterla in funzione.

---

## Indice

1. [Cosa fa la Fase 1 (e cosa non fa)](#1-cosa-fa-la-fase-1-e-cosa-non-fa)
2. [Il vocabolario minimo](#2-il-vocabolario-minimo)
3. [Che cosa significa "pacchettizzato": la definizione adottata](#3-che-cosa-significa-pacchettizzato-la-definizione-adottata)
4. [Gli strumenti usati](#4-gli-strumenti-usati)
5. [Come la Fase 1 prende la decisione: segnali forti e deboli](#5-come-la-fase-1-prende-la-decisione-segnali-forti-e-deboli)
6. [Il percorso di un singolo file, passo per passo](#6-il-percorso-di-un-singolo-file-passo-per-passo)
7. [I dataset: nome per nome](#7-i-dataset-nome-per-nome)
8. [La ground truth: chi decide qual è la risposta giusta](#8-la-ground-truth-chi-decide-qual-è-la-risposta-giusta)
9. [Gli script del progetto](#9-gli-script-del-progetto)
10. [I file prodotti in output](#10-i-file-prodotti-in-output)
11. [I risultati](#11-i-risultati)
12. [Cosa la Fase 1 non sa fare](#12-cosa-la-fase-1-non-sa-fare-limiti-dichiarati)
13. [Come rieseguire tutto da zero](#13-come-rieseguire-tutto-da-zero)

La mappa aggiornata dei dataset vive in **`E:\DATASET\INDICE.md`**, generata da
`scripts/make_dataset_index.py`.

---

## 1. Cosa fa la Fase 1 (e cosa non fa)

La Fase 1 riceve una cartella di file eseguibili e, per ognuno, risponde a **una sola domanda**:

> *Questo file è stato pacchettizzato, sì o no?*

Il risultato è una riga in un file CSV con una colonna `Is_Packed_Label` che vale `1` (sì) o `0`
(no), più tutte le informazioni che hanno portato a quella decisione.

**Non fa altro.** In particolare **non** spacchetta niente, **non** esegue i file, **non** dice se
il file è un malware. Spacchettare è compito della Fase 2, che ancora non è stata affrontata.

Perché serve un passo del genere: spacchettare un file costa minuti (emulazione, Ghidra, a volte
analisi manuale). Passare *tutti* i file alla Fase 2 sarebbe insostenibile. La Fase 1 è il filtro
che seleziona su cosa vale la pena spendere quel tempo, e costa **meno di mezzo secondo a file**.

L'analisi è **statica**: il file viene letto, mai eseguito. È una scelta di sicurezza (il dataset
contiene malware reali) oltre che di velocità.

---

## 2. Il vocabolario minimo

Se questi termini sono già noti, si può saltare al §3.

| termine | significato |
|---|---|
| **PE** | *Portable Executable*, il formato dei `.exe` e `.dll` di Windows. L'equivalente Linux è **ELF** |
| **Sezione** | un blocco interno del file con un nome e dei permessi: `.text` contiene il codice, `.data` i dati, `.rsrc` le risorse (icone, testi). I nomi sono convenzionali |
| **Entry point (EP)** | l'indirizzo della prima istruzione eseguita all'avvio. In un programma normale cade dentro `.text` |
| **Entropia** | misura del "disordine" dei byte, da 0 a 8. Codice compilato normale sta fra 5,5 e 6,5. Dati compressi o cifrati stanno sopra 7,0. È un indizio, non una prova: anche un'immagine PNG o una tabella crittografica hanno entropia alta |
| **IAT / import** | la lista delle funzioni di sistema che il programma userà (`CreateFile`, `malloc`, …). Un programma normale ne importa decine o centinaia |
| **Export** | le funzioni che un file *offre* ad altri. Tipico delle DLL |
| **Overlay** | dati appiccicati in fondo al file, fuori da ogni sezione |
| **Packer** | un programma che prende un eseguibile e ne produce un altro in cui il codice originale è compresso o cifrato, più un piccolo programma (**stub**) che al momento dell'avvio lo ricostruisce in memoria |
| **W+X** | una sezione scrivibile *ed* eseguibile allo stesso tempo. Inusuale nel software normale, normale in uno stub che si decomprime addosso |
| **.NET / managed** | programmi che non contengono codice macchina ma bytecode eseguito dal runtime .NET. Hanno una struttura diversa dagli eseguibili nativi |
| **CFG** | *Control Flow Guard*, una protezione anti-exploit che le toolchain Microsoft moderne attivano per default |

---

## 3. Che cosa significa "pacchettizzato": la definizione adottata

Questa è la scelta più importante del progetto, perché definisce cosa conta come risposta giusta.

> **Un eseguibile è `packed` quando presenta un'alterazione strutturale — compressione,
> cifratura, offuscamento, wrapping SFX/installer o protezione applicata dal vendor — che rende
> il codice originale non direttamente analizzabile tramite analisi statica.**
>
> La classificazione dipende **solo dalla struttura del file**, mai dal fatto che il software sia
> malevolo o legittimo, né dalle intenzioni di chi ha applicato la trasformazione.

### Perché questa definizione

Se un malware comprime il proprio codice per sfuggire all'analisi, e un installer lo comprime per
occupare meno spazio, **il file risultante è alterato allo stesso modo**. Una regola che volesse
distinguere i due casi dovrebbe conoscere l'*intenzione*, che non è scritta da nessuna parte nel
file.

Il vantaggio pratico è che la regola resta **uniforme**: nessuna eccezione ritagliata su un
produttore specifico. La stessa misura che intercetta Themida (protettore commerciale usato anche
dai malware) intercetta Warbird (protezione che Microsoft applica ai propri binari di licensing).

### Il prezzo, e come si paga

La classe `packed` diventa eterogenea: ci finiscono dentro cose molto diverse. Per questo i
risultati vanno **sempre riportati scomposti in tre sotto-classi**:

| sotto-classe | esempi | cosa ne farà la Fase 2 |
|---|---|---|
| **packer/protector di terze parti** | UPX, MPRESS, Themida, VMProtect, ASPack | emulazione o unpacker dedicato |
| **installer / SFX** | NSIS, Inno Setup, `wextract.exe` di Microsoft | **estrazione**, non emulazione |
| **protezione del vendor** | `sppsvc.exe`, `ClipUp.exe` (Warbird), PlayReady | fuori perimetro: rilevati e dichiarati, non spacchettati |

Senza questa scomposizione, su un insieme di software reale gli installer legittimi sarebbero
numericamente molto più dei packer, che sono l'oggetto del lavoro.

### Un caso che vale la pena conoscere

Quattro binari di licensing di Windows (`sppsvc.exe`, `SppExtComObj.Exe`, `ClipUp.exe`,
`GenValObj.exe`) hanno la sezione `.text` con entropia fra 7,19 e 7,70, contro 6,28 di
`notepad.exe` sulla stessa macchina. `sppsvc.exe` ha quattro sezioni chiamate `?g_Encry…`, un nome
che nessun compilatore produce. Sono protetti con **Warbird**, una tecnologia interna Microsoft.

**Detect It Easy non li nomina.** Su tutti e quattro `Die_Packer_Match` vale `NO` e il nome del
packer è vuoto: nessuna firma li identifica. Il verdetto è `weak_only` e poggia su **tre** segnali
deboli, di cui due strutturali (entropia di `.text`, entry point in sezione ad alta entropia oppure
nomi di sezione non standard) e uno dato dall'**euristica generica** di DIE (`packer: Generic`,
`protection: Generic`), che dichiara un'anomalia senza identificarla.

Misurato: togliendo l'euristica di DIE dai segnali deboli questi quattro file scendono a 2 e passano
sotto soglia. Sono **l'unico** punto dell'intero dataset in cui quell'euristica è determinante — sui
restanti 374 campioni `packed` non cambia nessun verdetto (§24.5 del log di sessione). Resta la
dimostrazione che le firme non bastano, perché nessuna li nomina; non è corretto dire che il
rilevamento sia *interamente* strutturale.

---

## 4. Gli strumenti usati

La Fase 1 combina quattro strumenti. Nessuno di loro, da solo, sarebbe sufficiente.

### LIEF — il lettore di formato

Libreria Python che apre un PE o un ELF e ne espone la struttura: sezioni, nomi, permessi,
dimensioni, entry point, import, export, overlay. È la fonte di tutte le misure **strutturali**.

Non "riconosce" niente: fornisce i numeri su cui la logica del progetto ragiona.

### Detect It Easy (DIE) — il riconoscitore a firme

Programma esterno con un database di firme di packer e compilatori. Viene chiamato da riga di
comando:

```
diec.exe -j -u <file>
```

- `-j` produce output JSON, così il risultato si legge in modo affidabile;
- `-u` attiva le euristiche.

DIE restituisce risultati di tre tipi, trattati con peso diverso:

1. **packer/protector/cryptor/cruncher con nome** (`"packer: UPX"`) → prova forte;
2. **installer/SFX** (`"installer: Nullsoft Scriptable Install System"`) → prova forte, ma
   registrata a parte perché la Fase 2 dovrà *estrarre*, non emulare;
3. **euristiche** (`~packer`, `~protection`) → indizio debole: DIE le assegna anche a file
   normalissimi.

> **Dettaglio che è costato tempo:** l'opzione `-d` (deep scan) era stata provata e poi rimossa.
> Su 46 file non aggiungeva nemmeno un riconoscimento in più sui file packed, ma faceva dire
> *"protector: VMProtect"* a 9 binari perfettamente puliti. Un'opzione che aggiunge rumore e
> nessuna informazione va tolta.

### YARA — le regole di pattern

Motore di regole che cerca sequenze di byte note. Si usa il ruleset pubblico **YARA-Forge**,
precompilato in `config/yara_forge_compiled.yrc` (48 MB) per non ricompilarlo a ogni avvio.

Anche qui due pesi diversi:

- regola che nomina un packer (`Packer_UPX`) → prova forte;
- regola generica (`Anti_Debug_API`) → **solo informativa, non conta**. Motivo misurato: scatta
  sul 45 % dei file puliti e solo sull'1 % di quelli packed. È un segnale che punta nella
  direzione sbagliata, quindi viene registrato ma non usato per decidere.

### capa — disattivato per default, e perché

capa (di Mandiant/FLARE) analizza le capacità di un binario. Su file packed stampa presto un
banner *"This sample appears to be packed"*.

È stato **disattivato** (`CAPA_MODE = "off"`) dopo una misura precisa su 189 file: consumava
**1.539 secondi su 1.599 complessivi (il 96 %)**, produceva **zero** prove forti e non cambiava
**nessun** verdetto.

La causa è strutturale, non risolvibile con del tuning: capa scrive il nome del packer nel JSON
solo **alla fine** dell'analisi, mentre il banner compare **all'inizio**. Se si ferma il processo
al banner (per risparmiare tempo) si perde il nome; se si lascia finire, si pagano minuti a file.

Resta disponibile con `--capa-mode full` per un confronto fra strumenti su un piccolo
sottoinsieme, e ogni riga del CSV registra in quale modalità è stata prodotta.

---

## 5. Come la Fase 1 prende la decisione: segnali forti e deboli

### La regola, in due righe

```
se esiste almeno UN segnale FORTE          → packed
altrimenti, se ci sono ALMENO 3 DEBOLI     → packed
altrimenti                                  → pulito
```

### I segnali forti (uno solo basta)

| segnale | cosa significa |
|---|---|
| **nome di sezione tipico di un packer** | il file ha sezioni `UPX0`, `.vmp0`, `.themida`… Non è probabilistico: è quel packer |
| **YARA con nome di packer** | una regola che identifica un packer specifico ha fatto match |
| **DIE nomina un packer/protector/installer** | idem, da un altro strumento indipendente |
| **capa nomina un packer** | idem (solo se capa è attivo) |
| **IAT minimale sospetta, con compressione osservata** | il file importa *solo* `LoadLibrary` + `GetProcAddress` — il minimo indispensabile a uno stub per ricostruire a mano tutto il resto — **e** c'è entropia alta o sezioni anomale. La corroborazione serve perché quel pattern di import, da solo, è anche la firma della **risoluzione dinamica degli import**, che è evasione e non compressione (vedi §12) |
| **stub strutturale** | l'entry point è in una sezione ad entropia ≥ 7,0 **e** (quella sezione è W+X **oppure** un'altra sezione eseguibile è vuota o sproporzionata). È il layout tipico di uno stub che si decomprime |
| **stub strutturale, ripiego .NET** | un assembly .NET ha `AddressOfEntryPoint` = 0 **per costruzione** (l'EP vero sta nell'header CLR), quindi non ha una sezione dell'EP e il segnale precedente non può scattare, quali che siano le sue sezioni. Dove `Has_CLR_Header` è `SI` e `EP_Section` è `UNKNOWN`, si cerca la stessa proprietà senza l'ancoraggio all'EP: una sezione eseguibile a entropia ≥ 7,0 **e un'altra** sezione eseguibile vuota o sproporzionata |

L'ultimo è l'unico che funziona **senza conoscere il packer**, ed è quello che ha salvato i casi
più difficili (vedi §11).

### I segnali deboli (ne servono 3 concordanti)

Entropia di una sezione ≥ 7,2 · sezioni di dimensione anomala · entry point in una sezione non
standard · entry point in sezione ad alta entropia · entry point in sezione W+X · entry point
fuori da ogni sezione · overlay grande e ad alta entropia · nomi di sezione non standard · numero
di import basso (< 20) · euristica DIE · sezioni stripped · header non parsabile.

### Perché due livelli e non un punteggio a percentuali

La versione iniziale sommava punti percentuali (entropia +20, sezioni anomale +15, …) con soglia
al 70 %. È stata abbandonata per tre ragioni:

1. **i pesi erano inventati**, non misurati. Misurando dopo, si è visto che l'entropia distingue
   packed da puliti nell'85 % contro 0 %, mentre YARA generico distingue *al contrario*. Un
   sistema additivo li sommava nella stessa valuta;
2. **il modello additivo è falso rispetto al fenomeno**: `UPX0` in una sezione *è* UPX, non "20
   punti su 100 di probabilità di essere UPX";
3. **non era tarabile**: toccare un peso spostava in modo imprevedibile tutte le altre decisioni.
   Con due livelli il parametro da regolare è **uno solo**, `WEAK_SIGNALS_REQUIRED`, e il suo
   effetto si misura.

Lo score percentuale esiste ancora nel CSV (`Packing_Score_%`) ma è **solo leggibilità**: i due
rami producono per costruzione valori sopra o sotto la soglia. Non è una probabilità.

### La qualità della prova

Oltre a sì/no, ogni file riceve una colonna `Packing_Evidence` che dice **quanto è solida** la
decisione:

| valore | significato | cosa ne farà la Fase 2 |
|---|---|---|
| `named` | il packer è stato riconosciuto **per nome** | può usare l'unpacker dedicato |
| `structural` | è packed, ma nessuno strumento sa dire quale | deve emulare |
| `weak_only` | 3 o più indizi deboli concordanti, nessuna prova forte | caso incerto, spenderci poco tempo |
| `none` | pulito | non passa alla Fase 2 |

---

## 6. Il percorso di un singolo file, passo per passo

L'ordine dei passi non è casuale: è dal più economico al più costoso, così i file che si possono
scartare subito non consumano strumenti.

**Passo 1 — Si leggono 4 byte.**
Se non iniziano con `MZ` (PE) o `ELF`, non è un eseguibile: `Parse_Status = not_executable`,
score 0, fine. Sembra banale, ma sul set di test il 19 % dei file con estensione `.exe` erano
**aggiornamenti differenziali di Windows Update** con magic `DCS`, e prima venivano passati a
YARA prima di essere scartati.

**Passo 2 — YARA.**
Si cercano le firme sul file grezzo. Funziona anche su file con header corrotto, per questo viene
prima del parsing.

**Passo 3 — LIEF apre il file.**
Se fallisce, **il file non viene scartato**: si classifica lo stesso con quello che dicono YARA e
DIE. (Prima un fallimento di parsing faceva sparire il file dal report in silenzio: succedeva
proprio sui file più offuscati, cioè quelli che interessano di più.)

**Passo 4 — Si leggono sottosistema ed export.**
Servono dopo, come *eccezioni*: un driver o un boot loader importa zero funzioni **per
costruzione**, e una DLL che esporta centinaia di simboli ha per forza il codice intatto.

**Passo 5 — DIE.**
Costa 1–4 secondi. Restituisce i nomi dei packer riconosciuti.

**Passo 6 — Si scorrono le sezioni.**
Per ognuna si calcolano entropia, permessi, rapporto fra dimensione dichiarata e reale, e si
verifica se il nome è standard. Si individua in quale sezione cade l'entry point.

> Due raffinamenti importanti, entrambi nati da falsi positivi reali:
> - la sezione `.rsrc` è **esclusa** dal calcolo dell'entropia che alimenta il segnale. Le risorse
>   contengono PNG e tabelle di testo, già compressi per natura. Un packer comprime il *codice*,
>   non le icone;
> - le "dimensioni anomale" si valutano **solo sulle sezioni eseguibili**: una `.bss` con
>   dimensione dichiarata molto maggiore di quella su disco è del tutto normale.

**Passo 7 — Import, IAT, overlay, .NET.**
Si conta quante funzioni importa, se importa solo il minimo sospetto, se ha un overlay grande e
compresso, e se è un assembly .NET.

**Passo 8 — Si valutano i segnali e si decide.**
Si costruiscono le tre liste (forti, deboli, informativi), si applica la regola del §5, si scrive
la riga nel CSV.

---

## 7. I dataset: nome per nome

Tutti i dataset vivono sotto un'unica radice, **`E:\DATASET\`**, organizzata su due livelli:

- **primo livello = affidabilità della label** (certa / materia prima / non etichettata);
- **secondo livello = oracolo**, cioè chi garantisce quella label.

Il principio è che **la cartella corrisponda all'oracolo, non alla label binaria**. Unire in
un'unica cartella `CLEAN` i file di System32 e le estensioni PyPI farebbe perdere l'informazione
che li rende difendibili: i primi sono `clean` perché firmati Microsoft, i secondi perché sono
wheel ufficiali da PyPI. Sono due garanzie diverse, con affidabilità diversa.

Per questo il primo livello **non** si chiama `PACKED` / `CLEAN`: quattro sorgenti contengono
label miste (System32 ha 7 file packed — Warbird, SFX, PlayReady), e un nome per label sarebbe
falso.

```
E:\DATASET\
├── 01_LABEL_CERTA\          oracolo esterno verificabile
│   ├── matrice_packed\      353  packer eseguito da noi
│   ├── system32\           1990  firma Authenticode Microsoft
│   ├── goodware_non_ms\    1042  distribuzioni ufficiali non-Microsoft
│   ├── pypi\                341  wheel ufficiali PyPI (calib 171 + test 170)
│   ├── pma_book\             48  dichiarazione del libro PMA
│   └── gorust\               16  compilati in proprio
├── 02_MATERIA_PRIMA\
│   └── masters\              56  originali puliti per il packing, mai valutati
├── 03_NON_ETICHETTATI\
│   ├── flare_vm\            800  hard set FLARE VM
│   ├── wild_malwarebazaar\  181  malware reali, label proposte dai tag
│   ├── legacy_misto\        125  ex TEST_BIN_PULITI
│   ├── malware_reali\        16  ex TEST_BIN_MALWARE
│   └── autopacked_vecchi\    15  ex TEST_SAMPLES
└── 04_VALIDAZIONE_ESTERNA\  label di terzi, tabella di metriche SEPARATA
    ├── v1_misto\            270  campione cieco da packing-box/dataset-packed-pe
    └── v1_chiave.csv             chiave di risposta, indicizzata per SHA-256
```

**Tutte** le cartelle di `01_LABEL_CERTA` hanno una label per ogni campione, quindi concorrono
interamente alle metriche. Nessun dataset vive più fuori dalla radice.

> **`E:\DATASET\INDICE.md` è generato automaticamente** da `scripts/make_dataset_index.py` e
> riporta, per ogni cartella: campioni, label, oracolo, e se il gruppo concorre alle metriche.
> È la mappa aggiornata: un indice scritto a mano va fuori sincrono al primo file aggiunto.

---

### `01_LABEL_CERTA` — i dataset che producono le metriche

#### `matrice_packed` — 353 file + `manifest.csv`
**Il dataset più importante del progetto.** Generato applicando 6 packer ai master, più due
combinazioni a due strati. La label **non è l'opinione di uno strumento: è il fatto di aver
eseguito il packer**. È l'unica certezza al 100 % disponibile.

| layer | campioni |
|---|---|
| Themida | 53 |
| NSIS | 53 |
| Inno Setup | 53 |
| MPRESS | 50 |
| VMProtect | 48 |
| UPX | 44 |
| UPX + NSIS | 44 |
| UPX + MPRESS | 8 |

Ogni file si chiama `<arch>_<toolchain>_<hash>_<packer>.exe`, e il manifest conserva
`origin_sha256`, l'hash dell'originale pulito da cui viene. Questo permette il confronto
**prima/dopo sullo stesso identico binario**.

Scelta di metodo: ogni combinazione parte **sempre dal master intatto** e produce un file nuovo.
L'alternativa — impacchettare "sul posto" e poi spacchettare per tornare indietro — è stata
scartata perché avrebbe fatto dipendere la correttezza del dataset dalla correttezza di ciò che il
lavoro deve misurare.

#### `system32` — 1.990 file
Eseguibili e DLL da `System32` e `SysWOW64`. Etichettati `clean` perché hanno una **firma
Authenticode Microsoft valida**: l'oracolo è la firma digitale, non un giudizio. 939 `.exe` e
1.051 `.dll`, 1.258 a 64 bit e 732 a 32 bit — il 32 bit è rappresentato di proposito, altrimenti
l'architettura diventerebbe un fattore confondente (molti packer classici esistono solo a 32 bit).

Contiene **7 file etichettati `packed`**: i quattro binari Warbird, i due `wextract.exe` (SFX
Microsoft) e `PlayReady`. Sono veri positivi secondo la definizione del §3, non falsi allarmi.

#### `pypi` — 341 file (`calib\` 171 + `test\` 170)
Estensioni native Python (`.pyd`) prese dal `.venv` del progetto. Sono la classe negativa
**non-Microsoft**: compilate da terzi, con toolchain diverse (Cython, mypyc, Meson/Fortran).

Servono perché `system32` è tutto della stessa natura, e le eccezioni ai falsi positivi (sezioni
kernel, esclusione di `.rsrc`) erano state scritte guardando proprio quello.

Divise in due metà **per pacchetto**, non per file: i `.pyd` dello stesso pacchetto condividono
toolchain e opzioni di build, quindi distribuirli a caso renderebbe le due metà non indipendenti.

Oracolo: **provenienza** — wheel ufficiali da PyPI, installate via `pip` dal `requirements.txt`.
Da dichiarare come label di provenienza, non come verifica strutturale.

#### `pma_book` — 48 file
Campioni di *Practical Malware Analysis* (ex `TEST_BIN_PMA`, che stava nel repository perché
versionata in git; rimossa dall'indice git il 27/09 e spostata qui).

Le label vengono **dal libro**: 6 `packed` (UPX, Upack, FSG, PECompact, ASPack), 42 confermati non
packed. Oracolo di terzi, indipendente da qualunque strumento della pipeline.

I campioni dei capitoli 15-17 (anti-disassembly, anti-debugging, anti-VM) sono un **controllo
negativo** prezioso: il libro conferma che non sono pacchettizzati, e la Fase 1 li classifica tutti
e 8 puliti. Risponde alla domanda *"il rilevatore riconosce il packing o riconosce che il file è
difficile da analizzare?"*, su campioni scelti da terzi.

#### `gorust` — 16 file + `manifest.csv`
8 binari Go e 8 Rust compilati in proprio, con profili di build deliberatamente diversi:

| Go (8) | Rust (8) |
|---|---|
| 2 × build default | 2 × `debug` |
| 2 × stripped `-ldflags "-s -w"` | 2 × `release` |
| 2 × statico `CGO_ENABLED=0` | 2 × `release` + `opt-level=z` + `lto` |
| 2 × con dipendenze reali (HTTP/JSON/crypto) | 2 × `release` + `panic=abort` |

I sorgenti stanno in `Unpacking\Packing\Build_Samples\`, con `build_go.ps1` e `build_rust.ps1`.
Dimensioni da 344 KB a 9,7 MB.

**È l'oracolo più forte del progetto**: non una firma di terzi, ma il fatto di averli compilati,
con il comando di build registrato in `config/gorust_labels.json`. I 2 campioni Go con `cgo`
(`g7`, `g8`) non sono stati prodotti: richiedono un compilatore C, assente sulla macchina.

Perché contano: un binario Go statico ha `.text` enorme, pochi import e sezioni atipiche — fa
scattare **tre segnali deboli insieme**, cioè esattamente la soglia. È il test più severo
disponibile (esito nel §11).

---

### `02_MATERIA_PRIMA` — né test set, né campioni packed

#### `masters` — 56 file

⚠️ **Attenzione a non confondersi: i master sono file PULITI.** Sono gli eseguibili *di partenza*
che vengono dati in pasto ai packer per produrre `matrice_packed`. Non sono un dataset di test:
nessuna metrica si calcola su di loro. Sono la materia prima.

Vengono copiati da `03_NON_ETICHETTATI\legacy_misto` (toolchain MinGW) e da
`01_LABEL_CERTA\system32` (toolchain Microsoft).

Criteri di ammissione, tutti verificati leggendo il binario e non dedotti:

1. **è un PE con sottosistema GUI o console** — driver, boot loader e applicazioni EFI vengono
   rifiutati dai packer user-mode (`unsupported subsystem`);
2. **non ha Control Flow Guard** — UPX rifiuta i file con CFG (`GUARD_CF enabled PE files are not
   supported`). È il vincolo che ha determinato la composizione del set: solo il 5 % di System32 è
   impacchettabile con UPX, contro il 94 % dei binari MinGW. Di conseguenza i master sono in
   maggioranza di toolchain più datate — è una restrizione **imposta dallo strumento**, da
   dichiarare come tale;
3. **non è già pacchettizzato.**

Il terzo criterio sembra un controsenso ("sono puliti, ovvio che non siano packed") ma è il più
importante dei tre.

**Perché un master deve essere pulito.** Se il file di partenza è già compresso, il campione
prodotto porta una label sbagliata: `x86_…_Themida.exe` dichiara `layers = Themida` quando il
contenuto reale è `UPX + Themida`. La label binaria `packed` resta corretta, ma **`layers` è il
dato centrale di un lavoro sul multilayer packing**. In più `origin_sha256` punterebbe a un binario
non pulito, e salterebbe il confronto prima/dopo.

**Perché il criterio è stato aggiunto dopo.** Nella prima versione dello script la selezione
controllava formato, sottosistema, dimensione e CFG, ma **non se il candidato fosse già
pacchettizzato**. `legacy_misto` ne conteneva alcuni, e tre sono finiti fra i master:

| master | come è stato scoperto | esito |
|---|---|---|
| `NBHextract_2E1ADF…` | sezioni `UPX0`/`UPX1` | intercettato dal filtro; 4 campioni cancellati |
| `RAIU_BEFA0244…` | sezioni `UPX0`/`UPX1` | intercettato dal filtro; 4 campioni cancellati |
| `UHARC04_A45C6F7D…` | **sezioni senza nome**: il filtro sui nomi non lo vede | trovato dalla Fase 1 (DIE + IAT minimale + stub strutturale); 4 campioni cancellati |

Il terzo è il caso interessante: è UPX con i **nomi di sezione azzerati**, la variante che il libro
PMA usa nell'esercizio `Lab18-02`. Il filtro basato sui nomi non lo intercetta — la Fase 1 sì, con
tre prove forti indipendenti. Il filtro robusto non è il nome della sezione ma la ground truth:
*se un candidato è già etichettato `packed`, si scarta*. Li avrebbe presi tutti e tre.

---

### `03_NON_ETICHETTATI` — analisi qualitativa, mai metriche

#### `flare_vm` — 800 file
Campione casuale da un'immagine **FLARE VM** (distribuzione di tool per il reverse engineering).

⚠️ **Non è una classe negativa** e non va usata come tale. Questi file non sono malware, ma FLARE
VM contiene i packer stessi, gli unpacker, editor PE e strumenti commerciali protetti: è una delle
raccolte più dense di packing che esistano. Serve come **hard set**, cioè materiale difficile su
cui fare analisi qualitativa.

> Questo errore è già stato commesso una volta: `legacy_misto` (allora `TEST_BIN_PULITI`) conteneva
> materiale FLARE e campioni PMA, e 15 file che sembravano falsi positivi erano in realtà **veri
> positivi**.

#### `wild_malwarebazaar` — 181 file
Malware reali da **MalwareBazaar**, in sottocartelle per tag del packer dichiarato: `vmprotect` 60,
`upx` 45, `themida` 13, `aspack` 3, `pecompact` 0, più `_senza_tag` 60.

Le label qui sono **proposte, non certe**, per due motivi da dichiarare:
- **circolarità**: molti tag nascono da strumenti della stessa famiglia di DIE e YARA, che la
  Fase 1 usa come fonti di segnale forte; si rischia di misurare l'accordo fra due istanze dello
  stesso strumento;
- **distorsione di selezione**: un file è taggato `fsg` perché *qualcuno l'ha riconosciuto*; i
  campioni FSG non riconosciuti non sono taggati e non entrano mai nel campione, gonfiando il
  recall.

I 60 file `_senza_tag` servono a **misurare** quanto il campionamento per tag sta nascondendo.

> Attenzione al tag `upx-dec`: significa **già decompresso**, non packed.

#### `legacy_misto` — 125 file
Ex **`TEST_BIN_PULITI`**, rinominata perché il nome mentiva: **non è un set di file puliti.** È un
insieme stratificato nel tempo — binari MinGW, campioni PMA (malware), materiale FLARE, file già
packati. Oggi serve solo come sorgente di master MinGW.

È la cartella che ha generato i 15 finti falsi positivi e i 3 master contaminati.

#### `malware_reali` — 16 file
Ex `TEST_BIN_MALWARE`: malware reali con ground truth parziale, usati nei primi test della cascata.

#### `autopacked_vecchi` — 15 file
Ex `TEST_SAMPLES`: output della **prima** versione di `pack_samples.py`, quella non deterministica e
senza seed. Solo 8 dei 15 hanno una label, per questo sta qui e non in `01_LABEL_CERTA`: è materiale
storico, conservato perché 2 campioni sono `packed` certi.

---

### `04_VALIDAZIONE_ESTERNA` — banco di prova indipendente

#### `v1_misto` — 270 campioni + `v1_chiave.csv`

Campione cieco estratto da **`packing-box/dataset-packed-pe`**, dataset pubblico di 3.664 campioni
e 25 famiglie di packer (fork sanificato di `chesvectain/PackingData`).

Serve a rispondere a un'obiezione che gli altri dataset non possono soddisfare: **quelli li abbiamo
costruiti noi**. Qui né i campioni né le label vengono da noi.

| parte | campioni | |
|---|---|---|
| packed | **200** | 8 per ciascuna delle 25 famiglie |
| not-packed | 60 | goodware: 7-Zip, Sysinternals, NirSoft, tool .NET |
| `outliers/not-packed` | 10 | tutti — sono i casi che gli autori stessi dichiarano ambigui |

**Stratificato e non casuale**, perché l'oggetto della misura è il recall *per famiglia*: un
campionamento casuale avrebbe lasciato fuori qualche famiglia. **Nomi neutri** (`v1_0001.exe` …) e
ordine mescolato, perché una cartella chiamata `Themida` non è un test cieco. **Chiave separata**,
indicizzata per SHA-256, consultata solo dopo il run.

**Zero sovrapposizione**: verificato sugli hash di tutti e 3.664 i campioni del dataset, nessuno era
già nel corpus del progetto.

> ⚠️ **Le sue label non stanno in `ground_truth.json`** e non entrano nella matrice principale.
> Sono di terzi, con qualità diversa dai nostri oracoli: si misurano con
> `scripts/validate_external.py`, che scrive una tabella a parte. Mescolarle abbasserebbe la
> qualità media del manifest senza che si veda.

---

## 8. La ground truth: chi decide qual è la risposta giusta

Senza una risposta di riferimento non esiste la nozione di "errore". Il file
`Pipeline_Reports/ground_truth.json` contiene, **indicizzato per SHA-256 del contenuto**, la label
di ogni campione e — soprattutto — **da dove viene quella label**.

Stato attuale: **3.924 voci** → 3.435 `clean`, 378 `packed`, 111 `unknown`.

### Perché la chiave è l'hash e non il nome

Perché il nome mente. Nel progetto esistevano `TEST_SAMPLES/awk_6DAD….exe` (268.800 byte) e
`TEST_BIN_PULITI/awk_6DAD….exe` (627.466 byte): stesso nome, contenuto diverso. Con lo storico
basato sul nome si coprivano a vicenda e 15 file non venivano mai analizzati.

### Gli oracoli, e perché sono indipendenti

Un oracolo è valido solo se **non guarda le stesse cose che il rilevatore sta valutando**.

| oracolo | come funziona | quanti |
|---|---|---|
| **Compilazione in proprio** | i binari Go/Rust li abbiamo compilati noi, comando registrato | 16 `clean` |
| **`pack_samples.py`** | abbiamo eseguito noi il packer | 353 `packed` |
| **`upx -t`** | è UPX stesso che verifica di poter decomprimere il file | 10 `packed` |
| **Firma Authenticode Microsoft** | il file è firmato digitalmente da Microsoft | 1.994 `clean` |
| **Wheel ufficiali PyPI** | provenienza: installate via `pip` dal `requirements.txt` | 341 `clean` |
| **Libro PMA** | l'appendice del libro dichiara la natura di ogni campione | 48 |
| **Verifica manuale documentata** | Warbird, SFX, PlayReady: analizzati a mano con motivazione scritta | 13 |

I primi due sono **certezze**: sappiamo cosa è stato fatto al file perché l'abbiamo fatto noi.
Gli altri sono garanzie di terzi o di provenienza, e vanno citati per quello che sono — in
particolare le wheel PyPI sono una label di **provenienza**, non una verifica strutturale.

**Regola non negoziabile:** una scansione automatica può creare **solo** voci `unknown`. "Non è
packed" è un'affermazione che richiede una verifica, non l'assenza di segnalazioni. È esattamente
la regola che ha evitato di contare come falsi positivi i 15 campioni FLARE/PMA.

I 113 `unknown` non sono un difetto: sono file per cui nessun oracolo si è pronunciato, e vengono
correttamente **esclusi dal calcolo delle metriche**.

---

## 9. Gli script del progetto

Tutti in `Unpacking/Packing/scripts/`.

### `parameters_info.py` — il punto di ingresso

Si lancia questo, non gli altri. Legge gli argomenti, chiama la Fase 1 e, se richiesto, la Fase 2.

```bash
python scripts/parameters_info.py --dir "E:/DATASET/01_LABEL_CERTA/matrice_packed" --phase1-only
```

| opzione | cosa fa |
|---|---|
| `--dir <cartella>` | cartella da analizzare (senza, apre una finestra di selezione) |
| `--phase1-only` | si ferma dopo la Fase 1. **È l'opzione che si usa sempre, oggi** |
| `--reanalyze` | archivia il CSV esistente e rianalizza tutto. Serve dopo aver cambiato la logica |
| `--capa-mode full` | riattiva capa (lento) |
| `--yes` | non chiede conferma prima della Fase 2 |

### `header_elf_lief.py` — il cuore della Fase 1

Fa tutto il lavoro descritto nel §6. Qui vivono anche le costanti che definiscono il
comportamento:

```python
WEAK_SIGNALS_REQUIRED = 3     # quanti segnali deboli servono
EP_ENTROPY_THRESHOLD  = 7.0   # entropia oltre cui la sezione è "compressa"
EXPORTS_REAL_API      = 10    # export oltre cui il codice è certamente intatto
ENTROPY_EXCLUDED_SECTIONS = (".rsrc",)
CAPA_MODE             = "off"
```

#### Il codice che calcola le feature dei segnali chiave

Le costanti qui sopra sono i parametri dichiarati. Le soglie che seguono vivono invece **come
letterali dentro `_packing_signals()`** e non hanno un nome: sono documentate qui perché sono
decisionali esattamente come le altre, e perché il §5 le cita solo in parte.

**L'entropia.** Shannon su base 2, sui byte grezzi, scala 0–8.

```python
def shannon_entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())
```

Viene applicata tre volte con significati diversi: per sezione (alimenta
`Max_Entropy_No_Rsrc`, che **esclude `.rsrc`**), alla sezione dell'entry point
(`EP_Section_Entropy`) e all'overlay (`Overlay_Entropy`, su un massimo di 4 MB letti).

**Le sezioni di dimensione anomala.** Il predicato guarda **solo le sezioni eseguibili**, perché
una `.bss` con dimensione virtuale molto maggiore di quella su disco è normale:

```python
if _section_is_executable(section):
    if raw_size == 0 and virtual_size > 0:
        results["Anomalous_Size_Sections"].append(sec_name)     # svuotata
    elif raw_size > 0 and (virtual_size > raw_size * 2.5):
        results["Anomalous_Size_Sections"].append(sec_name)     # sproporzionata
```

Il rapporto **2,5** è la soglia di sproporzione per il PE (per i segmenti `PT_LOAD` degli ELF è
2,0). È lo spazio riservato in cui lo stub scriverà il codice originale.

**Lo stub strutturale**, il segnale forte che funziona senza conoscere il packer:

```python
ep_high      = lief_ok and ep_entropy >= EP_ENTROPY_THRESHOLD      # 7.0
ep_anomalous = results["EP_Section_WX"] == "SI" or len(anomalous) > 0
structural   = ep_high and ep_anomalous
```

E il suo ripiego per gli assembly .NET, che cerca la stessa proprietà senza ancorarla all'EP. Le
due sezioni devono essere **distinte**, altrimenti si conterebbe due volte la stessa evidenza:

```python
exec_high   = set(results["Exec_High_Entropy_Sections"]) - set(anomalous)
managed_stub = (lief_ok and not structural
                and results["Has_CLR_Header"] == "SI"
                and results["EP_Section"] == "UNKNOWN"
                and bool(exec_high) and bool(anomalous))
```

**La corroborazione dell'IAT minimale.** È ciò che declassa il segnale da forte a debole quando
non c'è compressione osservata:

```python
iat_corroborata = results["Max_Entropy_No_Rsrc"] >= 7.2 or len(anomalous) > 0
```

**I tre segnali deboli con una soglia numerica.** Il valore **7,2** è un letterale ripetuto in
quattro punti del file e non ha una costante dedicata:

```python
if results["Max_Entropy_No_Rsrc"] >= 7.2:
    weak.append("entropia sezione >= 7.2")

if results["Overlay_Size"] >= max(65536, 0.5 * fsize) and results["Overlay_Entropy"] >= 7.2:
    weak.append("overlay grande ad alta entropia")

if lief_ok and results["Is_DotNet"] != "SI" and results["Total_Imports"] < 20 ...:
    weak.append("numero import basso (<20)")
```

Il criterio dell'overlay è quello meno ovvio e il §5 non lo riporta: servono **tutte e tre** le
condizioni — almeno 64 KB, almeno metà del file, ed entropia ≥ 7,2. Un overlay piccolo o un
overlay grande ma non compresso non producono il segnale.

| soglia | valore | dove vive | documentata nel §5 |
|---|---|---|---|
| segnali deboli richiesti | 3 | `WEAK_SIGNALS_REQUIRED` | sì |
| entropia della sezione dell'EP (forte) | 7,0 | `EP_ENTROPY_THRESHOLD` | sì |
| entropia di sezione (debole) | 7,2 | letterale, 4 occorrenze | sì, senza il contesto |
| corroborazione dell'IAT minimale | 7,2 **oppure** ≥ 1 sezione anomala | letterale | sì, in prosa |
| sproporzione virtuale/raw, sezioni eseguibili | 2,5 (PE) · 2,0 (ELF `PT_LOAD`) | letterale | **no** |
| overlay: dimensione | ≥ 64 KB **e** ≥ 50 % del file | letterale | **no** |
| overlay: entropia | ≥ 7,2 | letterale | **no** |
| import bassi | < 20, se non .NET | letterale | sì |
| export che provano codice intatto | 10 | `EXPORTS_REAL_API` | sì |

> Da sistemare quando la Fase 1 verrà riaperta, non adesso: il 7,2 va promosso a costante con un
> nome, come il 7,0. Oggi cambiarlo richiede quattro modifiche coordinate, ed è il tipo di numero
> magico che una revisione trova.

### `pipeline_utils.py` — le fondamenta condivise

Non fa analisi. Fornisce le quattro cose che servono a tutti gli altri:
- **un solo logger** e un solo `pipeline.log`, così una run intera si ricostruisce da un file;
- **l'hash SHA-256** usato come chiave ovunque;
- **lo stato di ripresa** (`pipeline_state.json`), per riprendere una run interrotta;
- **`run_external()`**, che esegue i programmi esterni con timeout, uccisione dell'intero albero
  di processi e registrazione della diagnostica.

> Una lezione imparata a caro prezzo: il salvataggio dello stato usava `os.replace()`, che su
> Windows fallisce se un antivirus tiene aperto il file. L'eccezione **fermava l'analisi al file
> 945 su 1.987, con codice di uscita 0 e nessun avviso**. Ora il salvataggio non solleva mai
> eccezioni e c'è un controllo esplicito che stampa `BATCH INCOMPLETO`.

### `pack_samples.py` — il generatore di campioni packed

Seleziona i master e ci applica i packer, producendo `E:\DATASET_LABEL_CERTA\matrice_packed`.

```bash
python scripts/pack_samples.py --masters 2    # prova su 2 master
python scripts/pack_samples.py                # matrice completa
```

È **deterministico**: con lo stesso seed (`20260923`) seleziona gli stessi master. Scrive il
manifest in modo incrementale, così un'interruzione non perde il lavoro fatto, e salta i file già
presenti.

Packer usati, tutti verificati eseguendoli da riga di comando:

| packer | dove | nota |
|---|---|---|
| UPX 5.1.1 | `E:\Tools\upx\` | compressore classico |
| MPRESS 2.19 | `E:\Tools\mpress\` | lavora sul posto, quindi si packa la copia |
| VMProtect 3.10.6 | `E:\Tools\VMProtect Demo\` | versione console |
| Themida 3.2.4.34 | `E:\Tools\` | richiede un file di progetto `.tmd` per architettura |
| NSIS | `C:\Program Files (x86)\NSIS\` | installer silenzioso che esegue il payload |
| Inno Setup 6 | `E:\Tools\Inno Setup 6\` | installer |

**PECompact e ASPack sono esclusi** perché aprono una finestra grafica anche senza argomenti: non
automatizzabili. **FSG, Petite, kkrunchy, Enigma** sono esclusi perché abbandonati e reperibili
solo da archivi non ufficiali — oltre al rischio, non se ne potrebbe **citare la provenienza**.

### `build_ground_truth.py` — costruisce le risposte di riferimento

```bash
python scripts/build_ground_truth.py --scan "E:/DATASET/03_NON_ETICHETTATI/wild_malwarebazaar" --dataset wild
python scripts/build_ground_truth.py --import-packing-matrix                   # label certe
python scripts/build_ground_truth.py --import-authenticode "E:/DATASET/01_LABEL_CERTA/system32"
python scripts/build_ground_truth.py --import-upx-test "E:/DATASET/03_NON_ETICHETTATI/wild_malwarebazaar/upx"
python scripts/build_ground_truth.py --stats
```

`--import-packing-matrix` legge `E:\DATASET_LABEL_CERTA\matrice_packed\manifest.csv` e, per ogni riga, **ricalcola lo
SHA-256 del file su disco e lo confronta con quello dichiarato**. Se non coincidono il campione
viene scartato: un file modificato dopo la generazione non è più coperto dalla sua label.

### `preflight.py` — verifica che l'ambiente possa eseguire la Fase 1

```bash
python scripts/preflight.py --packer
```

Controlla interprete, pacchetti Python (compresa la **major di LIEF**, che è il difetto storico più
frequente), strumenti esterni, regole YARA e cartelle dei dati. Per ogni cosa che manca dice **il
file e la costante da correggere**, invece di lasciare che il batch fallisca a metà con un
messaggio oscuro. Esce con codice 0 se la Fase 1 è eseguibile.

### `validate_external.py` — misura contro un set esterno

```bash
python scripts/validate_external.py
```

Incrocia il CSV della Fase 1 con una **chiave di risposta esterna** (un CSV a parte, non
`ground_truth.json`) e produce una tabella di metriche separata, più il recall per famiglia.

Scompone i disaccordi per categoria, perché la distinzione che conta è fra disaccordi **sparsi** —
che indicano un difetto del rilevatore — e disaccordi **tutti dello stesso tipo**, che indicano una
divergenza di definizione fra due dataset entrambi coerenti.

### `deep_check_fase1.py` — i sette controlli di coerenza

```bash
python scripts/deep_check_fase1.py            # tutti, read-only, ~15 s
python scripts/deep_check_fase1.py --only 5   # un controllo solo
python scripts/deep_check_fase1.py --live 200 # test 3 anche in rianalisi (lento)
```

Riesegue i sette controlli del §24 del log di sessione: riconciliazione dei conteggi, presenza
dell'oracolo per ogni etichetta, matrice ricalcolata contro `validation_phase1.json`, determinismo,
assenza di decisioni prese sotto timeout, margine della classe negativa, elenco dei casi limite.

Due scelte di progetto che vale conoscere:

- **Non codifica i numeri attesi.** I numeri si stampano; si fallisce solo sugli **invarianti** —
  nessuna label da scansione automatica, nessun file di servizio inventariato, zero decisioni
  troncate, nessun pulito che raggiunge la soglia, `FP = FN = 0`, matrice uguale al referto.
  Aggiungere campioni non deve far fallire il controllo; perdere una proprietà sì.
- **Riusa `validate_phase1.py`** (`load_rows`, `confusion`, `metrics`, `determinism_exposure`)
  invece di riscriverne la logica: se i due calcoli divergessero, il controllo non dimostrerebbe
  nulla sul referto che va in tesi.

Non scrive niente in `Pipeline_Reports/`, nemmeno con `--live`. Esce con codice 1 se un invariante
cade, quindi è usabile come controllo prima di un commit.

### `make_dataset_index.py` — genera la mappa dei dataset

```bash
python scripts/make_dataset_index.py
```

Scrive `E:\DATASET\INDICE.md` leggendo i fatti: conta i campioni sul disco, ricava label e
oracolo da `ground_truth.json`, e aggancia le due cose con lo **SHA-256 del contenuto**.
Per ogni cartella dice se concorre alle metriche, e segnala i **file senza label** (che nessuna
metrica vedrà) e le **label senza file** (campioni spostati o cancellati).

Un indice scritto a mano va fuori sincrono al primo file aggiunto, e a quel punto mente: è
esattamente il difetto che aveva `TEST_BIN_PULITI`.

### `validate_phase1.py` — calcola le metriche

```bash
python scripts/validate_phase1.py
```

Incrocia il CSV della Fase 1 con la ground truth e produce la matrice di confusione, la capacità
discriminante di ogni segnale e lo sweep della soglia. **Si rifiuta di stampare metriche con
supporto zero**, così non si producono numeri privi di significato.

**Deduplica per contenuto prima di contare.** Il CSV ha una riga per *file* (ed è giusto: è il log
dell'analisi), ma l'unità di misura è il *binario*. System32 contiene file byte-identici con nomi
diversi: `x64_MicrosoftEdgeBCHost/CP/DevTools.exe` sono lo stesso stub (3 nomi, 1 binario) e
`x86_dplaysvr.exe`/`dpnaddr.dll`/`dpnhpast.dll`/`dpnsvr.exe` altrettanto (4 nomi, 1 binario).
Contando le righe, quei 7 file gonfiavano i veri negativi di 5 unità.

---

## 10. I file prodotti in output

Tutti in `Unpacking/Packing/Pipeline_Reports/`.

| file | contenuto |
|---|---|
| **`report_analisi_lief.csv`** | il risultato: una riga per campione, 51 colonne. È il file principale |
| `ground_truth.json` | le risposte di riferimento, per SHA-256 |
| `validation_phase1.md` / `.json` | le metriche calcolate |
| `pipeline.log` | log unificato in append |
| `pipeline_state.json` | stato per la ripresa di run interrotte |
| `tool_diagnostics.jsonl` | **una riga per ogni esecuzione di uno strumento**: comando, codice di uscita, durata, esito. Più una riga iniziale con tutta la configurazione e le versioni |

E fuori da questa cartella, sotto la radice dei dataset:

| file | contenuto |
|---|---|
| **`E:\DATASET\INDICE.md`** | mappa generata dei dataset: cartella, campioni, label, oracolo, se concorre alle metriche |

`tool_diagnostics.jsonl` è ciò che permette di affermare *"nessuna decisione è stata presa mentre
uno strumento era stato interrotto da un timeout"* invece di sperarlo.

### Le 51 colonne del CSV, tutte

`Pipeline_Reports/report_analisi_lief.csv`, una riga per file analizzato. Lo schema è definito in
un punto solo (`_empty_results()` in `header_elf_lief.py`): se cambia, il CSV vecchio viene
archiviato automaticamente come `.bak_<data>`.

**Identità del campione (4)**

| colonna | contenuto |
|---|---|
| `File` | percorso **relativo** alla cartella analizzata (include la sottocartella) |
| `SHA256` | hash del contenuto: **l'unico identificatore stabile**. È la chiave verso la ground truth |
| `Dataset` | nome della cartella analizzata, per raggruppare i risultati |
| `Analyzed_At` | data e ora dell'analisi |

**Struttura del file (11)**

| colonna | contenuto |
|---|---|
| `Executable_Type` | `PE (Windows)` · `ELF (Linux)` · `OTHER` · `NON_EXECUTABLE (magic …)` |
| `Total_Raw_Size` | somma delle dimensioni su disco delle sezioni |
| `Total_Virtual_Size` | somma delle dimensioni in memoria |
| `Size_Difference` | differenza fra le due. **Informativa**: il segnale che la usava è stato rimosso (0 % sui packed, 1 % sui clean) |
| `Total_Sections` | numero di sezioni |
| `Sections_Stripped` | `SI` se la tabella delle sezioni è assente o svuotata |
| `Suspicious_Sections` | nomi di sezione **non standard**, separati da ` \| ` |
| `Anomalous_Size_Sections` | sezioni **eseguibili** con dimensione su disco 0 o sproporzionata rispetto a quella in memoria |
| `High_Entropy_Sections` | quante sezioni superano la soglia di entropia |
| `Max_Section_Entropy` | entropia massima su **tutte** le sezioni. Informativa |
| `Max_Entropy_No_Rsrc` | entropia massima **esclusa `.rsrc`**. ⚠️ È **questa** che alimenta il segnale |

**Entry point (6)**

| colonna | contenuto |
|---|---|
| `EP_Section` | sezione che contiene l'entry point, o `UNKNOWN` |
| `EP_Section_Entropy` | entropia di quella sezione |
| `EP_Section_WX` | `SI` se la sezione dell'EP è scrivibile **ed** eseguibile |
| `EP_Outside_Sections` | `SI` se l'EP ha RVA non nullo ma non cade in nessuna sezione (≠ DLL con EP = 0) |
| `Has_CLR_Header` | `SI` se la data directory CLR è valorizzata: assembly .NET, quindi `AddressOfEntryPoint` = 0 **per costruzione** e nessuna sezione di EP su cui misurare |
| `Exec_High_Entropy_Sections` | sezioni **eseguibili** a entropia ≥ 7,0. Alimenta il ripiego .NET dello stub strutturale |

**Import, export, overlay (6)**

| colonna | contenuto |
|---|---|
| `Total_Imports` | numero di funzioni importate |
| `Total_Exports` | numero di funzioni esportate. Serve come **eccezione**: molti export ⇒ codice intatto |
| `Imported_APIs` | prime 10 API importate |
| `Suspicious_IAT` | `SI` se importa solo `LoadLibrary`/`GetProcAddress` (o `dlopen`/`dlsym`) |
| `Overlay_Size` | byte in coda al file, fuori da ogni sezione |
| `Overlay_Entropy` | entropia dell'overlay |
| `Subsystem` | `GUI` · `CUI` · `NATIVE` · `WINDOWS_BOOT_APPLICATION`. Gli ultimi due sono kernel-mode: eccezione al segnale "pochi import" |

**Risultati degli strumenti (16)**

| colonna | contenuto |
|---|---|
| `YARA_Matches` | nomi delle regole YARA che hanno fatto match |
| `Yara_Status` | `ok` · `timeout` · `error:<Tipo>` · `unavailable` |
| `Die_Detections` | tutto ciò che DIE ha riconosciuto (compilatore, linker, packer) |
| `Die_Packer_Match` | `SI` se DIE nomina un packer/protector/installer, `NO` altrimenti |
| `Die_Packer_Name` | il **primo** nome, usato dalla Fase 2 come hint di instradamento |
| `Die_Packer_Type` | `packer`/`protector`/`cryptor`/`cruncher` oppure `installer`/`sfx` (da **estrarre**, non emulare) |
| `Die_All_Packers` | **tutte** le firme ordinate: su un multilayer la prima non basta |
| `Die_Heuristic` | euristiche `~packer`/`~protection`: segnale **debole** |
| `Die_Status` | `ok` · `empty` · `parse_error` · `timeout` · `not_found` · `rc_error` · `exception` |
| `Capa_Mode` | con quale modalità è stata prodotta la riga (`off` di default) |
| `Capa_Status` | `disabled` · `ok` · `stopped_at_banner` · `no_banner_probe` · `packed_limitation` · `timeout` · … |
| `Capa_Total_Matches` | numero di regole capa soddisfatte |
| `Capa_Packer_Match` | `SI` (packer nominato, forte) · `GENERICO` (debole) · `NO` |
| `Capa_Anti_Analysis_Match` | `SI` se capa rileva anti-debug/anti-VM. **Informativo** |
| `Capa_Capabilities` | prime 10 capability riconosciute |
| `Parse_Status` | `ok` · `lief_none` · `lief_error:<Tipo>` · `not_executable`. Un fallimento **non** scarta il file |

**Classificazione (8)**

| colonna | contenuto |
|---|---|
| `Is_DotNet` | `SI` per gli assembly .NET: pochi import è normale, il segnale viene saltato |
| `Packing_Score_%` | 100 se c'è un forte, `40 + 15n` se ci sono *n* ≥ 3 deboli, altrimenti `15n`. **Non è una probabilità**: serve solo a leggere il CSV |
| `Is_Packed_Label` | **la risposta**: `1` o `0` |
| `Packing_Evidence` | `named` · `structural` · `weak_only` · `none`: quanto è solida la decisione |
| `Strong_Signals` | elenco testuale dei segnali forti trovati |
| `Weak_Signals` | elenco testuale dei segnali deboli |
| `Info_Signals` | segnali registrati ma **non** contati (YARA generico, capa anti-analysis) |

Le colonne `*_Status` non sono decorative: sono ciò che permette di affermare *"nessuna decisione
è stata presa mentre uno strumento era in timeout"* invece di sperarlo.

**Come si legge una riga anomala.** Se un file è stato classificato in modo inatteso, `Strong_Signals`
e `Weak_Signals` dicono **esattamente** perché, in italiano. Non serve rileggere il codice.

---

## 11. I risultati

### Matrice di confusione

| | predetto packed | predetto pulito |
|---|---|---|
| **realmente packed** | **378** | **0** |
| **realmente pulito** | **0** | **3.435** |

Su **3.813 campioni etichettati** (3.923 righe, 110 `unknown` escluse). Precision 1,000 ·
Recall 1,000. **Zero decisioni prese mentre uno strumento era in timeout.**

I 3.435 puliti non vengono da una sola sorgente, ed è il punto che rende il numero difendibile:

| classe negativa | campioni | oracolo |
|---|---|---|
| System32 / SysWOW64 | 1.983 | firma Authenticode Microsoft |
| **distribuzioni ufficiali non-Microsoft** | **1.042** | **provenienza upstream, digest verificato dove pubblicato** |
| estensioni native Python | 341 | wheel ufficiali PyPI (provenienza) |
| libro PMA (`pma_book`) | 42 | dichiarazione del libro, oracolo di terzi |
| **Go e Rust** | **16** | **compilati in proprio, comando registrato** |
| altri verificati a mano | 11 | verifica documentata |

### Come vanno letti questi numeri

- **0 falsi positivi su 3.435 puliti**, provenienti da **cinque oracoli indipendenti** → il tasso
  di falsi allarmi è sotto lo **0,09 %**. È la metà solida della valutazione, e non è più misurata su
  una sola distribuzione: **1.042 dei puliti non sono Microsoft** (MinGW-w64, Cygwin, MSVC di terze
  parti, llvm-mingw), il che porta la quota Microsoft della classe negativa dall'83 % al 58 %. Su
  quei 1.042 file nessun segnale forte è scattato e solo 14 hanno raggiunto 2 segnali deboli su 3.
- **0 falsi negativi su 378 packed** → in tesi si scrive *"nessun falso negativo osservato su 378
  campioni"*, non *"recall del 100 %"*. La differenza conta: la misura vale per le **sei famiglie
  della matrice generata** (UPX, NSIS, Inno, MPRESS, Themida, VMProtect: 355 dei 378 campioni). Le
  altre sette presenti — Warbird, SFX Microsoft, PlayReady, FSG, PECompact, ASPack, (Win)Upack —
  hanno da 1 a 4 campioni ciascuna: sono casi documentati, non supporto statistico.

### Il margine, non solo il conteggio

Su una classe negativa il numero interessante non è "zero falsi positivi" ma **quanto ci si è
andati vicino**. La soglia è 3 segnali deboli:

| oracolo | campioni | 0 deboli | 1 | 2 | ≥ 3 |
|---|---|---|---|---|---|
| firma Authenticode Microsoft | 1.994 | 1.610 | 243 | **141** | **0** |
| distribuzione ufficiale non-Microsoft | 1.042 | 887 | 141 | **14** | **0** |
| wheel ufficiali PyPI | 341 | 226 | 113 | **2** | **0** |
| verifica manuale (libro PMA) | 42 | 34 | 7 | **1** | **0** |
| compilato in proprio (Go/Rust) | 16 | 10 | 0 | **6** | **0** |
| **totale** | **3.435** | **2.767** | **504** | **164** | **0** |

**Nessun segnale forte su nessuno dei 3.435**, e nessuno raggiunge la soglia: lo score massimo
osservato nella classe negativa è **30**, su una soglia di 70. Il caso peggiore è **2 segnali su
tutti e cinque gli oracoli**: nessuna classe si avvicina più di così.

Il tasso più alto è `compilato in proprio`, con **6 file su 16**: la classe strutturalmente più
vicina alla soglia è quella compilata in casa, non il malware — e il perché è qui sotto.

**I 6 binari Go a 2 segnali su 3 sono il caso più istruttivo.** Hanno una sezione a entropia
**8,00** — il massimo possibile — e prendono *entropia ≥ 7,2* più *euristica DIE*. Quell'entropia
non è packing: sono le sezioni **DWARF compresse con zlib**, che in un PE compaiono con i nomi
lunghi COFF `/4`, `/19`, `/65`. La prova: gli stessi programmi compilati con `-ldflags "-s -w"`
perdono il DWARF, l'entropia massima scende a 6,27 e i segnali vanno a **zero**.

Il terzo segnale che avrebbe prodotto il falso positivo sarebbe stato "nomi di sezione non
standard", e non scatta perché `is_standard_section_name()` riconosce la forma `/N`:

```python
return bool(re.fullmatch(r"/\d+", lname))  # nomi DWARF/COFF lunghi tipo "/4", "/19"
```

Quella riga era stata scritta per i binari di sistema Windows. **Senza di essa i 6 Go sarebbero 6
falsi positivi.** È un caso concreto di regola strutturale che generalizza a una toolchain su cui
non era mai stata provata — l'opposto dell'overfitting.

Nota utile: la configurazione "rischiosa" è quella **non** stripped, cioè il default dello
sviluppatore. Il malware scritto in Go è quasi sempre stripped, quindi finisce a zero segnali.

### Come si è arrivati a zero falsi positivi

All'inizio erano **23**. Sono stati risolti in due modi diversi, e la distinzione è importante:

**16 su 23 con correzioni al codice**, basate su una proprietà generale e non sul singolo file:

| causa | n | correzione |
|---|---|---|
| binari kernel e boot (`ntoskrnl`, `ntdll`, `winload`, …) | 13 | i nomi di sezione del kernel (`PAGE*`, `INIT*`) riconosciuti come standard, ed eccezione al segnale "pochi import" per i driver e per i file con molti export. Motivazione: *ntdll ha 2.433 export e 0 import per costruzione* — non *"escludi ntdll"* |
| entropia nelle risorse (`wermgr`, `auditpolmsg`) | 3 | `.rsrc` escluso dal calcolo dell'entropia |

**7 su 23 erano label sbagliate**, non errori del rilevatore: `wextract.exe` (SFX Microsoft) e i
cinque binari Warbird/PlayReady **sono** pacchettizzati secondo la definizione del §3. Sono stati
riclassificati come veri positivi.

Nessuna correzione ha mai perso un vero positivo.

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

Nota metodologica utile: **prima** delle correzioni la stessa tabella indicava 4 come valore
migliore. Alzare la soglia avrebbe nascosto dei segnali difettosi al prezzo della capacità di
rilevamento; correggere le cause ha reso 3 l'ottimo. Un iperparametro va usato come diagnostico,
non come cerotto.

### Il risultato più significativo: VMProtect a 32 bit

Fra i campioni generati internamente (quindi con label certa al 100 %):

| | campioni | DIE lo riconosce |
|---|---|---|
| VMProtect a **64 bit** | 26 | **25 (96 %)** |
| VMProtect a **32 bit** | 23 | **0 (0 %)** |

Stesso programma, stessa versione, stesse impostazioni. VMProtect 3.x **randomizza i nomi delle
sezioni**, quindi le firme che cercano `.vmp0` falliscono.

**Quei 23 campioni sono stati intercettati solo dal segnale "stub strutturale"**: entry point in
una sezione ad entropia 7,82 con le sezioni eseguibili svuotate. Senza i segnali strutturali
sarebbero **23 falsi negativi**.

È la giustificazione sperimentale dell'intera architettura forte/debole, su campioni la cui label
non è contestabile perché li abbiamo prodotti noi.

### Un caso limite da conoscere

Un solo campione su 356 è stato classificato con **soli segnali deboli**:
`x64_msvc_3c4de3f013d4_VMProtect.exe`, un assembly .NET protetto con VMProtect. Regge su 4 segnali
deboli contro una soglia di 3: **un segnale in meno e sarebbe un falso negativo**. È l'argomento
più concreto contro l'idea di alzare la soglia a 4.

### Verifica su malware reale: 168 campioni da MalwareBazaar

Ultima verifica, su materiale che non viene né dalla nostra matrice né da System32: **168 malware
reali**, mai analizzati prima, con i tag di packer dichiarati da MalwareBazaar. 157 secondi.

Accordo con i tag. **Due colonne, perché i numeri si riferiscono a due momenti diversi:** il run
del 27/09 e lo stato dopo le due correzioni ai segnali del §12, che hanno riclassificato 3 campioni.

| tag | campioni | segnalati **al run** | segnalati **dopo le correzioni** | `named`/`struct`/`weak` |
|---|---|---|---|---|
| `upx` | 43 | 42 (97 %) | **42** | 42 / 0 / 0 |
| `vmprotect` | 56 | 52 (92 %) | **52** | 15 / **34** / 3 |
| `themida` | 9 | 8 (88 %) | **8** | 8 / 0 / 0 |
| `_senza_tag` | 60 | **15 (25 %)** | **12 (20 %)** | 6 / 1 / 5 |
| **totale** | **168** | **117** segnalati, 51 puliti | **114** segnalati, 54 puliti | |

I 3 che cambiano sono tutti `_senza_tag`, e sono esattamente i 3 falsi positivi trovati a mano qui
sotto. L'ultima colonna descrive lo stato **attuale**, quindi somma 12 sulla riga `_senza_tag`.

#### La conferma indipendente sul VMProtect

| tag | DIE lo nomina |
|---|---|
| `upx` | 42/43 (98 %) |
| `themida` | 7/9 (78 %) |
| **`vmprotect`** | **10/56 (18 %)** |

Su malware VMProtect reale, etichettato da terzi, **DIE nomina 10 campioni su 56**. La Fase 1 ne
segnala 52, e **34 solo grazie ai segnali strutturali**.

È la stessa cosa osservata sulla matrice generata in casa (DIE 0/23 su VMProtect x86), ora
riprodotta su materiale reale con etichette di altri. Una previsione ricavata da campioni
controllati che si verifica in the wild: è la validazione più forte disponibile per l'architettura
forte/debole.

#### Il contro-campione `_senza_tag`: verifica manuale dei 15

I 60 file senza tag di packer servono a **misurare** la distorsione di selezione (un file è taggato
`fsg` solo perché qualcuno l'ha riconosciuto). **Al momento del run ne furono segnalati 15 su 60**,
e sono stati guardati **uno per uno**. (Sono 12 dopo le correzioni: la differenza è spiegata in
fondo a questa sottosezione — i 3 falsi positivi che le correzioni hanno eliminato.)

| # | campioni | verdetto | evidenza |
|---|---|---|---|
| 1 | 3 | ✅ vero positivo | DIE nomina `.NET Reactor` (protector) |
| 2 | 2 | ✅ vero positivo | DIE nomina `Microsoft Cabinet` (SFX) |
| 3 | 1 | ✅ vero positivo | DIE nomina `Nullsoft Scriptable Install System` |
| 4 | 1 | ✅ vero positivo | `.text`/`.rdata`/`.data` con **raw = 0** (svuotate), payload di 5,2 MB in una sezione a nome binario `.&-#` con H 7,98, 2 import. Packer custom da manuale |
| 5 | 5 | ✅ vero positivo (quasi certo) | assembly .NET con **`.text` a H 7,76–7,94**: l'IL normale sta a 5–6, quell'entropia è un payload cifrato incorporato. Uno porta anche l'euristica DIE `protection: Obfuscation` |
| 6 | **2** | ❌ **falso positivo** | MSVC, `.text` a H **6,20** e **5,45** (codice normale), sezioni tutte regolari, import: solo `GetProcAddress`, `LoadLibraryA`, `ExitProcess`. È **risoluzione dinamica degli import**, tecnica di evasione, non compressione |
| 7 | **1** | ❌ **falso positivo** | Delphi con 188 import (kernel32, wininet, bcrypt), `.text` a H 6,43. Segnalato perché `.itext` e `.didata` — **nomi di sezione standard di Delphi** — risultano "non standard" |

**Esito dell'analisi manuale: 12 veri positivi, 3 falsi positivi.** Erano i **primi falsi positivi
misurati del progetto**, da materiale su cui nessuna correzione era stata tarata (1,8 % sui 168
analizzati, 5 % sui 60 `_senza_tag`).

✅ **Entrambe le cause sono state corrette** (§12) e la Fase 1 rieseguita: i segnalati sono ora
**esattamente 12**, cioe' i 12 giudicati veri positivi a mano. I 3 ex falsi positivi risultano
`Is_Packed = 0` con 2 segnali deboli ciascuno, uno sotto la soglia. La matrice di confusione è
**invariata**, perché quei campioni non hanno label e non vi entravano.

**Cosa dicono i 6 veri positivi `named`:** sono packer e installer veri che **nessuno aveva
taggato**. Non sono errori del rilevatore — sono la misura di quanto il campionamento per tag stava
nascondendo. È esattamente il motivo per cui il contro-campione esisteva.

**Correzione al punto cieco .NET dichiarato:** i 5 assembly del caso 5 sono stati intercettati,
nonostante il §12 dichiari il .NET fuori portata. L'eccezione `Is_DotNet` sopprime il segnale "pochi
import", ma **entropia e entropia dell'EP restano attive** e bastano quando il crypter incorpora un
payload cifrato. Il punto cieco è più stretto di quanto dichiarato: riguarda l'offuscamento
*dell'IL*, non i crypter che allegano un payload.

#### I 6 con tag ma non segnalati

Non sono automaticamente falsi negativi: i tag sono label **proposte**, non ground truth.

| tag | cosa mostra il binario |
|---|---|
| `vmprotect` | score **0**, 150 import, H 6,45, EP in `.text`: sembra davvero non packed, tag probabilmente riferito al payload |
| `vmprotect` ×2 | score 30 con H 7,69: a **un segnale** dalla soglia |
| `vmprotect` | overlay di **63 MB a H 8,0** ma EP in `.text` con 185 import: dropper con payload cifrato in coda, il codice proprio non è packed |
| `themida` | 364 import, EP in `.text`: troppi import per Themida, tag sospetto |
| `upx` | 44 import, nessuna sezione UPX, DIE muto: forse un campione già decompresso (attenzione al tag `upx-dec`) |

#### Come va riportato in tesi

Questo run è un'**analisi di accordo con i tag di MalwareBazaar**, non una misura di recall, per due
motivi già dichiarati: **circolarità** (molti tag nascono da strumenti della famiglia di DIE e YARA)
e **distorsione di selezione**. Va in un paragrafo separato dalla matrice di confusione, e le sue
label **non sono state importate** nella ground truth proprio per non contaminarla.

### Validazione su dataset esterno: `packing-box/dataset-packed-pe`, 3.664 campioni

Tutte le misure precedenti hanno un limite comune: **il dataset l'abbiamo costruito noi**. Questo
no, e nemmeno le sue label. Protocollo e vincoli sono in `docs/05_protocollo_validazione_esterna.md`,
firmato prima del run; la composizione del dataset è descritta in §7.

Misura riproducibile con `python scripts/validate_external.py`, che scrive
`Pipeline_Reports/validation_external_dataset_packed_pe.md`.

> ⚠️ **Da questo dataset non si calcolano precision, tasso di falsi positivi, accuracy né F1.**
> La metà `not-packed` non è un oracolo: il fork ammette di aver rimosso da lì campioni compressi
> con UPX, e per ripulirla sono stati usati rilevatori della **stessa famiglia dei nostri** (PEiD
> reimplementato, Bintropy, PyPackerDetect, REMINDer). Misurare FP = 0 là sarebbe in parte una
> tautologia e un bias ottimistico. Si riporta **una sola riga di matrice**.
>
> La metà `packed` ha invece un oracolo **costruttivo** — 432 freeware passati dentro 25 packer,
> etichetta dal nome della cartella, nessun rilevatore coinvolto — quindi misurare DIE e YARA su di
> essa **non è circolare**.

#### Una sola riga

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** (3.220) | **TP = 3.219** | **FN = 1** |

**Recall 0,9997.** Supporto 3.220: i 3.222 campioni `packed` — 3.080 di `packed/` più i **142 di
`outliers/packed/`**, che erano fuori dalla chiave di risposta fino al 30/09/2026 — meno **2 file FSG
privi di magic `MZ`**
(`fsg_livekd.exe`, `fsg_Snap2HTML.exe`), esclusi dal triage come `not_executable` e contati come
**non analizzabili, non come falsi negativi**.

| gruppo (dichiarato prima del run) | famiglie | rilevati |
|---|---|---|
| calibrazione — UPX, MPRESS, Themida, FSG, Molebox | 5 | 598 / 598 |
| test — le altre 20 | 20 | 2.479 / 2.480 |

#### Il taglio che porta il risultato in tesi

| copertura da un prefisso di sezione | famiglie | rilevati |
|---|---|---|
| coperte | 7 | 901 / 901 |
| **scoperte** | **18** | **2.318 / 2.319** |

Scomposto fra cartelle principali e outliers: `packed/` 3.077 / 3.078, **`outliers/packed/` 142 / 142**
(tutti `named`). Gli outliers coprono 24 delle 25 famiglie e sono la selezione dei casi difficili
fatta dagli autori del dataset, non da noi. La chiave di risposta si rigenera con
`scripts/make_external_key.py`, che con `--verify` dimostra di riprodurre `v2_chiave.csv` — quella
del run firmato — riga per riga.

Sulle scoperte `PACKER_SECTION_PREFIXES` non ha una riga: il verdetto può venire solo da una firma
di terzi o dai segnali strutturali.

**La copertura è calcolata dai dati, non dedotta dal nome**, e non coincide con la lista a priori
del protocollo §6.3: Enigma Virtual Box e RLPack risultano coperte (producono `.enigma1`/`.enigma2`
e `.packed`), NSPack e PECompact no, perché in questo dataset non producono le sezioni attese.

#### Il contributo delle firme, isolato

Il dataset è pubblico da anni ed è il corpus di addestramento di packing-box: non si può escludere
che parte dei match `named` venga da firme scritte conoscendolo. Il numero che **non usa nomi** è
immune per costruzione:

- campioni senza alcun segnale forte da firma: **154**
- di questi, comunque segnalati packed: **153**

**Caso che vale da solo:** Enigma Virtual Box, **123/123 rilevati con DIE che non lo nomina mai** —
presi tutti dal nome di sezione. Una famiglia che la firma di terzi manca per intero e che il
riconoscimento strutturale copre.

#### L'unico falso negativo

```
amber_SmartDefragBootTime.exe   score 30 (2 deboli su 3)
   import 53, export 0        entropia massima 6,63      overlay assente
   EP in .text a H 6,02, non W+X                          nessuna sezione anomala
   unica sezione sospetta: .02iME4m                       DIE: solo "Generic"
```

Nessuna compressione osservabile: entropia da codice compilato, entry point nel posto giusto, 53
import. Gli altri 151 Amber sono riconosciuti da DIE come `cryptor: Amber`; su questo DIE tace.

Si conta come falso negativo. È il caso che il rilevatore per costruzione non può prendere: senza
compressione e senza firma restano solo i nomi di sezione, e da soli sono deliberatamente un segnale
**debole** — promuoverli produrrebbe falsi positivi su ogni binario con sezioni non convenzionali.

#### Osservazione sugli originali

15 dei 438 originali vengono segnalati (7 SFX, 5 installer, 3 con altro segnale forte). Fra questi
c'è un **controllo incrociato fra due selezioni indipendenti**: dei 10 file che gli autori avevano
isolato in `outliers/not-packed` perché li sospettavano compressi, noi ne segnaliamo **8, tutti con
un packer nominato** da DIE o YARA. I 2 restanti (`powerMAX_x32.exe`, `Start_Here_Win.exe`) sono
candidati a una classe pulita *difficile*, ma solo dopo verifica manuale. **Non sono falsi
positivi misurati**: servono come insieme di sospetti da confrontare con i 10 che il gruppo terzo ha
isolato in `outliers/not-packed`, cioè un controllo incrociato fra due selezioni indipendenti.

#### Limiti di questa misura

Non dice nulla su: falsi positivi · comportamento a **64 bit** (il dataset è a 32 bit: 3.660 su
3.664 x86, 2 x64, 2 senza magic `MZ`, misurato sul campo `Machine`; gli `outliers/` sono x86 al 100 %) · malware reale (sono utility freeware compresse) · .NET, Go, Rust (assenti).

**Deviazione dal protocollo, dichiarata:** il §5 prescriveva di eseguire prima la sola calibrazione
e di non guardare le 20 famiglie di test. Un campione preliminare di 270 file ne ha estratti 8 da
tutte e 25, quindi la sequenzialità non è stata rispettata. Resta intatta la proprietà che conta:
**nessuna correzione è stata applicata dopo aver visto un risultato di questo dataset**, quindi i
numeri non sono contaminati da taratura.

### Prestazioni

| | prima | dopo |
|---|---|---|
| 189 file | 1.599 s | **57 s** |
| decisioni prese con uno strumento in timeout | 73 su 189 (39 %) | **0** |

Il secondo numero conta più del primo: l'accelerazione non è stata ottenuta tagliando analisi a
metà.

---

## 12. Cosa la Fase 1 non sa fare (limiti dichiarati)

Un limite documentato vale più di una funzionalità fatta a metà.

### Falsi positivi: due cause trovate e risolte

Due cause misurate sui 168 malware reali (§11). Nessuna delle due era osservabile su System32,
perché System32 non contiene né malware che evade né binari Delphi: sono emerse solo confrontandosi
con materiale in the wild.

| causa | campioni | perché succedeva | correzione applicata | costo misurato |
|---|---|---|---|---|
| **Risoluzione dinamica degli import** | 2 | il segnale FORTE "IAT minimale sospetta" scattava su malware che importa solo `LoadLibrary`+`GetProcAddress` per risolvere il resto a runtime. È evasione, non compressione: `.text` a entropia 5,45–6,20 è codice in chiaro | il segnale è forte **solo se corroborato** da entropia ≥ 7,2 o sezioni anomale; altrimenti viene **declassato a debole**, non scartato, così l'informazione resta leggibile nel CSV | **0 veri positivi persi.** "IAT minimale" non era mai l'unico segnale forte, e dopo la correzione resta forte su **tutti e 64** i packed che lo avevano |
| **Nomi di sezione Delphi** | 1 | `.itext` e `.didata` sono prodotte dal compilatore Delphi/Borland ma non figuravano in `STANDARD_SECTIONS`: generavano due segnali deboli che con l'euristica DIE facevano 3 | aggiunte a `STANDARD_SECTIONS`, come già fatto per le famiglie kernel `PAGE*`/`INIT*` | **0 veri positivi persi.** 53 packed hanno quelle sezioni (sono gli installer **Inno**, che *è* un programma Delphi) ma hanno tutti segnali forti |

Entrambe sono della stessa natura delle 16 correzioni che avevano portato i falsi positivi da 23 a 0
su System32: **si corregge la causa strutturale, non il campione.** È la terza iterazione dello
stesso metodo.

**Esito dopo la rianalisi completa** (3.056 file, 9 cartelle in sequenza):

| | prima | dopo |
|---|---|---|
| `_senza_tag` segnalati packed | 15 | **12** (= i 12 giudicati veri positivi a mano) |
| i 3 ex falsi positivi | `Is_Packed = 1` | **`Is_Packed = 0`**, 2 segnali deboli ciascuno, uno sotto la soglia |
| matrice di confusione | TP 378 · FN 0 · FP 0 · TN 3.435 | **identica** |
| test automatici | 38 verdi | **44 verdi** (2 a protezione delle correzioni, 4 del ripiego .NET) |

La matrice non cambia perché quei 3 campioni **non hanno label** — vengono da un set di sola analisi
qualitativa — e quindi non vi entravano. Il beneficio non è un numero migliore: è che il rilevatore
è più corretto su una classe di casi reali.

**Due test nuovi proteggono le correzioni**, così una regressione futura si vede subito:
`test_iat_minimale_senza_compressione_e_solo_debole` (entropia 6,2 → non forte, ma l'informazione
resta fra i deboli) e `test_sezioni_delphi_sono_standard`.

**Nota su un residuo.** Il campione Delphi ora prende ancora "entry point in sezione non standard",
perché quel controllo usa `STANDARD_EXEC_SECTIONS`, una lista **diversa** da `STANDARD_SECTIONS`.
Con 2 soli segnali deboli resta correttamente `clean`, quindi non è stato toccato: aggiungere
`.itext` anche a quella lista sarebbe la correzione completa, ma va misurata prima come le altre due.

### Quanto del risultato è in-sample

Le 16 correzioni che hanno portato i falsi positivi da 23 a 0 (§11) **sono state ricavate guardando
System32**. System32 non è stato escluso dalla validazione, e vale **1.994 dei 3.435** campioni
puliti: il `FP = 0` complessivo è quindi, per quella parte, una misura **in-sample**. Va detto, non
aggirato.

L'argomento indipendente **non è uno split calibrazione/test**: quello split non esiste come
protocollo, perché nessuno script di Fase 1 lo legge. L'argomento è **cronologico**: le eccezioni
erano già scritte quando la classe negativa era il solo System32, e il resto del corpus è arrivato
dopo.

| | campioni | quando |
|---|---|---|
| System32 | 1.994 | **prima**: da qui le 16 correzioni |
| libro PMA | 42 | prudenzialmente contato come in-sample |
| **wheel PyPI** | **341** | **dopo** che le eccezioni erano scritte |
| **distribuzioni ufficiali non-Microsoft** | **1.042** | **dopo**, e analizzate a rilevatore congelato: §22 del log dichiara che `header_elf_lief.py` non e' stato toccato in quella sessione |
| **entrati dopo le correzioni** | **1.383** | **0 falsi positivi, 0 segnali forti** |

I 16 binari Go/Rust compilati in proprio sono anch'essi successivi e portano il totale a **1.399**,
sempre con zero falsi positivi; si contano a parte perche' il loro oracolo e' di natura diversa.

**La rivendicazione corretta è quindi:** zero falsi positivi su **1.383** binari puliti entrati nel
corpus dopo che le correzioni erano state scritte, e zero su 3.435 complessivi. Il primo numero è
la misura indipendente, il secondo è il supporto.

Tre precisazioni che reggono l'argomento:

1. **Le correzioni sono regole con una motivazione generale, non esclusioni.** `ntdll` non è stato
   escluso: è stata aggiunta l'eccezione *"0 import ma 2.433 export"*, che vale per qualunque
   binario con una export table consistente.
2. **La generalizzazione è già stata messa alla prova, e ha retto.** Il caso più netto è nel §16.2
   del log: la regola sui nomi di sezione `/N`, scritta per i binari **kernel di Windows**, ha
   impedito a 6 binari **Go** di diventare falsi positivi — una toolchain su cui non era mai stata
   provata. È il contrario dell'overfitting.
3. **Il secondo giro di correzioni non contamina nulla.** Le due del §12 — IAT condizionale,
   `.itext`/`.didata` — derivano dai 168 malware reali di MalwareBazaar, che **non hanno label e
   non entrano nella matrice**.

### Determinismo, misurato

Il rilevatore produce lo stesso verdetto sullo stesso file, e non è un'assunzione: è misurato in due
modi (§24.7 del log di sessione).

- **Fra due run a cinque giorni di distanza**, su 3.051 binari in comune fra i CSV archiviati:
  **40 colonne su 49 identiche**. Le 9 che differiscono sono il timestamp, i percorsi riorganizzati,
  e le due correzioni ai segnali del §19 — che hanno mosso il verdetto di **tre binari e soltanto
  tre**, cioè esattamente i tre falsi positivi che dovevano sistemare.
- **Contro l'artefatto congelato**, rianalizzando 217 binari scelti per contenere ogni caso limite:
  **zero differenze** su tutte e 50 le colonne, comprese quelle che decidono.

Sono identiche tutte le colonne di misura: entropie a due decimali, output completo di DIE, match
YARA, conteggi e lista degli import, sezione dell'entry point.

Il limite da dichiarare: è determinismo **misurato**, non dimostrato. DIE, YARA e LIEF restano
processi esterni, e la garanzia vale sui campioni provati.

> **Trappola per chi scrive strumenti di misura:** `_format_for_csv` **non è idempotente** su
> `Imported_APIs`, `Capa_Capabilities` e `Die_Detections`, perché `_as_list()` scarta le voci vuote —
> che sono gli import per ordinale. `analyze_with_lief` la chiama già una volta
> (`header_elf_lief.py:1030`): richiamarla altera 551 righe su 7.752 e produce differenze che nella
> pipeline non esistono.

### Due segnali deboli che misurano un solo fatto

`entropia sezione >= 7.2` e `entry point in sezione ad alta entropia` sono conteggiati
separatamente. Sono due proprietà diverse — quanto è calda la sezione più calda, e dove cade
l'entry point — ma **coincidono** quando la sezione dell'entry point è anche la più calda del file:
in quella configurazione due segnali nascono da una sola misurazione.

Misurato su tutto il dataset etichettato (§24.6 del log di sessione):

| | con la coppia | di cui un solo fatto |
|---|---|---|
| `packed` (378) | 4 | 4 |
| `clean` (3.435) | 1 | 1 |

Cinque file su 3.813, lo 0,13 %, ma concentrati dove il margine è già sottile:
`x64_ClipUp.exe`, `x64_GenValObj.exe` e `x86_Windows.Media.Protection.PlayReady.dll` superano la
soglia con **due fatti distinti** invece di tre; `x86_MLS6.dll`, pulito e firmato Microsoft, sta a
due segnali prodotti da una sola misurazione ed è il file più esposto della classe negativa.

**Dichiarato e non corretto, con la ragione.** Far contare la coppia come un segnale solo
introdurrebbe **3 falsi negativi** sulla sottoclasse della protezione del vendor — che è già
dichiarata fuori perimetro, rilevata ma non spacchettata. Se la soglia verrà ritarata, la
correzione giusta è contare i *fatti* osservati invece dei *segnali* emessi.

### Limiti di perimetro

| limite | stato |
|---|---|
| **Offuscamento dell'IL .NET** | i packer che riscrivono l'IL non producono le firme strutturali cercate, e l'eccezione `Is_DotNet` disattiva il segnale "pochi import". ⚠️ **Limite più stretto di quanto si pensava**: i *crypter* .NET che incorporano un payload cifrato vengono intercettati da entropia + entropia dell'EP — misurato su 5 campioni reali (§11). Resta scoperto l'offuscamento puro dell'IL, che non alza l'entropia |
| ~~**Packer non testati** (FSG, ASPack, PECompact, Petite)~~ | ✅ **superato**: il dataset esterno (§11) ne fornisce 8 campioni per famiglia, tutti rilevati. Restano non testati solo kkrunchy e l'Enigma classico, assenti anche da lì |
| **Punto cieco residuo delle firme** | `Lab18-02` del libro PMA resta un FSG su cui né DIE né YARA producono un nome, mentre gli 8 FSG del dataset esterno vengono tutti nominati: le firme coprono le **versioni note** di un packer, non tutte |
| **ELF** | il supporto esiste nel codice ma è incompleto: un errore di LIEF (`ARCH has no attribute x86_64`) fa trattare gli ELF come binari Windows. Se l'ELF non entra nello scope, va dichiarato fuori perimetro invece di restare a metà |
| **File MSI** | non sono PE (sono contenitori OLE): escono come `not_executable` |
| **Nessun punteggio continuo** | l'output è binario, quindi **non si può tracciare una curva ROC/PR** |
| **Riproducibilità su altre macchine** | percorsi assoluti in 3 script (`DIEC_PATH`, le costanti dei packer, `DEFAULT_ROOT`): su una macchina diversa vanno corretti a mano. **Mitigato** da `scripts/preflight.py`, che dice quali non esistono e dove stanno, e da `03_setup_e_esecuzione.md`; la soluzione pulita resta un `config/tools.json` unico. È il punto strutturalmente più debole del progetto |

### Classi ancora assenti dal dataset

| classe | perché conterebbe |
|---|---|
| **Goodware non-Microsoft ampio** | oggi la classe negativa è System32 (1.983) + 341 `.pyd` + 16 Go/Rust. Manca MSYS2/Cygwin, software portabile, installer legittimi reali |
| **Assembly .NET offuscati con ConfuserEx** | servirebbero a quantificare il punto cieco residuo sull'IL |
| **Packer a 64 bit di terze parti** | oltre a Themida/VMProtect/UPX/MPRESS della matrice |

---

## 13. Come rieseguire tutto da zero

### Prerequisiti

```bash
python -m pip install -r requirements-fase1.txt
python scripts/preflight.py --packer
```

La Fase 1 ha **due sole dipendenze obbligatorie**: `lief==1.0.0` e `yara-python==4.5.4`. Lo stack
di emulazione della Fase 2 (`qiling`, `unicorn`, `pefile`) è importato in modo **ritardato**,
quindi `--phase1-only` gira senza averlo installato.

- interprete: il `.venv` del progetto. Il Python di sistema ha LIEF di major diverso e **non**
  esegue la pipeline — `preflight.py` lo verifica;
- strumenti esterni: al triage serve solo **Detect It Easy** (i packer servono a
  `pack_samples.py`), percorsi come da §9;
- regole YARA compilate in `config/yara_forge_compiled.yrc`.

L'installazione completa su una macchina nuova è descritta in **`03_setup_e_esecuzione.md`**.

### 1. Generare i campioni packed

```bash
python scripts/pack_samples.py
```

### 2. Costruire la ground truth

```bash
python scripts/build_ground_truth.py --import-packing-matrix
python scripts/build_ground_truth.py --import-authenticode "E:/DATASET/01_LABEL_CERTA/system32"
python scripts/build_ground_truth.py --import-upx-test "E:/DATASET/03_NON_ETICHETTATI/wild_malwarebazaar/upx"
python scripts/build_ground_truth.py --import-labels config/pma_labels.json --labels-dir "E:/DATASET/01_LABEL_CERTA/pma_book"
python scripts/build_ground_truth.py --import-labels config/pypi_labels.json --labels-dir "E:/DATASET/01_LABEL_CERTA/pypi"
python scripts/build_ground_truth.py --import-labels config/gorust_labels.json --labels-dir "E:/DATASET/01_LABEL_CERTA/gorust"
python scripts/build_ground_truth.py --stats
```

### 3. Eseguire la Fase 1

```bash
python scripts/parameters_info.py --dir "E:/DATASET/01_LABEL_CERTA/matrice_packed" --phase1-only
python scripts/parameters_info.py --dir "E:/DATASET/01_LABEL_CERTA/system32"      --phase1-only
python scripts/parameters_info.py --dir "E:/DATASET/01_LABEL_CERTA/pypi"          --phase1-only
python scripts/parameters_info.py --dir "E:/DATASET/01_LABEL_CERTA/gorust"        --phase1-only
```

I file già analizzati vengono saltati (lo storico è per SHA-256). Per rianalizzare tutto dopo aver
cambiato la logica serve `--reanalyze`.

### 4. Calcolare le metriche

```bash
python scripts/validate_phase1.py
```

### 5. Rigenerare la mappa dei dataset

```bash
python scripts/make_dataset_index.py
```

### Come leggere il risultato

Aprire `Pipeline_Reports/validation_phase1.md` per le metriche, e
`Pipeline_Reports/report_analisi_lief.csv` per il dettaglio file per file. Se un file è stato
classificato in modo inatteso, le colonne `Strong_Signals` e `Weak_Signals` dicono **esattamente**
perché.

---

## In sintesi

La Fase 1 legge un eseguibile senza eseguirlo, ne misura la struttura con LIEF, la confronta con
le firme di DIE e YARA, e applica una regola a due livelli: **una prova forte basta, altrimenti
servono tre indizi deboli concordanti**.

Su 3.813 campioni con risposta di riferimento verificabile non ha sbagliato: 378 file
pacchettizzati tutti riconosciuti, 3.435 file puliti — da cinque oracoli indipendenti — nessuno
segnalato per errore.

Il risultato più interessante non è lo zero: è che **23 campioni VMProtect a 32 bit, invisibili a
tutte le firme, sono stati intercettati dai soli segnali strutturali**. È la prova che riconoscere
il packing richiede di misurare com'è fatto il file, non solo di cercare pattern già noti.

Da qui si può passare alla Fase 2: prendere i file marcati `packed` e provare a ricostruirne il
codice originale.

---

## Appendice — Fonti e riferimenti

Raccolta unica di tutto ciò che va citato in tesi. Gli **strumenti** stanno nel §4 con i rispettivi
link; qui ci sono le **fonti dei dati** e i **lavori di terzi** che gli argomenti metodologici
chiamano in causa — quelli che un revisore vorrà poter verificare.

### Fonti dei campioni

| insieme | campioni | provenienza |
|---|---|---|
| matrice generata | 355 | prodotta in proprio da `pack_samples.py` a partire da 53 master |
| System32 | 1.994 | installazione Windows locale, firma Authenticode verificata |
| distribuzioni ufficiali non-Microsoft | 1.042 | URL e digest in `scripts/fetch_goodware_non_ms.py`, uno per archivio — vedi sotto |
| wheel PyPI | 341 | <https://pypi.org>, installate con `pip download` |
| libro *Practical Malware Analysis* | 48 | <https://github.com/SafeEval/practical-malware-analysis> |
| compilati in proprio (Go/Rust) | 16 | sorgenti e script di build in `Build_Samples/` |
| malware reale | 168 | **MalwareBazaar** — <https://bazaar.abuse.ch/> |
| dataset esterno | 3.664 | vedi sotto |

Le sette distribuzioni ufficiali da cui vengono i 1.042 binari non-Microsoft:

| progetto | fonte |
|---|---|
| Cygwin | <https://mirrors.kernel.org/sourceware/cygwin> |
| MSYS2 (mingw64) | <https://repo.msys2.org/mingw/mingw64> |
| MSYS2 (msys) | <https://repo.msys2.org/msys/x86_64> |
| VLC | <https://get.videolan.org/vlc/last/win64/> |
| Notepad++ | <https://github.com/notepad-plus-plus/notepad-plus-plus/releases/> |
| PuTTY | <https://the.earth.li/~sgtatham/putty/latest/> |
| curl for Windows | <https://curl.se/windows/latest.cgi?p=win64-mingw.zip> |

Per ogni file il manifest registra l'archivio di provenienza, il suo SHA-256 e la verifica del
digest upstream: la provenienza è ricostruibile campione per campione.

### Il dataset esterno e la sua catena di provenienza

| | |
|---|---|
| dataset usato | <https://github.com/packing-box/dataset-packed-pe>, commit **`45bf915f`** (13/07/2024) |
| dataset originale, di cui il precedente è un fork sanificato | <https://github.com/chesvectain/PackingData> |
| licenza | **nessuna dichiarata** — si cita, non si ridistribuisce |

Il fork dichiara di aver rimosso dalla cartella `not-packed` campioni che risultavano compressi, e
di aver isolato in `outliers/` quelli ambigui. **È il motivo per cui la sua metà `not-packed` non
viene usata come oracolo** (§7 e protocollo §3.2): quella selezione è stata fatta con rilevatori
della stessa famiglia dei nostri, elencati qui sotto.

### I rilevatori di terzi citati nell'argomento sulla circolarità

Sono gli strumenti con cui il fork ha ripulito la metà `not-packed`. Vanno citati perché l'intero
argomento — *misurare FP = 0 là sarebbe in parte una tautologia* — poggia sul fatto che misurano le
stesse proprietà del nostro rilevatore.

| strumento | cosa misura | fonte |
|---|---|---|
| PEiD (reimplementazione Python) | firme di packer su pattern noti | <https://github.com/packing-box/peid> |
| Bintropy | entropia, per stimare la presenza di dati compressi o cifrati | <https://github.com/packing-box/bintropy> |
| PyPackerDetect | euristiche strutturali su sezioni e import | <https://github.com/packing-box/pypackerdetect> |
| REMINDer | entry point in sezione scrivibile | <https://github.com/packing-box/reminder> |

### Rassegna bibliografica

<https://github.com/packing-box/awesome-executable-packing> — raccolta curata di letteratura,
dataset, packer e strumenti sul packing di eseguibili. Non contiene campioni: è una bibliografia, ed
è la fonte da cui partire per il capitolo sullo stato dell'arte.

### Risorse didattiche usate durante il lavoro

- <https://www.jaiminton.com/Tutorials/PracticalMalwareAnalysis/> — soluzioni del libro PMA
- <https://hackerhood.redhotcyber.com/tutorial-di-malware-analysis-2/>
- <https://medium.com/@dbragetti/unpacking-malware-685de7093e5>
- <https://web.archive.org/web/20241215175113/https://deluks2006.github.io/posts/snowy-days-and-the-malware-packing-ways/>

