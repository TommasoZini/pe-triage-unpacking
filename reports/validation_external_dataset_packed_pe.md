# Validazione esterna — `packing-box/dataset-packed-pe`

Prodotta da `scripts/validate_external.py` secondo il protocollo firmato **prima** del run,
in `docs/05_protocollo_validazione_esterna.md`.

- chiave di risposta: `E:\DATASET\04_VALIDAZIONE_ESTERNA\v3_chiave.csv`
- voci della chiave: **3664**, agganciate a una riga del CSV: **3664**, mai analizzate: **0**
- di cui 3222 `packed` e 442 `not-packed`
- provenienza delle righe (colonna `Dataset` = run di PRIMA analisi, non appartenenza all'insieme): `dataset-packed-pe-main` 3390, `v1_misto` 270, `legacy_misto` 4
- duplicati per contenuto collassati: 0
- non analizzabili (magic non valido, fuori perimetro): **2**
- supporto reale della misura: **3220**

## Una sola riga di matrice

> La metà `not-packed` di questo dataset **non è un oracolo**, e il protocollo (§3.2) vieta
> di calcolarne precision, tasso di falsi positivi, accuracy o F1: è stata ripulita con
> rilevatori della stessa famiglia dei nostri, quindi misurare FP = 0 là sarebbe in parte
> una tautologia. Si riporta **una sola riga**, e si scrive che è una sola.

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** (3220) | **TP = 3219** | **FN = 1** |

**Recall 0.9997** — 3219 su 3220.

### La sottoparte `outliers/`, misurata a parte

Il README del dataset descrive questi file come *"samples we could identify as
potentially disturbing our models, i.e. when they were sorted among the not packed
samples while demonstrating characteristics of packed data"*: sono i casi difficili
scelti da **altri**, non da noi, e non stanno ne' in `packed/` ne' in `not-packed/`
(sovrapposizione misurata: zero). Diluiti nel totale non direbbero niente, quindi
si riportano separati.

| sottoinsieme | campioni | rilevati | recall |
|---|---|---|---|
| `packed/` (le cartelle principali) | 3078 | 3077 | 0.9997 |
| **`outliers/packed/`** | **142** | **142** | **1.0000** |

Gli outliers coprono 24 delle famiglie gia' presenti — non ne aggiungono
di nuove, aggiungono gli esemplari piu' difficili di quelle. Evidenza sui rilevati: `named` 142.

### Recall senza firme

Questo dataset è pubblico da anni ed è il corpus di addestramento del progetto packing-box:
non si può escludere che parte dei match `named` venga da firme scritte conoscendolo (§6.4).
Il numero che segue **non usa nomi**, quindi è immune a quella contaminazione per costruzione.

- campioni senza alcun segnale forte da firma: **156**
- di questi, comunque segnalati packed: **155**

## Recall per famiglia

`cal` = calibrazione, `test` = gruppo di test (divisione dichiarata prima del run, §5).
`sez` = la famiglia ha una riga in `PACKER_SECTION_PREFIXES`.

| famiglia | gruppo | sez | rilevati | campioni | named | struct | weak | DIE nomina |
|---|---|---|---|---|---|---|---|---|
| Amber | test | — | 154 | 155 | 154 | 0 | 0 | 154 |
| ASPack | test | sì | 126 | 126 | 126 | 0 | 0 | 126 |
| Alienyze | test | — | 129 | 129 | 112 | 1 | 16 | 112 |
| BeRoEXEPacker | test | — | 125 | 125 | 125 | 0 | 0 | 125 |
| EXpressor | test | — | 127 | 127 | 127 | 0 | 0 | 127 |
| Enigma Virtual Box | test | sì | 126 | 126 | 126 | 0 | 0 | 0 |
| Eronana Packer | test | — | 153 | 153 | 152 | 1 | 0 | 152 |
| Exe32pack | test | — | 128 | 128 | 128 | 0 | 0 | 128 |
| FSG | cal | — | 125 | 125 | 110 | 0 | 15 | 110 |
| JDPack | test | — | 127 | 127 | 127 | 0 | 0 | 127 |
| MEW | test | — | 125 | 125 | 125 | 0 | 0 | 125 |
| MPRESS | cal | sì | 125 | 125 | 125 | 0 | 0 | 125 |
| Molebox | cal | — | 126 | 126 | 126 | 0 | 0 | 126 |
| NSPack | test | — | 125 | 125 | 125 | 0 | 0 | 125 |
| Neolite | test | — | 118 | 118 | 118 | 0 | 0 | 118 |
| PECompact | test | — | 129 | 129 | 129 | 0 | 0 | 129 |
| PEtite | test | sì | 148 | 148 | 148 | 0 | 0 | 148 |
| Packman | test | — | 124 | 124 | 124 | 0 | 0 | 124 |
| RLPack | test | sì | 124 | 124 | 124 | 0 | 0 | 124 |
| TELock | test | — | 127 | 127 | 127 | 0 | 0 | 127 |
| Themida | cal | sì | 126 | 126 | 126 | 0 | 0 | 126 |
| UPX | cal | sì | 126 | 126 | 126 | 0 | 0 | 126 |
| WinUpack | test | — | 126 | 126 | 126 | 0 | 0 | 126 |
| Yoda-Crypter | test | — | 126 | 126 | 126 | 0 | 0 | 126 |
| Yoda-Protector | test | — | 124 | 124 | 124 | 0 | 0 | 124 |

### Il taglio che porta il risultato in tesi

- famiglie coperte da un prefisso di sezione: 7 — **901/901** rilevati
- famiglie **scoperte**: 18 — **2318/2319** rilevati


> **La copertura misurata non coincide con la lista a priori del protocollo (§6.3).** Dedurla
> dal nome della famiglia non è affidabile:
> coperte nei fatti ma non nella lista: **Enigma Virtual Box, RLPack** (producono sezioni che un prefisso intercetta);
> nella lista ma non nei fatti: **NSPack, PECompact** (in questo dataset non producono le sezioni attese).
> Il conteggio qui sopra usa la copertura **misurata**.

Sulle famiglie scoperte la tabella dei prefissi non ha una riga: il verdetto può venire solo
da una firma di terzi o dai segnali strutturali. È il test diretto di ciò che la tesi
rivendica, su etichette a oracolo costruttivo.

### Per gruppo

| gruppo | famiglie | rilevati | campioni |
|---|---|---|---|
| calibrazione | 5 | 628 | 628 |
| test | 20 | 2591 | 2592 |

### File non analizzabili

2 file con magic non valido, esclusi dal triage e **non contati come falsi negativi** (§9.2):

- `fsg_livekd.exe` — packed/FSG
- `fsg_Snap2HTML.exe` — packed/FSG

## Falsi negativi

Ognuno va guardato a mano prima di essere contato, e classificato come **difetto del
rilevatore** oppure **caso di definizione**: entrambi si contano, il numero non si sconta
(§9.2).

| famiglia | falsi negativi |
|---|---|
| Amber | 1 |

- **Amber** `amber_SmartDefragBootTime.exe` — score 30, import 53, H 6.63, EP `.text`
  - deboli: nomi sezione non standard | DIE euristica: protection: Generic
  - DIE: Generic

## Osservazioni sulla metà `not-packed` (qualitative, non metriche)

15 dei 442 originali vengono segnalati. **Non sono falsi positivi**
**misurati**: quella metà non è un oracolo (§3.2). Sono un insieme di sospetti.

**Controllo incrociato fra due selezioni indipendenti.** Il gruppo terzo ha isolato
10 file in `outliers/not-packed` perché li sospettava compressi pur
essendo etichettati `not-packed`. Noi ne segnaliamo **8 su 10**,
di cui **8 con un packer nominato** da DIE o YARA. Due selezioni fatte con
criteri diversi convergono sugli stessi file: è un argomento a favore della
rilevazione, non un conteggio di falsi positivi — quei file sono probabilmente
compressi per davvero, ed è il motivo per cui i loro autori li hanno messi da parte.

I 2 non segnalati sono i candidati a una classe pulita
**difficile**, ma solo dopo verifica manuale documentata: la loro etichetta
`not-packed` non è un oracolo.

- `powerMAX_x32.exe` — score 15, H 6.54, import 683, deboli: DIE euristica: packer: Generic
- `Start_Here_Win.exe` — score 15, H 6.69, import 104, deboli: overlay grande ad alta entropia (16894 KB, H=8.0)

| categoria | campioni |
|---|---|
| SFX / autoestraente | 7 |
| installer | 5 |
| altro segnale forte | 3 |

