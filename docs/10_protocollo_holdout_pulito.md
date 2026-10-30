# Protocollo di misura su classe negativa indipendente

**Registrato il 21 ottobre 2026 con il commit `a699d63`, prima di qualunque raccolta.**

**Emendato il 21 ottobre 2026, sempre prima della raccolta**, su §3, §4, §6.1 e §9: la
prima stesura ammetteva la firma Authenticode di un produttore qualunque come oracolo,
mentre `build_ground_truth.py:373` stabilisce già il contrario, perché software firmato e
protetto allo stesso tempo è comune. L'oracolo per il materiale non Microsoft è quindi il
canale ufficiale con digest verificato, come per i 1.042 binari già nel corpus.

---

## 1. La domanda a cui questo run risponde

Il tasso di falsi allarmi della Fase 1 è misurato su una classe negativa di 3.435 binari
che contiene anche i file da cui sono state derivate le eccezioni della regola.
Verificato nel codice il 21/10/2026: `threshold_sweep()` e `confusion()` in
`scripts/validate_phase1.py` iterano le stesse righe etichettate, e lo sweep a soglia 3
riporta TN = 3.435, identico alla matrice. **In Fase 1 non esiste alcuno split
calibrazione/test.**

La domanda, mai misurata finora:

> Su materiale pulito raccolto *dopo* il congelamento della regola, da toolchain non
> rappresentate nel corpus interno, quanti file il rilevatore segnala come packed?

## 2. Che cosa resta fuori

- **Il recall.** Qui non ci sono campioni packed: niente TP, FN, precision, F1, accuracy.
  Si riporta una sola grandezza, quanti puliti vengono segnalati.
- **Il confronto con i 3.435.** I due numeri non si sommano e non si mediano. Il primo
  misura l'aderenza al materiale d'origine, questo il comportamento su materiale estraneo.

## 3. L'oracolo ammesso, e cosa è vietato

Ammesso **solo** l'oracolo di provenienza, nella forma già in uso per i 1.042 binari non
Microsoft del corpus: **download dal canale ufficiale del progetto, con digest pubblicato
a monte e verificato al momento del download**, e i PE estratti da quell'archivio
verificato. È il comportamento che `fetch_goodware_non_ms.py` implementa già, con il
campo `archive_verified` nel manifest.

⚠️ **La firma Authenticode di un produttore non Microsoft non autorizza la label
`clean`**, e la ragione è già scritta in `build_ground_truth.py:373`: software firmato e
protetto allo stesso tempo è comune, quindi una firma valida esclude una manomissione
dopo la firma ma non un packing applicato dal produttore prima di firmare. Nel corpus
restano `unknown` sette file firmati Gen Digital e GitHub per questo motivo, e la stessa
restrizione vale qui. La firma resta utile come controllo accessorio, mai come oracolo.

Vietato, e il divieto è la ragione d'essere del protocollo:

- ⚠️ **qualunque etichetta prodotta da un rilevatore**, incluso DIE, YARA, un antivirus o
  un servizio online. L'assenza di un allarme non è una verifica;
- ⚠️ **MalwareBazaar e ogni sorgente di malware**, in qualunque forma. Su un campione
  malevolo la proprietà «non è packed» si stabilisce solo con analisi manuale uno per uno,
  e i 168 campioni MalwareBazaar già presenti sono la sorgente delle due correzioni del
  secondo giro, quindi quella sorgente è materiale di calibrazione;
- ⚠️ **gli output della Fase 2**, che sono dump prodotti dallo strumento in misura;
- ⚠️ **qualunque file il cui SHA-256 sia già nel corpus.** Deduplicazione obbligatoria
  contro `ground_truth.json`: un file già presente non è indipendente.

## 4. La sorgente: distribuzioni ufficiali di progetti assenti dal corpus

I file si prendono scaricando l'archivio ufficiale di ciascun progetto con
`fetch_goodware_non_ms.py`, che verifica il digest a monte ed estrae i PE dall'archivio.
L'inventario dei pacchetti installati nella VM serve solo a scegliere quali progetti
valgono la pena, non a fornire i file.

### 4.1 Progetti ammessi, elenco chiuso adesso

Si privilegiano le toolchain assenti dal corpus interno. Esclusi i progetti già presenti
nei 1.042: MSYS2, Cygwin, VLC, PuTTY, Notepad++, curl.

| progetto | perché | toolchain che porta |
|---|---|---|
| `lazarus` o `freepascal` | mette alla prova l'eccezione sui nomi di sezione Delphi aggiunta nel secondo giro | FPC, sezioni `.itext`/`.didata` |
| `llvm` | toolchain assente dal corpus | Clang, lld |
| `dotnet-sdk` | header CLR e pochi import: il caso che le tre esenzioni devono coprire | Roslyn, bundle .NET |
| `openjdk` o `temurin` | stub PE con payload appeso, overlay grandi su file legittimi | MSVC più bundling |
| `nodejs` | binario singolo molto grande, V8 | MSVC |
| `golang` | toolchain Go ufficiale, distinta dai 16 compilati in proprio | Go |
| `ruby`, `php`, `julia`, `r` | interpreti, molte DLL, toolchain varie | MinGW e MSVC |
| `qt` o un'applicazione Qt | MSVC recente, CFG attivo, molte DLL | MSVC |

⚠️ **Esclusi per principio:**

- **gli strumenti di reverse engineering**, compresi quelli installati nella VM FLARE.
  Molti sono impacchettati davvero: eseguibili congelati con PyInstaller (che è un wrapper
  autoestraente), utility compresse con UPX, strumenti .NET offuscati. Etichettarli
  `clean` produrrebbe falsi allarmi inesistenti, cioè veri positivi mascherati;
- **gli installer e gli SFX**, cioè i file `*setup*.exe`, `*install*.exe`, `unins*` e gli
  archivi autoestraenti. Un installer **è** packed per la definizione operativa, quindi la
  sua segnalazione è un vero positivo e non un falso allarme;
- **gli archivi il cui digest a monte non è pubblicato o non si verifica**, con il numero
  di progetti caduti per questo motivo registrato nel referto;
- **i binari con protezione del produttore** (licensing, DRM): non si etichettano `clean`,
  si registrano a parte come fuori perimetro.

### 4.2 Dimensione

Attesa: almeno 150 file PE, da almeno sei pacchetti e quattro toolchain distinte.
⚠️ **Non è una condizione di arresto.** La misura si riporta con i file che l'elenco del
§4.1 produce, quale che sia il numero. Non si aggiungono pacchetti dopo aver visto i
risultati, e non si rimuovono quelli che producono segnalazioni.

## 5. Il rilevatore congelato

Nessuna modifica a `scripts/header_elf_lief.py`, a `config/` o alle soglie fra la
registrazione di questo protocollo e la pubblicazione del risultato.

- commit di registrazione: `________` (annotare subito dopo il commit)
- `WEAK_SIGNALS_REQUIRED = 3`, `EP_ENTROPY_THRESHOLD = 7.0`, `CAPA_MODE = "off"`, deep
  scan disattivato
- versioni: LIEF 1.0.0, DIE 3.21, YARA 4.5.4 con YARA-Forge, Python 3.13.13

## 6. Le misure da produrre, nella forma decisa adesso

### 6.1 Tabella per pacchetto

| progetto | toolchain | file PE | digest verificato | segnalati | a 2 deboli | max deboli |
|---|---|---|---|---|---|---|

### 6.2 Riga aggregata

Numero di file puliti indipendenti, numero di segnalati, e il limite superiore al 95 %
calcolato come per la misura interna: con zero eventi su *n* file il limite è
`1 - 0.05^(1/n)`, cioè circa `3/n`. La formula è fissata qui per non scegliere dopo aver
visto l'esito.

### 6.3 Il margine, non solo il verdetto

La colonna «a 2 deboli» è il dato interessante anche con zero segnalati: misura quanto il
materiale estraneo sta vicino al confine. Riferimento interno verificato il 21/10/2026:
164 puliti su 3.435 stanno a due segnali deboli, e dei 1.383 ammessi dopo il congelamento
ne sono 16.

## 7. Ipotesi registrate prima del run

1. **Segnalati sotto l'1 %.** Base: nessuno dei 1.383 puliti ammessi dopo il congelamento
   ha raggiunto il verdetto positivo, e nessuno dei 3.435 ha mai alzato un segnale forte.
2. **File a due segnali deboli fra l'1 % e il 10 %.** Base: 1,2 % sui 1.383 ammessi dopo,
   4,8 % sull'intera classe negativa, 6 su 16 sui binari Go compilati in proprio.
3. **I binari Free Pascal non vengono segnalati.** È la previsione più esposta: se
   l'eccezione Delphi è stata scritta troppo stretta, qui si vede.
4. **Il caso .NET con bundle è quello a rischio più alto**, perché unisce pochi import,
   header CLR e un payload compresso.

Se un'ipotesi è smentita, si riporta smentita. Una previsione sbagliata registrata in
anticipo vale più di una previsione giusta scritta dopo.

## 8. Regole di interpretazione, decise prima di vedere i numeri

1. ⚠️ **Se escono falsi allarmi, quel numero è il risultato.** Non si modificano regola,
   soglie o eccezioni per farli sparire. Nel momento in cui lo si fa, questo insieme
   diventa materiale di calibrazione e la misura perde ogni valore.
2. **Unica eccezione ammessa, e vincolata:** la correzione di un'etichetta sbagliata. Se
   l'ispezione manuale di un file segnalato mostra che è **davvero** packed (installer
   sfuggito al filtro del §4.1, protezione del produttore, eseguibile congelato),
   l'etichetta si corregge, ma solo con giustificazione scritta nel referto, e il numero di
   queste correzioni si riporta accanto al risultato. È la distinzione già usata nel primo
   giro, dove 23 falsi positivi erano 16 correzioni alla regola e 7 etichette sbagliate:
   qui le prime sono vietate e le seconde sono contate.
3. **Se le segnalazioni si concentrano su una toolchain**, è un limite misurato del
   rilevatore e va scritto nei limiti dichiarati, non sanato allargando un'eccezione.
4. **Zero non diventa «nessun falso positivo»**: si scrive come limite superiore, con la
   sua confidenza e il suo *n*.

## 9. Esecuzione, in sequenza

1. commit di questo file e del suo emendamento; commit di registrazione `a699d63`;
2. aggiungere i progetti del §4.1 alla lista `SOURCES` di `fetch_goodware_non_ms.py`, con
   l'URL ufficiale e la pagina del digest;
3. scaricare nella cartella nuova, tenuta separata da tutte le altre:
   `python scripts/fetch_goodware_non_ms.py --dest "E:\DATASET\01_LABEL_CERTA\holdout_clean_2026_10" --only <nomi>`
   Lo script verifica il digest dell'archivio, estrae i PE e scrive `manifest.csv` con
   `archive_verified`;
4. registrare i progetti caduti per digest assente o non verificato;
5. etichettare con un file di label proprio, `config/holdout_clean_labels.json`, con la
   stessa forma di `goodware_non_ms_labels.json` e `source = dist-ufficiale-holdout`.
   ⚠️ `fetch_goodware_non_ms.py` sovrascrive sempre `config/goodware_non_ms_labels.json`:
   dopo ogni fetch, copiare il file generato e ripristinare l'originale da git;
6. ⚠️ **non importare queste voci in `ground_truth.json`.** Sarebbero conteggiate da
   `validate_phase1.py` nella matrice globale, portando i TN da 3.435 a oltre 3.500 e
   cambiando i numeri del Capitolo 4: è la stessa separazione dalle metriche principali
   che il §3.3 di `05_protocollo_validazione_esterna.md` impone al dataset esterno.
   L'oracolo resta documentato dal manifest e dal file di label. Non essendo in ground
   truth, le righe risultano `unmatched` per `validate_phase1.py`, che è il comportamento
   voluto;
7. deduplicare per SHA-256 contro `ground_truth.json` e registrare quanti file sono stati
   scartati perché già presenti;
8. eseguire la Fase 1 **solo** su quella cartella;
9. contare i segnalati filtrando il CSV per `Dataset = holdout_clean_2026_10`: non serve
   nessuna label, perché per costruzione tutti i file sono puliti;
10. produrre le tabelle del §6, senza altre analisi.

## 10. Come va scritto in tesi

Sezione propria del Capitolo 6, mai sommata alla matrice interna. La formulazione, fissata
qui:

> Su *n* binari puliti raccolti dopo il congelamento della regola, da *k* pacchetti e *m*
> toolchain non rappresentate nel corpus interno, il rilevatore ha segnalato *x* file.
> Questo è l'unico tasso di falsi allarmi di questo lavoro misurato su materiale che non ha
> avuto parte nella taratura.

Va dichiarato anche il limite della sorgente: i pacchetti provengono da una sola
infrastruttura di distribuzione, quindi l'indipendenza è rispetto alla **taratura della
regola**, non rispetto al canale di provenienza.

Nel Capitolo 3 non cambia nulla: §3.2 dichiara dove la regola è stata tarata, e questa
misura è una delle prove indipendenti che quel paragrafo rinvia al Capitolo 6.

## 10bis. Esito del run, 21 ottobre 2026

Fase 1 eseguita sulla sola cartella `holdout_clean_2026_10`, rilevatore congelato come al
§5, nessuna modifica fra la registrazione del protocollo e questa misura.

### Tabella per progetto (§6.1)

| progetto | toolchain | file PE | digest verificato | segnalati | segnali forti | a 2 deboli | max deboli |
|---|---|---|---|---|---|---|---|
| temurin | MSVC, bundling Adoptium | 127 | sì | **0** | 0 | 14 | 2 |
| dotnet_sdk | Roslyn, bundle .NET | 162 | sì | **0** | 0 | 6 | 2 |
| golang | Go | 10 | sì | **0** | 0 | 0 | 0 |
| nodejs | MSVC | 1 | sì | **0** | 0 | 1 | 2 |
| **totale** | | **300** | sì | **0** | **0** | **21** | **2** |

### Riga aggregata (§6.2)

300 binari puliti indipendenti, **0 segnalati**, limite superiore al 95 % pari a
**0,994 %** con la formula fissata al §6.2 (la regola del tre dà 1,00 %). Nessun segnale
forte è scattato su nessuno dei 300, compresi i 162 assembly gestiti: il ripiego .NET, che
è il segnale forte più esposto al falso allarme sul codice managed, non è scattato mai.

### Il margine (§6.3), che è il risultato più informativo

21 file su 300 stanno a due segnali deboli, il 7,0 %, contro il 4,8 % della classe
negativa interna e l'1,2 % dei 1.383 ammessi dopo il congelamento. Nessun file arriva a
tre. La composizione di quei 21 è omogenea:

| coppia di segnali | file |
|---|---|
| euristica DIE + numero import basso | 15 |
| euristica DIE + nomi sezione non standard | 6 |

**Tutti e 21 coinvolgono l'euristica DIE**, che da sola scatta su **62 dei 300**, cioè un
file pulito su cinque. È la stessa dipendenza misurata in casa, dove 162 dei 164 file a due
segnali deboli dipendono da quella euristica: il corpus indipendente la riproduce. Da
scrivere come affermazione sostenuta da due misure su materiale diverso, non come
osservazione incidentale.

Due controlli secondari. Le tre esenzioni sul conteggio degli import hanno tenuto: 40 file
hanno meno di venti import e nessuno di essi ha raccolto un terzo segnale. E lo YARA
generico o anti-analisi scatta su **97 dei 300** puliti, il 32 %, contro il 15 % misurato
sui puliti interni: conferma indipendente della scelta di registrarlo in
`Info_Signals` senza contarlo.

### Esito delle ipotesi del §7

| ipotesi | previsione | esito |
|---|---|---|
| 1 | segnalati sotto l'1 % | **confermata**, 0 % |
| 2 | fra l'1 % e il 10 % a due deboli | **confermata**, 7,0 % |
| 3 | i binari Free Pascal non vengono segnalati | **non messa alla prova** (§11) |
| 4 | il caso .NET è quello a rischio più alto | **smentita**: `dotnet_sdk` sta a 3,7 % di file a due segnali, `temurin` a 11,0 %. Il JDK è più vicino al confine del .NET |

Nessuna correzione di etichetta è stata necessaria, perché nessun file è stato segnalato,
quindi la clausola 2 del §8 non è stata usata. Nessuna modifica a regola, soglie o
eccezioni dopo la misura.

## 11. Restrizioni dichiarate

Da compilare **prima** del run. Qualunque restrizione aggiunta dopo l'esecuzione va
riportata come deviazione, con la data.

- **21/10/2026, prima del run: nessuna toolchain Delphi o Free Pascal nell'insieme
  indipendente.** Lazarus e FPC si distribuiscono solo come installer, e un installer è
  packed per la definizione operativa, quindi non può entrare nella classe negativa. Di
  conseguenza l'ipotesi 3 del §7 **non viene messa alla prova** da questo run: l'eccezione
  sui nomi di sezione Delphi resta verificata solo sul corpus interno, e questo va scritto
  fra i limiti del Capitolo 6.
- **21/10/2026, prima del run: si ammettono solo i progetti che pubblicano un digest in
  forma leggibile da uno script.** È un criterio di costo, non di merito, e fa cadere i
  progetti che pubblicano solo firme PGP.
- **21/10/2026, prima della Fase 1: tetto di 300 file sull'insieme.** L'SDK .NET da solo
  ha prodotto 3.190 PE su 3.328 scaricati, quindi senza un tetto la misura sarebbe stata
  una misura su quel solo archivio. La regola, applicata **prima** di eseguire la Fase 1 e
  quindi prima di conoscere qualunque verdetto, è una quota uguale per progetto alzata
  fino al budget (*water filling*), con campionamento deterministico a seme fisso
  (20261021) nei progetti che sfondano la quota. Esito: `temurin` 127, `dotnet_sdk` 162,
  `golang` 10, `nodejs` 1. I 3.028 file in eccesso non sono stati cancellati ma spostati
  in `holdout_clean_2026_10_excess`, e la selezione è registrata in `selection.csv` e
  `selection.json` dentro la cartella misurata. È un criterio di dimensione, non di esito.
- **21/10/2026, prima del run: PHP e Julia non sono nell'insieme.** Il resolver di PHP ha
  fallito al primo tentativo e Julia non ha prodotto alcun PE dall'archivio ufficiale.
  Conseguenza da dichiarare in tesi: i 300 file vengono da **quattro** progetti, e due di
  essi (`dotnet_sdk` e `temurin`) ne coprono 289, quindi l'insieme è indipendente rispetto
  alla taratura ma non ampio quanto a varietà di toolchain.
