# Stato dell'arte e riferimenti esterni

**Documento di riferimento. Redatto il 13 ottobre 2026.**

Esiste perché è l'unico blocco della tesi che non ha materiale negli altri documenti di progetto:
il piano dei contenuti lo dice esplicitamente del §2.4 — *«this is the only section with no material
in your documents. It needs reading, and it is the section an examiner is most likely to probe»*.
Qui dentro ci sono i lavori pre-esistenti, gli strumenti professionali usati con la loro
provenienza, e la collocazione di questo lavoro rispetto a entrambi.

**Regola di questo documento.** Ogni voce ha una fonte verificata su dblp, sull'editore o sul
repository ufficiale, oppure è marcata con ⚠️. Nessuna citazione scritta a memoria: una voce
bibliografica sbagliata in sede di discussione costa più di una voce mancante.

---

## Indice

1. [Blocco A — rilevamento a firme, e perché degrada](#1-blocco-a--rilevamento-a-firme-e-perché-degrada)
2. [Blocco B — entropia e statistica, e i suoi falsi positivi](#2-blocco-b--entropia-e-statistica-e-i-suoi-falsi-positivi)
3. [Blocco C — machine learning, e cosa richiede che qui non c'è](#3-blocco-c--machine-learning-e-cosa-richiede-che-qui-non-cè)
4. [Blocco D — dove si colloca questo lavoro](#4-blocco-d--dove-si-colloca-questo-lavoro)
5. [Unpacking automatico: lo stato dell'arte](#5-unpacking-automatico-lo-stato-dellarte)
6. [Gli strumenti usati, con versione e provenienza](#6-gli-strumenti-usati-con-versione-e-provenienza)
7. [I rilevatori pre-esistenti citati nei protocolli](#7-i-rilevatori-pre-esistenti-citati-nei-protocolli)
8. [BibTeX pronto da incollare](#8-bibtex-pronto-da-incollare)
9. [Bozza di §2.4 in inglese](#9-bozza-di-24-in-inglese)
10. [Cosa resta da decidere](#10-cosa-resta-da-decidere)

---

## 1. Blocco A — rilevamento a firme, e perché degrada

**L'inquadramento del problema** si cita da Guo, Ferrie e Chiueh [`guo2008`]: è il lavoro che
formula il *packer problem* come problema di analisi e ne classifica le soluzioni, ed è già nella
bibliografia. La complessità reale dei packer in circolazione — strati, anti-analisi, scrittura
incrementale della memoria — è misurata longitudinalmente da Ugarte-Pedrero et al. [`ugarte2015`],
anch'esso già presente: è la fonte da usare ogni volta che serve affermare che i packer moderni non
sono tutti UPX.

**Perché le firme degradano.** Il meccanismo è quello che la Fase 1 misura su VMProtect a 32 bit: le
firme cercano costanti strutturali — nomi di sezione, byte all'entry point — e un protector che le
randomizza le annulla. In letteratura il punto è documentato da due direzioni:

- Alkhateeb, Ghorbani e Habibi Lashkari [`alkhateeb2023`] passano in rassegna i packer run-time e le
  tecniche di mitigazione lato motore AV, e trattano esplicitamente il decadimento dei metodi a
  firma sui packer moderni. È la rassegna più recente e la citazione più economica per questo blocco;
- Zhong et al. [`zhong2026`] ⚠️ *(preprint)* fanno validazione semantica di **undici** strumenti di
  identificazione open source e sei proprietari di VirusTotal, usando gli unpacker come contratto
  eseguibile: se uno strumento dichiara una famiglia, l'unpacker corrispondente deve riuscire a
  recuperare contenuto analizzabile. Riportano che correzioni mirate alla logica decisionale
  aumentano la copertura di identificazione **fino al 58,6 %**, e descrivono Detect It Easy come
  combinazione di *signature matching* e regole euristiche leggere su import, sezioni e API.

> **Perché quest'ultimo conta per noi.** È lo stesso ragionamento del nostro oracolo di correttezza,
> applicato all'identificazione invece che all'unpacking: una dichiarazione vale quanto la verifica
> che la sostiene. Va citato nel §2.4 e **richiamato** nel capitolo della Fase 2, perché rafforza
> l'argomento contro il criterio «il disassemblatore approva».

**Il verso opposto, da non omettere.** Le firme non sono un vicolo cieco: PackGenome
[`packgenome2023`] genera automaticamente regole YARA robuste per il riconoscimento dei packer e si
confronta con le collezioni pubbliche di firme e con gli strumenti di generazione automatica
esistenti. Serve a mostrare che la scelta di questo lavoro — non migliorare le firme, ma misurare
quanto valgono accanto all'evidenza strutturale — è una scelta fra alternative vive, non l'unica
strada disponibile.

---

## 2. Blocco B — entropia e statistica, e i suoi falsi positivi

**L'origine.** Lyda e Hamrock [`lyda2007`] introducono l'analisi dell'entropia per individuare
malware cifrato e compresso: è il lavoro che tutti citano e la base della scala 0–8 e delle bande
empiriche usate nel capitolo di terminologia. La nozione di entropia è di Shannon [`shannon1948`].

**La versione statistica.** Sono due lavori distinti e vanno tenuti separati: diversi motori di
ricerca e aggregatori li descrivono con lo stesso abstract, ed è un errore in cui è facile cadere.
Perdisci, Lanzi e Lee [`perdisci2008`] usano classificatori statistici per decidere **se** un
eseguibile è compresso, allo scopo di instradare verso il rilevamento costoso solo i file che lo
richiedono: è lo stesso ruolo architetturale del filtro di questa tesi, formulato nel 2008. Sun,
Versteeg, Boztaş e Yann [`sun2010`] costruiscono invece profili di casualità per classificare
**quale** packer è stato applicato, su un insieme che comprende 17.336 campioni di malware reale,
con efficacia dichiarata oltre il 99 %.

**I modi di falso positivo, che sono il punto del blocco.** Qui la letteratura dice esattamente
quello che i nostri documenti hanno misurato in casa, e la convergenza va sfruttata:

- **entropia alta senza packing.** È il caso delle risorse già compresse e delle informazioni di
  debug compresse dei binari Go, misurato nel progetto e corretto escludendo `.rsrc` dal calcolo che
  alimenta il segnale. In letteratura è la critica classica all'uso dell'entropia come criterio
  singolo, raccolta in [`alkhateeb2023`];
- **packing senza entropia alta**, che è la metà più interessante e la meno citata: Mantovani et al.
  [`mantovani2020`] misurano la prevalenza degli schemi di packing **a bassa entropia**
  nell'ecosistema malware e riportano che, preso un campione malware con entropia inferiore a sette,
  **la probabilità che sia comunque compresso con uno schema a bassa entropia è del 35,6 %**.

> **Come si usa in tesi.** [`mantovani2020`] è la giustificazione bibliografica dell'architettura a
> due livelli: se l'entropia da sola sbaglia in **entrambe** le direzioni, un rilevatore che la usa
> come indizio debole fra altri — e che richiede tre indizi concordanti — non è una complicazione
> gratuita. Ed è anche il riferimento onesto da mettere accanto al nostro unico falso negativo del
> dataset esterno (`amber_SmartDefragBootTime.exe`: entropia 6,63, nessuna compressione osservabile),
> che è precisamente un caso di packing a bassa entropia.

---

## 3. Blocco C — machine learning, e cosa richiede che qui non c'è

**Lo stato dell'arte.** Biondi et al. [`biondi2019`] etichettano oltre 280.000 campioni con tre
tecniche diverse ed estraggono entropia, byte all'entry point, import, metadati, risorse e sezioni
per addestrare classificatori di rilevamento e classificazione del packing. Bertrand Van Ouytsel et
al. [`bertrand2021`] confrontano **undici** approcci di machine learning su **119** feature,
chiedendosi quali feature contino, quale algoritmo renda di più e quale costi meno.

**Cosa richiedono, che questo lavoro non ha.** Tre cose, e vanno scritte come requisiti e non come
difetti:

1. un **insieme di addestramento** etichettato di dimensione adeguata — i lavori sopra stanno fra
   10^4 e 10^5 campioni, contro i 3.813 etichettati di questo lavoro, la cui ground truth è però
   garantita per costruzione e non per inferenza;
2. un **punteggio continuo**, che è ciò che rende possibile una curva ROC/PR e la scelta a posteriori
   di un punto di lavoro. L'uscita di questo lavoro è binaria, limite già dichiarato;
3. la **separazione fra ciò che il modello impara e ciò che si vuole misurare**, che è il punto
   critico: Aghakhani et al. [`aghakhani2020`] mostrano i limiti dei classificatori basati su feature
   statiche in presenza di packing, cioè che un classificatore addestrato su campioni compressi può
   finire a riconoscere **il packer** invece della proprietà di interesse.

> **Come si usa in tesi.** [`aghakhani2020`] non serve a dire «il machine learning non funziona».
> Serve a dire perché questo lavoro è *a regole*: un rilevatore a due livelli espone quale segnale ha
> deciso e consente di attribuire il merito a firme o struttura separatamente, che è l'oggetto della
> seconda domanda di ricerca e che un classificatore con 119 feature non concede. La rivendicazione
> corretta è **verificabilità e auditabilità**, non prestazione superiore.

---

## 4. Blocco D — dove si colloca questo lavoro

### 4.1 I tre precedenti più vicini, da citare e non da scoprire in sede d'esame

**(a) Il segnale «stub strutturale» ha un precedente esplicito.** Han, Lee e Lee [`han2009`]
rilevano file PE compressi combinando **l'entropia della sezione dell'entry point** con la
**proprietà di scrittura** di quella sezione. È, nella sostanza, il segnale forte che nel nostro
rilevatore ha intercettato i 23 VMProtect a 32 bit. Il gruppo packing-box ne distribuisce
un'implementazione sotto il nome **REMINDer**, e la attribuisce a quel paper.

> **Conseguenza per la tesi, da scrivere e non da aggirare.** La novità rivendicabile **non** è il
> segnale: è (i) la sua composizione in una regola a due livelli in cui una prova dimostrativa non
> viene diluita in una somma di indizi, (ii) il ripiego per gli assembly .NET, che per costruzione
> hanno `AddressOfEntryPoint = 0` e sui quali la forma primaria non può scattare, e (iii) la
> misurazione separata del contributo di firme e struttura su etichette a oracolo costruttivo.
> Rivendicare il segnale come originale sarebbe falso e verificabile in trenta secondi da un
> esaminatore che conosce REMINDer.

**(b) L'anomaly detection strutturale.** Ugarte-Pedrero et al. [`ugarte2011`] usano feature
strutturali del PE per identificare eseguibili compressi come problema di rilevamento di anomalie, e
si dichiarano il primo rilevatore di packing costruito su quell'impostazione: rappresentano gli
eseguibili **non** compressi come vettori di informazione strutturale e valori euristici. È il
precedente diretto dell'idea che la struttura, e non la firma, possa portare il verdetto — e
l'inversione del punto di vista (modellare la classe pulita) è anche il motivo per cui qui la classe
negativa è stata costruita con cinque oracoli invece di essere assunta.

**(c) Il filtro statico come precedente architetturale.** Jacob et al. [`jacob2013`] costruiscono un
filtro statico **agnostico rispetto al packer** per individuare varianti simili di malware: è lo
stesso ruolo architetturale — un filtro economico davanti al lavoro costoso — su un obiettivo
diverso.

### 4.2 La collocazione, in una frase

Un rilevatore **a regole** i cui due livelli sono misurabili separatamente, costruito per essere
**auditabile** e non ottimale, validato su una ground truth stabilita per costruzione e su un corpus
pubblico di terzi sotto un protocollo congelato prima dell'esecuzione, con il contributo di firme e
struttura quantificato invece che asserito.

### 4.3 Il dataset esterno viene dagli stessi autori dei rilevatori: è l'argomento di circolarità

Il corpus `packing-box/dataset-packed-pe` usato nella validazione esterna è prodotto dal gruppo
packing-box [`dhondt2023`], gli stessi autori di [`bertrand2021`] e co-autori di [`biondi2019`], e
la loro piattaforma include i rilevatori statici open source con cui la metà `not-packed` è stata
ripulita. Questo è esattamente ciò che il nostro protocollo (`05_protocollo_validazione_esterna.md`
§3.2) dichiara come causa del divieto di calcolarne precision e tasso di falsi positivi, e fino a
oggi era affermato **senza riferimento**. Ora ha la sua citazione, e con essa il paragrafo di
validazione esterna diventa difendibile: la contaminazione non è un sospetto generico, è una
proprietà documentata della provenienza del corpus.

---

## 5. Unpacking automatico: lo stato dell'arte

Serve al capitolo della Fase 2, non al §2.4, ma si raccoglie qui per non cercarlo due volte.

| lavoro | idea | rapporto con questo lavoro |
|---|---|---|
| PolyUnpack [`royal2006`] | confronto fra la sequenza statica attesa e quella eseguita: il codice che compare solo a run-time è il payload | primo unpacker generico; costoso |
| Renovo [`kang2007`] | «scrivi-poi-esegui»: il payload è dove il programma ha scritto e poi eseguito | **è l'euristica OEP implementata in Qiling nella nostra Fase 2** |
| OmniUnpack [`martignoni2007`] | stessa idea a granularità di pagina, con protezione della memoria: molto più veloce | motiva perché un'euristica di questo tipo è praticabile in batch |
| rassegna [`alkhateeb2023`] | tassonomia di packer e mitigazioni, con il ciclo di vita lato AV | inquadramento del capitolo |
| rassegna ACM CSUR [`csur2022`] | il packing dal punto di vista del malware: 23 metodi di rilevamento e classificazione passati in rassegna, più statistiche d'uso dei packer su 24.000 file PE in dieci anni | la rassegna più ampia; le statistiche d'uso servono a sostenere la frase «la maggioranza dei binari di un corpus reale non è compressa» |

> **Da dichiarare nel capitolo Fase 2:** l'euristica di Qiling non è originale — è Renovo. Ciò che è
> nostro sono i due filtri contro i falsi allarmi (`QILING_OEP_WARMUP_BLOCKS = 200`,
> `QILING_MIN_WRITTEN_BYTES = 4096`) e **l'oracolo che verifica il risultato**, che in quei lavori non
> c'è: la correttezza vi è stabilita dall'ispezione o dal fatto che il campione «si analizza», che è
> il criterio che il nostro §6 confuta.

---

## 6. Gli strumenti usati, con versione e provenienza

Versioni come fissate nel protocollo della Fase F (`07_protocollo_fase2_esterna.md` §4).

### Fase 1 — triage statico

| strumento | versione | natura | provenienza |
|---|---|---|---|
| **LIEF** | 1.0.0 | libreria di parsing dei formati eseguibili | Quarkslab, `lief-project/LIEF` |
| **Detect It Easy (DIE)** | 3.21 | database di firme più euristiche leggere, CLI `diec.exe` | `horsicq/Detect-It-Easy` |
| **YARA** | 4.5.4 | motore di regole su byte grezzi | VirusTotal, `VirusTotal/yara` |
| **YARA-Forge** | pacchetto *full* | raccolta curata di regole pubbliche | `YARAHQ/yara-forge` |
| **capa** | 9.4.0 | rilevamento di capability su regole | Mandiant FLARE, `mandiant/capa` — **disattivato**, misura in `01 §5` |
| **pefile** | 2024.8.26 | parsing PE in Python | Ero Carrera, `erocarrera/pefile` |

### Fase 2 — cascata di unpacking

| strumento | versione | natura | provenienza |
|---|---|---|---|
| **UPX** | 5.1.1 | packer *e* unpacker ufficiale della propria famiglia | `upx/upx` |
| **7-Zip** | 26.00 | estrattore di archivi; risolve gli SFX NSIS | `7-zip.org` |
| **innounp** | 0.50 | estrattore Inno Setup; la pagina ufficiale dichiara il supporto da IS 2.0.7 a **6.1.2** | `innounp.sourceforge.net` |
| **innoextract** | 1.9 | estrattore Inno Setup, limite dichiarato fino alla 6.0.5 | `constexpr.org/innoextract` |
| **AspackDie** | — | unpacker dedicato ASPack 2000–2.12, solo interfaccia grafica | strumento storico |
| **Unipacker** | 1.0.8 | emulazione PE a 32 bit con firme dei packer classici | `unipacker/unipacker` |
| **Qiling** | 1.4.11 | framework di emulazione di sistema, costruito su Unicorn | `qilingframework/qiling` |
| **Unicorn** | 2.1.3 | emulatore di CPU | `unicorn-engine/unicorn` |
| **mal_unpack** | — | unpacking per esecuzione reale — **disattivato** | hasherezade, `hasherezade/mal_unpack` |
| **Ghidra** | 12.0.4 | disassemblatore headless, verifica automatica | NSA, `NationalSecurityAgency/ghidra` |
| **IDA Free** | 9.4 | disassemblatore interattivo, ultima risorsa | Hex-Rays |

### Packer usati come strumenti per costruire il corpus

| packer | ruolo nella matrice | natura |
|---|---|---|
| **UPX** | compressore, 44 campioni | libero |
| **MPRESS** | compressore, 50 | freeware, MATCODE |
| **NSIS** | installer/SFX, 53 | libero |
| **Inno Setup** | installer, 53 — versione 6.7.0, fuori portata di ogni estrattore libero | libero |
| **Themida** | protector con virtualizzazione, 53 | commerciale, Oreans |
| **VMProtect** | protector con virtualizzazione, 48 (v3.10.6) | commerciale |

> I packer **non** inseribili nella matrice sono già documentati: ASPack senza interfaccia a riga di
> comando, Enigma non reperibile, PECompact solo PE32 con licenza di prova scaduta. Va detto come
> vincolo del corpus, separando «senza CLI» da «provenienza non citabile».

### Infrastruttura

Python 3.13.13 · `scikit-learn` e `pandas` (solo per gli split del dataset builder) · Go e Rust con
le toolchain elencate in `Build_Samples/README.md` per i binari puliti compilati in proprio.

---

### BibTeX degli strumenti

Convenzione: `@misc` con `howpublished = {\url{...}}` e la versione nel `note`. Richiede
`\usepackage{url}` o `hyperref`. Data di consultazione: 14 ottobre 2026. Dove l'autore non e'
attribuibile con certezza il campo e' omesso di proposito.

```bibtex
@misc{tool:lief,
  author = {Quarkslab},
  title = {{LIEF}: Library to Instrument Executable Formats},
  howpublished = {\url{https://lief.re/}},
  note = {version 1.0.0; accessed 14 October 2026}
}

@misc{tool:die,
  author = {horsicq},
  title = {{Detect It Easy}},
  howpublished = {\url{https://github.com/horsicq/Detect-It-Easy}},
  note = {version 3.21, command line interface \texttt{diec}; accessed 14 October 2026}
}

@misc{tool:yara,
  author = {VirusTotal},
  title = {{YARA}: The Pattern Matching Swiss Knife for Malware Researchers},
  howpublished = {\url{https://github.com/VirusTotal/yara}},
  note = {version 4.5.4; accessed 14 October 2026}
}

@misc{tool:yaraforge,
  author = {{YARA}{HQ}},
  title = {{YARA}-Forge: Curated {YARA} Rule Packages},
  howpublished = {\url{https://github.com/YARAHQ/yara-forge}},
  note = {full package; accessed 14 October 2026}
}

@misc{tool:capa,
  author = {{Mandiant FLARE Team}},
  title = {{capa}: Automatically Identify Malware Capabilities},
  howpublished = {\url{https://github.com/mandiant/capa}},
  note = {version 9.4.0; present but disabled in the measured configuration; accessed 14 October 2026}
}

@misc{tool:pefile,
  author = {Carrera E.},
  title = {{pefile}: Portable Executable Reader Module},
  howpublished = {\url{https://github.com/erocarrera/pefile}},
  note = {version 2024.8.26; accessed 14 October 2026}
}

@misc{tool:upx,
  author = {Oberhumer M. F. X. J. and Moln\'ar L. and Reiser J. F.},
  title = {{UPX}: the Ultimate Packer for e{X}ecutables},
  howpublished = {\url{https://upx.github.io/}},
  note = {version 5.1.1; used both as a packer and as the reference unpacker of its own family; accessed 14 October 2026}
}

@misc{tool:sevenzip,
  author = {Pavlov I.},
  title = {{7-Zip}},
  howpublished = {\url{https://www.7-zip.org/}},
  note = {version 26.00; accessed 14 October 2026}
}

@misc{tool:innounp,
  title = {{innounp}, the {Inno Setup} Unpacker},
  howpublished = {\url{https://innounp.sourceforge.net/}},
  note = {version 0.50; the official page declares support for Inno Setup 2.0.7 to 6.1.2; accessed 14 October 2026}
}

@misc{tool:innoextract,
  author = {Scharrer D.},
  title = {{innoextract}: A Tool to Unpack Installers Created by {Inno Setup}},
  howpublished = {\url{https://constexpr.org/innoextract/}},
  note = {version 1.9; declares support for Inno Setup 1.2.10 to 6.0.5; accessed 14 October 2026}
}

@misc{tool:aspackdie,
  title = {{AspackDie}},
  howpublished = {\url{https://www.aldeid.com/wiki/AspackDie}},
  note = {legacy unpacker for ASPack 2000--2.12; no official upstream distribution point; graphical only, invoked with a timeout; accessed 14 October 2026}
}

@misc{tool:unipacker,
  author = {{Unipacker Project}},
  title = {{unipacker}: Automatic and Platform-Independent Unpacker for {Windows} Binaries Based on Emulation},
  howpublished = {\url{https://github.com/unipacker/unipacker}},
  note = {version 1.0.8; covers ASPack, FSG, MEW, MPRESS, PEtite, UPX and YZPack at 32 bit; accessed 14 October 2026}
}

@misc{tool:qiling,
  author = {{Qiling Framework Project}},
  title = {{Qiling}: Advanced Binary Emulation Framework},
  howpublished = {\url{https://qiling.io/}},
  note = {version 1.4.11; accessed 14 October 2026}
}

@misc{tool:unicorn,
  author = {Nguyen A. Q. and Dang H. V.},
  title = {{Unicorn}: The Ultimate {CPU} Emulator},
  howpublished = {\url{https://www.unicorn-engine.org/}},
  note = {version 2.1.3; emulation backend of Qiling; accessed 14 October 2026}
}

@misc{tool:malunpack,
  author = {hasherezade},
  title = {{mal\_unpack}: Dynamic Unpacker Based on {PE-sieve}},
  howpublished = {\url{https://github.com/hasherezade/mal_unpack}},
  note = {disabled by default; it executes the sample and produced none of the reported results; accessed 14 October 2026}
}

@misc{tool:ghidra,
  author = {{National Security Agency}},
  title = {{Ghidra} Software Reverse Engineering Framework},
  howpublished = {\url{https://ghidra-sre.org/}},
  note = {version 12.0.4, headless mode; accessed 14 October 2026}
}

@misc{tool:idafree,
  author = {{Hex-Rays}},
  title = {{IDA Free}},
  howpublished = {\url{https://hex-rays.com/ida-free/}},
  note = {version 9.4; last resort of the cascade, manual; accessed 14 October 2026}
}
```

**Gli strumenti usati per costruire il corpus**, da citare separatamente perche' qui sono strumenti
di generazione e non di analisi:

```bibtex
@misc{tool:mpress,
  author = {{MATCODE Software}},
  title = {{MPRESS}: High-Performance Executable Packer},
  howpublished = {\url{http://www.matcode.com/mpress.htm}},
  note = {version 2.19; the vendor page is intermittently unavailable and is mirrored at \url{https://www.autohotkey.com/mpress/mpress_web.htm}; accessed 14 October 2026}
}

@misc{tool:nsis,
  author = {{NSIS Project}},
  title = {{NSIS}: Nullsoft Scriptable Install System},
  howpublished = {\url{https://nsis.sourceforge.io/}},
  note = {accessed 14 October 2026}
}

@misc{tool:innosetup,
  author = {Russell J.},
  title = {{Inno Setup}},
  howpublished = {\url{https://jrsoftware.org/isinfo.php}},
  note = {version 6.7.0, more recent than any free extractor supports; accessed 14 October 2026}
}

@misc{tool:themida,
  author = {{Oreans Technologies}},
  title = {{Themida}},
  howpublished = {\url{https://www.oreans.com/Themida.php}},
  note = {commercial protector with code virtualisation; accessed 14 October 2026}
}

@misc{tool:vmprotect,
  author = {{VMProtect Software}},
  title = {{VMProtect}},
  howpublished = {\url{https://vmpsoft.com/}},
  note = {version 3.10.6; commercial protector with code virtualisation; accessed 14 October 2026}
}
```

---

## 7. I rilevatori pre-esistenti citati nei protocolli

Sono i quattro nominati in `05_protocollo_validazione_esterna.md` §3.2 come causa del divieto di
calcolare precision sul dataset esterno. Finora erano nomi; ora hanno un'origine.

| rilevatore | che cosa fa | origine |
|---|---|---|
| **PEiD** | firme sui byte all'entry point; storico, non più mantenuto | strumento storico, reimplementato in [`dhondt2023`] |
| **Bintropy** | soglie sull'entropia a blocchi | implementazione del metodo di [`lyda2007`], `packing-box/bintropy` |
| **REMINDer** | entropia della sezione dell'entry point più il flag di scrittura | implementazione di [`han2009`], `packing-box/reminder` |
| **PyPackerDetect** | combinazione di euristiche sul PE (sezioni, import, entry point) | `packing-box/pypackerdetect` |

> **Il punto metodologico da portare in tesi.** Tre dei quattro ricadono nella stessa famiglia di
> segnali che la nostra Fase 1 valuta — entropia, sezione dell'entry point, import — e il quarto è a
> firme. Misurare falsi positivi su una classe negativa ripulita con quegli strumenti sarebbe in
> parte una tautologia: è la frase già scritta nel protocollo, che ora si può sostenere con le fonti.

---

## 8. BibTeX pronto da incollare

Stile allineato a `biblio.bib` (`author = {Cognome X., Cognome Y.}`). `guo2008` e `ugarte2015` sono
già presenti: non duplicarle.

```bibtex
@article{shannon1948,
  author = {Shannon C. E.},
  title = {A Mathematical Theory of Communication},
  journal = {Bell System Technical Journal},
  volume = {27},
  number = {3},
  pages = {379-423},
  year = {1948}
}

@article{lyda2007,
  author = {Lyda R., Hamrock J.},
  title = {Using Entropy Analysis to Find Encrypted and Packed Malware},
  journal = {IEEE Security \& Privacy},
  volume = {5},
  number = {2},
  pages = {40-45},
  year = {2007}
}

@article{perdisci2008,
  author = {Perdisci R., Lanzi A., Lee W.},
  title = {Classification of Packed Executables for Accurate Computer Virus Detection},
  journal = {Pattern Recognition Letters},
  volume = {29},
  number = {14},
  pages = {1941-1946},
  year = {2008}
}

@conference{han2009,
  author = {Han S.-W., Lee K.-G., Lee S.},
  title = {Packed PE File Detection for Malware Forensics},
  booktitle = {International Conference on Computer Science and its Applications (CSA)},
  year = {2009}
}

@conference{ugarte2011,
  author = {Ugarte-Pedrero X., Santos I., Bringas P. G.},
  title = {Structural Feature Based Anomaly Detection for Packed Executable Identification},
  booktitle = {Computational Intelligence in Security for Information Systems (CISIS)},
  series = {Lecture Notes in Computer Science},
  volume = {6694},
  pages = {230-237},
  year = {2011}
}

@conference{jacob2013,
  author = {Jacob G., Comparetti P. M., Neugschwandtner M., Kruegel C., Vigna G.},
  title = {A Static, Packer-Agnostic Filter to Detect Similar Malware Samples},
  booktitle = {Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA)},
  year = {2013}
}

@article{biondi2019,
  author = {Biondi F., Enescu M. A., Given-Wilson T., Legay A., Noureddine L., Verma V.},
  title = {Effective, Efficient, and Robust Packing Detection and Classification},
  journal = {Computers \& Security},
  volume = {85},
  pages = {436-451},
  year = {2019}
}

@conference{aghakhani2020,
  author = {Aghakhani H., Gritti F., Mecca F., Lindorfer M., Ortolani S., Balzarotti D., Vigna G., Kruegel C.},
  title = {When Malware is Packin' Heat; Limits of Machine Learning Classifiers Based on Static Analysis Features},
  booktitle = {Network and Distributed System Security Symposium (NDSS)},
  year = {2020}
}

@conference{mantovani2020,
  author = {Mantovani A., Aonzo S., Ugarte-Pedrero X., Merlo A., Balzarotti D.},
  title = {Prevalence and Impact of Low-Entropy Packing Schemes in the Malware Ecosystem},
  booktitle = {Network and Distributed System Security Symposium (NDSS)},
  year = {2020}
}

@misc{bertrand2021,
  author = {Bertrand Van Ouytsel C.-H., Given-Wilson T., Minet J., Roussieau J., Legay A.},
  title = {Analysis of Machine Learning Approaches to Packing Detection},
  howpublished = {arXiv preprint arXiv:2105.00473},
  year = {2021}
}

@article{alkhateeb2023,
  author = {Alkhateeb E., Ghorbani A., Habibi Lashkari A.},
  title = {A Survey on Run-Time Packers and Mitigation Techniques},
  journal = {International Journal of Information Security},
  volume = {23},
  number = {2},
  pages = {887-913},
  year = {2023}
}

@misc{dhondt2023,
  author = {D'Hondt A., Bertrand Van Ouytsel C.-H., Legay A.},
  title = {Experimental Toolkit for Manipulating Executable Packing},
  howpublished = {arXiv preprint arXiv:2302.09286},
  year = {2023}
}

@misc{zhong2026,
  author = {Zhong F., Qian Z., Ren M., Jiang Y., Huang J., Pang Y., Cheng X.},
  title = {Semantic Validation of Packer Identification Tools: Characterization, Repair, and Downstream Impact},
  howpublished = {arXiv preprint arXiv:2605.25923},
  year = {2026},
  note = {preprint}
}

@conference{royal2006,
  author = {Royal P., Halpin M., Dagon D., Edmonds R., Lee W.},
  title = {PolyUnpack: Automating the Hidden-Code Extraction of Unpack-Executing Malware},
  booktitle = {Annual Computer Security Applications Conference (ACSAC)},
  year = {2006}
}

@conference{kang2007,
  author = {Kang M. G., Poosankam P., Yin H.},
  title = {Renovo: A Hidden Code Extractor for Packed Executables},
  booktitle = {ACM Workshop on Recurring Malcode (WORM)},
  year = {2007}
}

@conference{martignoni2007,
  author = {Martignoni L., Christodorescu M., Jha S.},
  title = {OmniUnpack: Fast, Generic, and Safe Unpacking of Malware},
  booktitle = {Annual Computer Security Applications Conference (ACSAC)},
  year = {2007}
}

@conference{sun2010,
  author = {Sun L., Versteeg S., Boztas S., Yann T.},
  title = {Pattern Recognition Techniques for the Classification of Malware Packers},
  booktitle = {Information Security and Privacy (ACISP)},
  series = {Lecture Notes in Computer Science},
  volume = {6168},
  pages = {370-390},
  year = {2010}
}

@article{csur2022,
  author = {Muralidharan T., Cohen A., Gerson N., Nissim N.},
  title = {File Packing from the Malware Perspective: Techniques, Analysis Approaches, and Directions for Enhancements},
  journal = {ACM Computing Surveys},
  volume = {55},
  number = {5},
  pages = {1-45},
  year = {2022},
  doi = {10.1145/3530810},
  note = {Article 108}
}

@conference{packgenome2023,
  author = {Li S., Ming J., Qiu P., Chen Q., Liu L., Bao H., Wang Q., Jia C.},
  title = {PackGenome: Automatically Generating Robust YARA Rules for Accurate Malware Packer Detection},
  booktitle = {ACM SIGSAC Conference on Computer and Communications Security (CCS)},
  pages = {3078-3092},
  year = {2023}
}
```

### Manuale di riferimento e fonti divulgative

Statuto diverso dai paper, e va dichiarato: il primo e' un libro tecnico di riferimento, gli altri
tre sono materiale divulgativo di professionisti. Si citano per **la procedura manuale che la
cascata automatizza** — cioe' a sostegno della premessa di costo del capitolo introduttivo — e non a
sostegno di un numero misurato. Verificati il 14 ottobre 2026.

```bibtex
@book{pma2012,
  author = {Sikorski M., Honig A.},
  title = {Practical Malware Analysis: The Hands-On Guide to Dissecting Malicious Software},
  publisher = {No Starch Press},
  address = {San Francisco},
  year = {2012},
  note = {Appendix C, Solutions to Labs, p.~478 ff., is the oracle for the 48 book samples in the corpus}
}

@misc{web:hackerhood2022,
  author = {Poonia R.},
  title = {Unpacking the Malwares},
  howpublished = {\url{https://hackerhood.redhotcyber.com/tutorial-di-malware-analysis-2/}},
  note = {HackerHood, Tutorial di Malware Analysis; 14 March 2022; accessed 14 October 2026}
}

@misc{web:deluks2024,
  author = {0xdeluks},
  title = {Snowy Days \& The Malware Packing Ways},
  howpublished = {\url{https://web.archive.org/web/20241215175113/https://deluks2006.github.io/posts/snowy-days-and-the-malware-packing-ways/}},
  note = {Magic Bytes blog, 15 December 2024; the original path no longer resolves, so the Internet Archive snapshot is cited; accessed 14 October 2026}
}

@misc{web:bragetti2022,
  author = {Bragetti D.},
  title = {Unpacking Malware: In Manual and Automated Ways},
  howpublished = {\url{https://medium.com/@dbragetti/unpacking-malware-685de7093e5}},
  note = {Medium, 28 August 2022; accessed 14 October 2026}
}
```

#### I writeup degli esercizi PMA: sono nella catena di etichettatura

Non sono materiale di studio: stanno nella catena di etichettatura di 38 dei 48 campioni del set
PMA. La fonte primaria e' l'**Appendice C del libro** (*Solutions to Labs*, p. 478 e seguenti), che
dichiara la natura di ciascun esercizio; i due writeup la corroborano. Misurato sul file delle label:
le 38 corroborate sono **tutte `clean`**, mentre le 6 `packed` hanno ciascuna una conferma tecnica
propria (`upx -t`, nome di sezione, DIE o YARA) e **non dipendono dai writeup**. Vanno quindi citati,
perche' sotto la regola "*not packed* richiede una verifica" sono la documentazione della meta'
negativa di quel set.

```bibtex
@misc{web:safeeval,
  author = {SafeEval},
  title = {Practical Malware Analysis: Exercise Writeups},
  howpublished = {\url{https://github.com/SafeEval/practical-malware-analysis}},
  note = {accessed 14 October 2026}
}

@misc{web:minton,
  author = {Minton J.},
  title = {Practical Malware Analysis --- Lab Write-up},
  howpublished = {\url{https://www.jaiminton.com/Tutorials/PracticalMalwareAnalysis/}},
  note = {accessed 14 October 2026}
}
```

> **Il conteggio, riconciliato il 15/10/2026.** Le "tre risorse indipendenti" che il file delle label
> citava sono l'Appendice C piu' i due writeup: la nota e' stata riscritta in questi termini su tutte
> e 38 le voci, perche' "tre risorse" senza nominarle non e' verificabile.

> **Come va descritta la catena, con precisione.** I writeup sono letture indipendenti **dello stesso
> esercizio**, non misure indipendenti: la formulazione corretta e' *cross-checked against independent
> published writeups*, non *verified independently*. E in bibliografia si cita **il libro**, con
> editore e appendice, non una copia PDF ospitata da terzi: il PDF non e' un'edizione citabile e la
> sua presenza online non e' autorizzata.

> **Due avvertenze d'uso.** (1) `pma2012` non e' solo una fonte di metodo: e' **l'oracolo** dei 48
> campioni del libro nel corpus, perche' l'appendice dichiara la natura di ciascuno, ed e' la fonte
> del punto cieco residuo delle firme (`Lab18-02`, un FSG che ne' DIE ne' YARA nominano). Oggi quella
> riga della tabella degli oracoli non ha citazione: va aggiunta. (2) Le tre fonti divulgative
> descrivono l'unpacking **manuale** con debugger e breakpoint di memoria. E' esattamente il lavoro
> che la Fase 2 riduce, quindi il loro posto e' accanto alla frase sul costo dell'intervento umano e
> accanto all'ultimo gradino della cascata; non vanno usate per sostenere una proprieta' del
> rilevatore, per la quale esistono le fonti peer-reviewed dei paragrafi precedenti.

**Stato delle verifiche: chiuso il 13 ottobre 2026.** Tutte e 19 le voci sopra hanno autori, sede e
anno verificati sull'editore, sulla pagina degli autori o su dblp; nessuna resta marcata. I DOI,
se il relatore li vuole nel campo `note`: `10.1007/978-3-642-14081-5_23` (sun2010),
`10.1145/3530810` (csur2022), `10.1145/3576915.3616625` (packgenome2023),
`10.1007/978-3-642-21323-6_29` (ugarte2011), `10.1109/MSP.2007.48` (lyda2007),
`10.1007/s10207-023-00759-y` (alkhateeb2023). Per le altre il DOI non è stato raccolto: si prende
dalla pagina dell'editore al momento del bisogno, non da qui.

Gli strumenti, se il relatore vuole citazioni anche per quelli, vanno come `@misc` con
`howpublished = {\url{...}}` e `note = {versione X, consultato il ...}`. Elenco e versioni al §6.

---

## 9. Bozza di §2.4 in inglese

Quattro blocchi, nell'ordine prescritto dal piano dei contenuti. Circa una pagina e mezza.

> **Signature-based detection.** The oldest and still the most widely deployed approach recognises a
> packer by a constant left behind in the file: a sequence of bytes at the entry point, a section
> name, an import pattern. Guo et al. \cite{guo2008} frame the packer problem and classify its
> solutions along these lines, and the approach has an obvious attraction — when a signature fires it
> does not estimate a probability, it names a producer. Its failure mode is equally structural. A
> signature can only recognise what it already describes, so coverage degrades with every new version
> of a packer and collapses on protectors that randomise the very constants a signature reads;
> Ugarte-Pedrero et al. \cite{ugarte2015} document how far the complexity of run-time packers has
> moved beyond the simple compressors the technique was designed for, and the survey of Alkhateeb et
> al. \cite{alkhateeb2023} collects the mitigation strategies adopted on the detection side. The
> reliability of the tools themselves has also been questioned: Zhong et al. \cite{zhong2026} validate
> eleven open-source and six proprietary packer identification tools by requiring that a claimed
> family be confirmed by the corresponding unpacker actually recovering analysable content, and report
> that targeted repairs to their decision logic raise identification coverage by up to 58.6 per cent.
> Work in the opposite direction exists as well, aimed at making signatures themselves robust rather
> than replacing them \cite{packgenome2023}.
>
> **Entropy-based and statistical detection.** The second family measures the file instead of
> recognising it. Shannon entropy \cite{shannon1948} applied to an executable separates compiled code
> from compressed or encrypted data, and Lyda and Hamrock \cite{lyda2007} established its use for
> finding packed and encrypted malware. Perdisci et al. \cite{perdisci2008} apply statistical
> classifiers to the packed-or-not decision itself, in order to route expensive detection only towards
> the files that require it, and Sun et al. \cite{sun2010} extend the same statistical material to
> identifying which packer was applied. The approach needs no
> prior knowledge of the packer, which is precisely what signatures lack, and it fails in two opposite
> ways, both of them relevant here. High entropy does not imply packing: resource sections full of
> already-compressed media, and compressed debug information in binaries produced by some modern
> toolchains, reach the same values as a compressed payload. And packing does not imply high entropy:
> Mantovani et al. \cite{mantovani2020} measure the prevalence of low-entropy packing schemes in the
> malware ecosystem and find that, among malware samples whose entropy is below seven, more than a
> third are nonetheless packed. An entropy threshold is therefore a usable indicator and an unusable
> criterion.
>
> **Machine-learning detection.** The third family learns the decision from data. Biondi et al.
> \cite{biondi2019} label more than 280,000 samples and train classifiers over entropy values, entry
> bytes, imports, metadata, resources and sections; Bertrand Van Ouytsel et al. \cite{bertrand2021}
> compare eleven algorithms over 119 features to establish which features and which algorithms
> actually carry the result. These approaches reach the highest reported accuracies, and they require
> three things this work does not have. They require a labelled training corpus one to two orders of
> magnitude larger than the one used here, whose labels are typically produced by other detectors
> rather than by construction. They require, and produce, a continuous score, which is what makes a
> threshold-free evaluation possible. And they require care in separating what the model learns from
> what the experiment intends to measure: Aghakhani et al. \cite{aghakhani2020} show that static
> features in the presence of packing can lead a classifier to recognise the packer rather than the
> property of interest.
>
> **Where this work sits.** The detector presented here is rule-based, and the choice is not a claim
> of superior accuracy. It is a claim of auditability: a two-tier rule states which signal decided a
> file, which makes the contribution of third-party signatures and of packer-independent structural
> evidence separately measurable — the question this dissertation sets out to answer — whereas a
> classifier over a hundred features does not. Its individual signals are not novel, and are not
> presented as such: the combination of entry-point section entropy with the write permission of that
> section is the heuristic of Han et al. \cite{han2009}, and structural features had already been used
> for packer identification as an anomaly detection problem \cite{ugarte2011}; the architectural role
> of an inexpensive static filter placed ahead of expensive analysis follows Jacob et al.
> \cite{jacob2013}. What is contributed is their composition into a rule that keeps demonstrative
> evidence from being diluted into a sum of weak indications, a ground truth established by
> construction rather than by the judgement of another detector, and a measurement of what each class
> of signal is worth, reported on a corpus built here and verified on a public one under a protocol
> frozen before execution.

**Nota su cosa è stato deliberatamente omesso:** nessun confronto quantitativo con i lavori citati.
Non è possibile e non va simulato — corpora diversi, etichettature diverse, metriche diverse — e il
protocollo della tesi vieta già di confrontare numeri prodotti su oracoli differenti.

---

## 10. Cosa resta da decidere

1. **Verifica delle voci: fatta.** Nessuna voce del §8 resta aperta. Un controllo trovato per strada
   e già corretto nel §2: l'abstract dei «profili di casualità su 17.336 campioni» appartiene a
   [`sun2010`], non a [`perdisci2008`] — vari aggregatori li confondono. Se ricopi quelle frasi da
   una ricerca online invece che da qui, l'errore rientra.
2. **Quante referenze tenere.** Il piano dei contenuti prevede «four to six references» per §2.4 e
   una pagina. La bozza del §9 ne usa 16: regge se il §2.4 cresce a una pagina e mezza, altrimenti i
   candidati al taglio sono `packgenome2023`, `sun2010` e `ugarte2011`, in quest'ordine. Le sei
   intoccabili sono `guo2008`, `ugarte2015`, `lyda2007`, `mantovani2020`, `aghakhani2020`, `han2009`:
   portano rispettivamente l'inquadramento, la complessità dei packer moderni, l'entropia, il suo
   fallimento in entrambe le direzioni, il limite del machine learning e il precedente del nostro
   segnale strutturale.
3. **Dove va il §4.1(a)** — il precedente di Han et al. Due opzioni: nel §2.4 come qui, oppure nella
   sezione che definisce i segnali, dove è più difficile da non notare. La seconda è più onesta e la
   raccomando; si cita in entrambi i posti solo se il §2.4 resta generico.
4. **Se citare gli strumenti** uno per uno in bibliografia o solo con versione nel testo. La seconda è
   la prassi comune; la prima la chiedono alcuni relatori. Da chiedere.
5. **I lavori 2025–2026 trovati e non usati** (PackHero, approcci con autoencoder, rappresentazioni a
   immagine, validazione semantica degli identificatori): tenerli come «direzioni attuali» in una
   frase del §2.4, oppure ignorarli. Sono tutti successivi all'impostazione di questo lavoro e non ne
   cambiano le scelte.
6. **Se serve ampliare**, il gruppo packing-box mantiene `packing-box/awesome-executable-packing`,
   una lista curata di risorse sul packing. Utile come punto di partenza, non citabile come fonte: va
   usata per trovare i paper, non per riferirli.
