# Protocollo di validazione esterna della Fase 2

**Stato: FIRMATO il 14/10/2026 sul commit `7379138`.** Redatto l'11/10/2026 prima di
qualunque esecuzione; le decisioni del §12 sono state prese e gli scostamenti di ambito
registrati al §13 il 14/10/2026, anch'essi prima di eseguire qualunque cosa.

Questo documento si firma **prima** di lanciare l'analisi, e vale lo stesso vincolo del
protocollo della Fase 1 (`05_protocollo_validazione_esterna.md`): se quello che segue viene
usato per tarare qualcosa, cessa di essere una misura esterna. Le sezioni 1–12 non vanno
modificate dopo aver visto i risultati; eventuali scoperte si annotano in una sezione 13
separata e datata.

---

## 1. La domanda a cui questo run risponde

**Una sola:** quanto del risultato della Fase 2 sopravvive su **packer che non abbiamo
applicato noi**.

La Fase E ha misurato 71% di ricostruzione su 353 campioni, ma quel corpus è stato costruito
in casa: 53 programmi originali, 6 packer, **una sola versione per packer**, tutti applicati
dal nostro `pack_samples.py`. Il numero dice "sappiamo disfare i packer che abbiamo applicato
noi". Questo run serve a sapere quanto vale fuori da quella condizione.

Domande a cui questo run **NON** risponde, e che non vanno chieste ai suoi numeri:

- **quanti falsi positivi produce la Fase 2** — qui si parte da file già etichettati packed
  dalla Fase 1, non c'è una classe negativa;
- **come si comporta a 64 bit** — i 29 campioni dell'oracolo forte sono **tutti a 32 bit**
  (verificato). Il ramo Qiling, che in Fase E ha gestito 50 file, **non viene esercitato
  affatto** dalla misura forte;
- **se il payload estratto dai malware reali è corretto** — per quei campioni non esiste
  l'originale pulito, e il criterio di livello 2 (§3.3) misura plausibilità, non correttezza;
- **quanto è veloce** — hardware e carico non sono confrontabili con le run precedenti.

---

## 2. L'oggetto: cosa sono questi dataset

| dataset | campioni packed | provenienza | oracolo disponibile |
|---|---|---|---|
| `v1_misto` | 208 | `packing-box/dataset-packed-pe`, metà del dataset pubblico | **29 con originale** (§3.1), 179 senza |
| `wild_malwarebazaar` | 114 | MalwareBazaar, malware reale | nessuno |
| `malware_reali` | 16 | malware reale | nessuno |
| `legacy_misto` | 9 | misto storico | nessuno |
| `pma_book` | 6 | campioni del libro *Practical Malware Analysis* | nessuno |

Totale **353 campioni esterni** — coincidenza numerica con la matrice interna, nessun
significato.

---

## 3. I due livelli di misura, e perché sono separati

### 3.1 Livello 1 — oracolo accoppiato (29 campioni, 20 famiglie)

`v1_misto` ha due metà: 200 packed e 70 puliti. La chiave `v1_chiave.csv` conserva per ogni
file il `nome_originale`, e i nomi rivelano che **parte dei packed sono versioni compresse di
programmi che stanno, non compressi, nella metà pulita**:

```
packed      fsg_cpuz_x32.exe   ->  clean   cpuz_x32.exe
packed      packman_Autologon.exe  ->  clean   Autologon.exe
```

`scripts/build_fase_f_pairs.py` costruisce la tabella togliendo il prefisso fino al **primo**
underscore e cercando il nome risultante fra i puliti. Risultato, in
`config/fase_f_coppie.csv`: **29 coppie su 20 famiglie di packer**, tutte PE valide e presenti
su disco.

Su questi 29 si applica **lo stesso oracolo della Fase E, con le stesse soglie** (`MATCH_OK =
0.95`, `NONZERO_MIN = 0.05`) e lo stesso codice. È l'unico numero di questa fase confrontabile
con il 71%.

**17 famiglie su 20 non sono mai state viste in Fase E:** ASPack, Amber, BeRoEXEPacker,
EXpressor, Enigma Virtual Box, Exe32pack, FSG, JDPack, MEW, Molebox, NSPack, PECompact,
Packman, RLPack, TELock, Yoda-Crypter, Yoda-Protector. Le tre già note sono UPX, MPRESS,
Themida.

### 3.2 L'assunzione dichiarata, e la sua verifica parziale

Che i nomi combacino **non prova** che i due binari siano lo stesso programma. La prova
richiederebbe un decompressore di riferimento per ciascuna famiglia, che non esiste.

Quello che si è potuto verificare, il 10/10/2026: sulle **2 coppie UPX** — l'unica famiglia per
cui esiste un decompressore ufficiale e senza perdita — `upx -d` sul packed restituisce il
pulito corrispondente con **match 0.9940 e 1.0000**.

**Per le altre 18 famiglie l'accoppiamento è un'assunzione**, fondata sul nome e sulla
coerenza del dataset a monte. Va scritta come tale in tesi. Conseguenza operativa: un esito
`fallito` su una di quelle coppie è ambiguo fra "la pipeline non ce l'ha fatta" e
"l'accoppiamento era sbagliato", e non va letto come il primo senza un controllo a mano.

### 3.3 Livello 2 — criterio proxy (324 campioni), definito ADESSO

Per i campioni senza originale il criterio è il seguente, e si chiama **`plausibile`**, mai
`ricostruito`. Servono **tutte e quattro** le condizioni:

1. la sezione che contiene l'entry point non è a zeri (frazione di byte non-zero ≥ 5%);
2. l'entropia massima di sezione scende sotto la soglia della Fase 1 (7.2);
3. Ghidra headless trova almeno 5 funzioni;
4. rieseguendo la Fase 1 sull'output, `Is_Packed_Label` passa da 1 a 0.

Nessuna delle quattro è sufficiente da sola; la 3 da sola è esattamente il criterio che in
Fase B aveva promosso 5 falsi successi. La 4 è parzialmente circolare — è lo stesso
rilevatore che aveva detto "packed" — e per questo non basta nemmeno insieme alla 3.

**Questo numero non va mai sommato né messo nella stessa tabella del livello 1.**

### 3.4 Separazione dalle metriche della Fase E — vincolo tecnico

I risultati di questo run vanno in `Pipeline_Reports/validation_phase2_esterna.{md,csv}`.
Non toccano `validation_phase2.{md,csv}`, che resta la misura della Fase E. Nessuna tabella
della tesi mescola i due corpora.

### 3.5 Deduplicazione

Prima del run si verifica che nessuno SHA-256 dei 353 esterni compaia già fra i 353 della
matrice interna. Un duplicato va escluso e registrato.

**Verificato l'11/10/2026, prima della firma:** sulle 29 coppie, **zero** sovrapposizioni con
la matrice interna, e **zero** fra i 29 binari puliti esterni e i 53 master interni. I due
corpora sono disgiunti per contenuto.

---

## 4. Il codice congelato

Il run si esegue sul commit **`7379138`**, che contiene già i tre script di questa fase.
La cascata è **byte-identica** a `46a2cfd`, il commit dichiarato in fase di redazione:
fra i due sono entrati soltanto script nuovi, nessuno dei quali sta nel percorso misurato
(verificato su `subprocesses.py`, `validate_phase2.py`, `parameters_info.py` e
`pipeline_utils.py`). Nessuna modifica alla cascata, alle soglie o agli strumenti fra la
firma di questo documento e la fine del run. Se emerge un difetto che impone una
modifica, il run si **annulla e si rifà da capo**, con il nuovo commit dichiarato qui.

Versioni degli strumenti: Qiling 1.4.11 · Unicorn 2.1.3 · Unipacker 1.0.8 · UPX 5.1.1 ·
7-Zip 26.00 · innounp 0.50 · Ghidra 12.0.4 · IDA Free 9.4 · Python 3.13.13 · LIEF 1.0.0 ·
pefile 2024.8.26.

---

## 5. Le misure da produrre — forma decisa in anticipo

**5.1 Livello 1, tabella principale.** Una riga per famiglia (20 righe), colonne:
`famiglia · campioni · ricostruito · parziale · fallito`. Più il totale, nella stessa forma
del 71%.

**5.2 Livello 1, confronto con la Fase E.** Solo sulle 3 famiglie in comune (UPX, MPRESS,
Themida): è l'unico confronto diretto possibile fra corpus interno ed esterno.

**5.3 Livello 2, tabella separata.** `dataset · campioni · plausibile · non plausibile ·
non processato`, con la dicitura "criterio proxy, non correttezza" nel titolo della tabella,
non in nota.

**5.4 Per strumento.** Come in Fase E: quale strumento ha prodotto l'output, con quale esito.

**5.5 Costo.** Tempo per strumento da `tool_diagnostics.jsonl`, e quanti campioni hanno
superato il budget.

---

## 6. Il campione verificato a mano — DECADUTO, decisione del 14/10/2026

**Questa sezione non si esegue.** La verifica manuale dei 30 campioni richiedeva una persona
disponibile a giudicarli, e non c'è. La si dichiara decaduta **prima** di aver visto qualunque
risultato: e' la sola condizione che rende la rinuncia onesta invece che opportunistica.

**Conseguenza, accettata:** il livello 2 **non dice nulla sulla correttezza**. Il criterio
proxy del §3.3 resta definito e si esegue — scarta i dump vuoti, quelli ad alta entropia e
quelli che la Fase 1 continua a vedere impacchettati, quindi dice piu' della semplice conta
degli output — ma e' un **proxy non validato**. Si riporta come copertura con un filtro di
qualita', mai come tasso di ricostruzione. Formulazione esatta al §11.

**L'alternativa scartata** era far giudicare i campioni a un modello linguistico. Scartata per
una ragione di struttura, non di qualita': il criterio proxy e' stato scritto dallo stesso
modello, quindi il suo giudizio non sarebbe indipendente da cio' che deve verificare. E' la
stessa forma dell'errore che in Fase B aveva fatto passare 5 falsi successi, con Ghidra
giudice del proprio output.

---

## 7. Sicurezza — questa è la prima fase che tocca malware reale

Fin qui il corpus erano binari puliti compilati in casa. `wild_malwarebazaar`,
`malware_reali` e `pma_book` sono **malware vero**.

- `MAL_UNPACK_ENABLED` resta **False**. È l'unico passo che esegue davvero il campione.
- **Attenzione a 7-Zip**: su un installer malevolo estrae i payload reali su disco, non li
  emula. `UNPACKED_SAMPLES/` va trattata come cartella infetta.
- Rete della VM **disattivata** per tutta la durata del run.
- **Snapshot** della VM prima di cominciare.
- Qiling e Unipacker restano emulazione: non eseguono nulla sull'host.

---

## 8. Ipotesi registrate prima del run

Si scrivono ora per poter essere smentite. Una previsione sbagliata è un risultato, non un
errore da nascondere.

1. **Il livello 1 darà meno del 71%.** Delle 20 famiglie, Unipacker ne copre nativamente 6
   (UPX, ASPack, FSG, MEW, MPRESS, PECompact); per le altre 14 ha solo l'unpacker generico.
   Previsione: **fra il 30% e il 50%**.
2. **Themida (3) e Yoda-Protector (3) daranno `parziale` o `fallito`, mai `ricostruito`.**
   Sono protector e il corpus è a 32 bit, dove in Fase E Themida ha dato 0 su 27.
3. **Enigma Virtual Box (1) verrà instradato agli estrattori** e non all'emulazione, perché
   DIE lo classifica container.
4. **Il livello 2 avrà un tasso molto più basso del livello 1**, perché il malware reale usa
   varianti modificate e packer custom che nessuno dei nostri strumenti riconosce.
5. **Il ramo Qiling resterà quasi inutilizzato**: tutti i 29 sono a 32 bit, quindi vanno a
   Unipacker.

---

## 9. Regole di interpretazione, decise prima di vedere i numeri

- **Un timeout conta come fallimento**, non come "non misurato": dal punto di vista
  dell'obiettivo — ridurre il lavoro manuale — un file che non si chiude in tempo resta sul
  tavolo dell'analista. Il numero dei timeout si riporta a parte.
- **Un `fallito` su una coppia non verificata (§3.2) non si conta come difetto della pipeline**
  finché non si è controllato a mano che l'accoppiamento fosse giusto.
- **Nessuna soglia viene toccata dopo aver visto i risultati.** Se le soglie 0.95 / 0.05 si
  rivelano inadatte al corpus esterno, lo si scrive come limite; non si ritarano.
- **Un risultato peggiore della Fase E non è un fallimento del lavoro**: è la misura di quanto
  il corpus interno fosse facile, che è precisamente ciò che questo run serve a quantificare.

---

## 10. Esecuzione — sequenza

Aggiornata il 14/10/2026 con la restrizione di ambito del §13.

1. Commit degli script (`build_fase_f_pairs.py`, `build_fase_f_manifest.py`,
   `score_fase_f_livello2.py`) e di `config/fase_f_coppie.csv`; firma di questo documento.
   **Fatto:** commit `7379138`.
2. Verifica di deduplicazione (§3.5). **Fatta l'11/10/2026.**
3. Manifest del livello 1 con `build_fase_f_manifest.py`. **Fatto il 14/10/2026:** 29 coppie,
   20 famiglie, zero scartate, tutte le origini presenti su disco, tutte **x86** — verificato
   leggendo il Magic dell'optional header, non assunto dal nome del dataset.
4. Fase 1 + Fase 2 su `v1_misto`. **Nessuno snapshot e nessuna disconnessione di rete:
   `v1_misto` non e' malware.** Viene da `packing-box/dataset-packed-pe` ed e' costruito come
   la matrice interna — programmi puliti impacchettati da terzi. E' precisamente il motivo per
   cui 29 dei suoi packed hanno l'originale pulito dentro lo stesso dataset.
5. Livello 1: i 29 accoppiati, con l'oracolo forte invariato.
6. Fase 1 **rieseguita sugli output** della cascata: serve alle condizioni 2 e 4 del §3.3.
7. Livello 2: i packed restanti di `v1_misto`, con il criterio proxy non validato.
8. Stesura dei risultati nella forma del §5, con il §5.3 rititolato secondo il §13.

Il §7 e la sua cerimonia **non si applicano a questo run**: valgono solo se piu' avanti si
decide di processare i 145 campioni di malware reale, che questo run non tocca.

---

## 11. Come va scritto in tesi

Il risultato principale della Fase 2 resta il **71% sulla matrice interna**, con il suo
limite dichiarato (corpus costruito in casa). Il livello 1 di questa fase è **la verifica di
quel limite**, e va presentato così: *"su 29 campioni impacchettati da terzi, con 20 famiglie
di cui 17 mai incontrate, il tasso è X%"*.

Il livello 2 **non è un tasso di ricostruzione** e non va scritto come tale. Essendo
decaduto il §6, non esiste nemmeno un accordo col giudizio umano da riportare. La
formulazione corretta è: *"su N campioni esterni dove l'originale non esiste, la cascata
ha prodotto un output per X; di questi, Y superano un criterio proxy definito in anticipo
e **non validato**. Il criterio misura plausibilità, non correttezza."*

---

## 12. Decisioni che servivano prima di procedere — PRESE il 14/10/2026

1. **Documento firmato**: data 14/10/2026, commit `7379138` (vedi intestazione e §4).
2. **La verifica manuale dei 30 non si fa**, e il §6 decade. Motivazione e conseguenze lì.
3. **L'assunzione sulle 18 famiglie (§3.2) è accettata** come assunzione dichiarata.
   Restringere il livello 1 alle 2 coppie verificabili non reggerebbe una misura, e il §3.2
   già impone di non leggere un `fallito` su quelle coppie come difetto della pipeline senza
   un controllo a mano. Decisione per assenza di alternativa praticabile, da scrivere in tesi
   come tale.

---

## 13. Scostamenti dal protocollo, registrati prima dei risultati — 14/10/2026

Due restrizioni di ambito, decise prima di eseguire qualunque cosa.

**13.1 Il §6 decade.** Nessuna verifica manuale. Dettaglio e conseguenze al §6.

**13.2 Il livello 2 si limita a `v1_misto`.** Il protocollo prevedeva 324 campioni su cinque
corpora. Questo run processa solo i packed di `v1_misto` che non appartengono alle 29 coppie.
I **145 campioni di `wild_malwarebazaar`, `malware_reali`, `legacy_misto` e `pma_book` non
vengono processati**, e il titolo della tabella del §5.3 va corretto di conseguenza.

Ragione: sono l'unica parte del corpus che e' malware vero, richiedono snapshot e rete
disattivata, e portano solo copertura su un criterio che — decaduto il §6 — non e' comunque
validato. Costo alto, resa nulla.

**Cosa si perde, dichiarato.** La misura non dice nulla su malware reale. L'ipotesi 4 del §8
— *"il livello 2 avra' un tasso molto piu' basso del livello 1, perche' il malware reale usa
varianti modificate e packer custom"* — **resta non verificata**: in tesi va scritta come
previsione non messa alla prova, non come risultato. Lo stesso vale per l'ipotesi 3 su Enigma
Virtual Box, che invece resta verificabile perche' quella coppia sta in `v1_misto`.

**Cosa non si perde.** Il livello 1, cioe' l'unico numero confrontabile con il 71% e la
risposta all'obiezione che questa fase doveva chiudere. Le 29 coppie stanno tutte in
`v1_misto`, quindi la restrizione non le sfiora.
