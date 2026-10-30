# Validazione Fase 1

- CSV: `C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\Pipeline_Reports\report_analisi_lief.csv`
- Manifest: `C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\Pipeline_Reports\ground_truth.json`
- Righe nel CSV: **8063**
- Righe agganciate al manifest: **3923** (non agganciate: 4140, hash non risolto: 0)
- Righe utilizzabili per le metriche: **3813** (label `unknown`, escluse: 110)

## Matrice di confusione

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** | TP = 378 | FN = 0 |
| **reale clean**  | FP = 0 | TN = 3435 |

- Supporto etichettato: 378 packed, 3435 clean
- Precision: **1.000** | Recall: **1.000** | F1: **1.000** | Accuracy: **1.000**

## Discriminazione per segnale

Su 378 packed e 3435 clean etichettati.

| segnale | tipo | packed | clean | lift |
|---|---|---|---|---|
| die | forte | 92% (349) | 0% (0) | +92 |
| die euristica | debole | 99% (373) | 17% (588) | +82 |
| nomi sezione non standard | debole | 82% (310) | 4% (137) | +78 |
| entry point in sezione non standard | debole | 69% (261) | 0% (0) | +69 |
| sezione tipica di packer | forte | 67% (255) | 0% (0) | +67 |
| entropia sezione >= 7.2 | debole | 56% (210) | 1% (27) | +55 |
| sezioni con dimensione anomala | debole | 54% (205) | 0% (1) | +54 |
| numero import basso | debole | 50% (189) | 2% (76) | +48 |
| stub strutturale | forte | 41% (154) | 0% (0) | +41 |
| overlay grande ad alta entropia | debole | 27% (102) | 0% (0) | +27 |
| iat minimale sospetta | forte | 17% (64) | 0% (0) | +17 |
| yara packer specifico | forte | 15% (55) | 0% (0) | +15 |
| entry point in sezione scrivibile+eseguibile | debole | 14% (52) | 0% (0) | +14 |
| entry point in sezione ad alta entropia | debole | 1% (5) | 0% (3) | +1 |
| entry point fuori da ogni sezione | debole | 1% (2) | 0% (0) | +1 |
| sezioni stripped | debole | 1% (2) | 0% (0) | +1 |
| header non parsabile da lief | debole | 0% (1) | 0% (0) | +0 |
| yara generico/anti-analysis | info | 1% (5) | 35% (1210) | -34 |

## Sweep di WEAK_SIGNALS_REQUIRED

| soglia | TP | FP | FN | TN | precision | recall | F1 |
|---|---|---|---|---|---|---|---|
| 1 | 378 | 668 | 0 | 2767 | 0.361 | 1.000 | 0.531 |
| 2 | 378 | 164 | 0 | 3271 | 0.697 | 1.000 | 0.822 |
| 3 **(attuale)** | 378 | 0 | 0 | 3435 | 1.000 | 1.000 | 1.000 |
| 4 | 374 | 0 | 4 | 3435 | 1.000 | 0.989 | 0.995 |
| 5 | 373 | 0 | 5 | 3435 | 1.000 | 0.987 | 0.993 |
| 6 | 373 | 0 | 5 | 3435 | 1.000 | 0.987 | 0.993 |

## Esposizione al non determinismo

Righe decise con almeno un tool troncato da un timeout o da una finestra di sondaggio scaduta: **0 / 8063** (0%).
