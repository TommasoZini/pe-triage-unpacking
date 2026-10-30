# Fase F, livello 2 — criterio proxy, NON correttezza

> I campioni di questa tabella **non hanno un originale pulito**: l'esito `plausibile`
> dice che l'output supera quattro controlli definiti prima del run, non che il payload
> ricostruito sia corretto. **Non si somma al livello 1 e non va nella sua tabella.**

- condizione 1: byte non-zero nella sezione dell'entry point >= 5%
- condizione 2: entropia massima di sezione < 7.2
- condizione 3: Ghidra >= 5 funzioni
- condizione 4: Fase 1 rieseguita sull'output, `Is_Packed_Label` da 1 a 0

Servono tutte e quattro. Soglie rilette dal codice congelato, non ricopiate.

## Per dataset — criterio proxy, non correttezza

| dataset | campioni | non_plausibile | plausibile |
|---|---|---|---|
| v1_misto | 179 | 166 | 13 |
| **totale** | **179** | **166** | **13** |

**Plausibili: 13/40 = 32% dei campioni con un output** — criterio proxy, non correttezza.

Copertura, che e' un numero diverso: la cascata ha prodotto un output valutabile per **40 dei 179** campioni (22%). 139 non hanno prodotto alcun output e 0 non sono stati processati; entrambi restano sul tavolo dell'analista, quindi sul totale i plausibili sono 13/179 = 7%.

## Quale condizione non regge

Solo sui campioni effettivamente valutati: dice dove si ferma la cascata.

| condizione | soddisfatta | non soddisfatta |
|---|---|---|
| ep_non_a_zeri | 40 | 0 |
| entropia_sotto_soglia | 34 | 6 |
| ghidra_funzioni | 40 | 0 |
| fase1_non_piu_packed | 13 | 27 |

## Per strumento

| strumento | non_plausibile | plausibile |
|---|---|---|
| (nessuno) | 139 | 0 |
| sevenzip | 1 | 7 |
| unipacker | 26 | 0 |
| upx | 0 | 6 |
