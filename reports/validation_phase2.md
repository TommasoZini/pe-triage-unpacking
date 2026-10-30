# Validazione Fase 2 — confronto con l'originale

- manifest: `E:\DATASET\01_LABEL_CERTA\matrice_packed\manifest.csv`
- master: `E:\DATASET\02_MATERIA_PRIMA\masters`
- stato pipeline: `C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\Pipeline_Reports\pipeline_state.json`
- soglie: ricostruito se byte coincidenti >= 95%; fallito se byte non-zero < 5%

> Il confronto e' per RVA sulle sole sezioni ESEGUIBILI dell'originale. Codice
> rilocato a una base diversa produce `parziale`, non `ricostruito`: e' voluto,
> serve a non spacciare per identico un dump che identico non e'.

## Compressori e installer — l'identita' byte a byte e' il bersaglio

| packer | arch | n | ricostruito | parziale | fallito | non_processato | non_confrontabile | senza_originale |
|---|---|---|---|---|---|---|---|---|
| Inno | x64 | 26 | 0 | 0 | 26 | 0 | 0 | 0 |
| Inno | x86 | 27 | 0 | 0 | 27 | 0 | 0 | 0 |
| MPRESS | x64 | 25 | 24 | 0 | 1 | 0 | 0 | 0 |
| MPRESS | x86 | 25 | 16 | 1 | 8 | 0 | 0 | 0 |
| NSIS | x64 | 26 | 26 | 0 | 0 | 0 | 0 | 0 |
| NSIS | x86 | 27 | 27 | 0 | 0 | 0 | 0 | 0 |
| UPX | x64 | 25 | 24 | 0 | 0 | 1 | 0 | 0 |
| UPX | x86 | 19 | 18 | 0 | 0 | 1 | 0 | 0 |
| UPX + MPRESS | x86 | 8 | 0 | 2 | 6 | 0 | 0 | 0 |
| UPX + NSIS | x64 | 25 | 25 | 0 | 0 | 0 | 0 | 0 |
| UPX + NSIS | x86 | 19 | 18 | 0 | 0 | 0 | 1 | 0 |

**Ricostruiti: 178/252 (71%)** · parziali: 3 (1%)

## Protector che virtualizzano — identita' NON attesa

| packer | arch | n | ricostruito | parziale | fallito | non_processato | non_confrontabile | senza_originale |
|---|---|---|---|---|---|---|---|---|
| Themida | x64 | 26 | 0 | 26 | 0 | 0 | 0 | 0 |
| Themida | x86 | 27 | 0 | 0 | 27 | 0 | 0 | 0 |
| VMProtect | x64 | 26 | 0 | 0 | 26 | 0 | 0 | 0 |
| VMProtect | x86 | 22 | 0 | 0 | 22 | 0 | 0 | 0 |

**Ricostruiti: 0/101 (0%)** · parziali: 26 (26%)

> Su questi ultimi `parziale` e' l'esito buono: il codice originale non esiste piu'
> come sequenza di byte. Non concorrono al tasso di ricostruzione.

## Per tecnica

| tecnica | ricostruito | parziale | fallito |
|---|---|---|---|
| qiling | 24 | 26 | 0 |
| sevenzip | 53 | 0 | 0 |
| unipacker | 16 | 3 | 3 |
| upx | 85 | 0 | 0 |
