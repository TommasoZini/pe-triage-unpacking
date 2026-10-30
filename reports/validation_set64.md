# Validazione Fase 2 — confronto con l'originale

- manifest: `E:\DATASET\01_LABEL_CERTA\set64_esterno\manifest.csv`
- master: `E:\DATASET\02_MATERIA_PRIMA\masters64_esterni`
- stato pipeline: `C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\Pipeline_Reports\pipeline_state.json`
- soglie: ricostruito se byte coincidenti >= 95%; fallito se byte non-zero < 5%

> Il confronto e' per RVA sulle sole sezioni ESEGUIBILI dell'originale. Codice
> rilocato a una base diversa produce `parziale`, non `ricostruito`: e' voluto,
> serve a non spacciare per identico un dump che identico non e'.

## Compressori e installer — l'identita' byte a byte e' il bersaglio

| packer | arch | n | ricostruito | parziale | fallito | non_processato | non_confrontabile | senza_originale |
|---|---|---|---|---|---|---|---|---|
| MPRESS | x64 | 8 | 8 | 0 | 0 | 0 | 0 | 0 |
| NSIS | x64 | 10 | 10 | 0 | 0 | 0 | 0 | 0 |
| UPX | x64 | 10 | 10 | 0 | 0 | 0 | 0 | 0 |

**Ricostruiti: 28/28 (100%)** · parziali: 0 (0%)

## Protector che virtualizzano — identita' NON attesa

| packer | arch | n | ricostruito | parziale | fallito | non_processato | non_confrontabile | senza_originale |
|---|---|---|---|---|---|---|---|---|
| Themida | x64 | 10 | 0 | 10 | 0 | 0 | 0 | 0 |
| VMProtect | x64 | 10 | 0 | 0 | 10 | 0 | 0 | 0 |

**Ricostruiti: 0/20 (0%)** · parziali: 10 (50%)

> Su questi ultimi `parziale` e' l'esito buono: il codice originale non esiste piu'
> come sequenza di byte. Non concorrono al tasso di ricostruzione.

## Per tecnica

| tecnica | ricostruito | parziale | fallito |
|---|---|---|---|
| qiling | 8 | 10 | 0 |
| sevenzip | 10 | 0 | 0 |
| upx | 10 | 0 | 0 |
