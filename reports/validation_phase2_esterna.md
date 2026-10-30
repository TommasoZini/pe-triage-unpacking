# Validazione Fase 2 — confronto con l'originale

- manifest: `E:\DATASET\04_VALIDAZIONE_ESTERNA\fase_f_manifest.csv`
- master: `E:\DATASET\04_VALIDAZIONE_ESTERNA\v1_misto`
- stato pipeline: `C:\Users\zinit\Desktop\Tirocinio_Malware\Unpacking\Packing\Pipeline_Reports\pipeline_state.json`
- soglie: ricostruito se byte coincidenti >= 95%; fallito se byte non-zero < 5%

> Il confronto e' per RVA sulle sole sezioni ESEGUIBILI dell'originale. Codice
> rilocato a una base diversa produce `parziale`, non `ricostruito`: e' voluto,
> serve a non spacciare per identico un dump che identico non e'.

## Compressori e installer — l'identita' byte a byte e' il bersaglio

| packer | arch | n | ricostruito | parziale | fallito | non_processato | non_confrontabile | senza_originale |
|---|---|---|---|---|---|---|---|---|
| ASPack | x86 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| Amber | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| BeRoEXEPacker | x86 | 2 | 0 | 0 | 2 | 0 | 0 | 0 |
| EXpressor | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| Enigma Virtual Box | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| Exe32pack | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| FSG | x86 | 2 | 1 | 0 | 1 | 0 | 0 | 0 |
| JDPack | x86 | 2 | 0 | 0 | 2 | 0 | 0 | 0 |
| MEW | x86 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| MPRESS | x86 | 1 | 1 | 0 | 0 | 0 | 0 | 0 |
| Molebox | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| NSPack | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| PECompact | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| Packman | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| RLPack | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| TELock | x86 | 1 | 0 | 0 | 1 | 0 | 0 | 0 |
| UPX | x86 | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| Yoda-Crypter | x86 | 2 | 0 | 0 | 2 | 0 | 0 | 0 |
| Yoda-Protector | x86 | 3 | 0 | 0 | 3 | 0 | 0 | 0 |

**Ricostruiti: 6/26 (23%)** · parziali: 0 (0%)

## Protector che virtualizzano — identita' NON attesa

| packer | arch | n | ricostruito | parziale | fallito | non_processato | non_confrontabile | senza_originale |
|---|---|---|---|---|---|---|---|---|
| Themida | x86 | 3 | 0 | 0 | 3 | 0 | 0 | 0 |

**Ricostruiti: 0/3 (0%)** · parziali: 0 (0%)

> Su questi ultimi `parziale` e' l'esito buono: il codice originale non esiste piu'
> come sequenza di byte. Non concorrono al tasso di ricostruzione.

## Per tecnica

| tecnica | ricostruito | parziale | fallito |
|---|---|---|---|
| unipacker | 4 | 0 | 0 |
| upx | 2 | 0 | 0 |
