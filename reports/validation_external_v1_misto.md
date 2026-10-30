# Validazione su set esterno — `v1_misto`

- chiave di risposta: `E:\DATASET\04_VALIDAZIONE_ESTERNA\v1_chiave.csv`
- campioni: **270** (200 packed, 70 not-packed)
- le label **non** sono in `ground_truth.json`: sono di terzi e restano separate

## Matrice di confusione (label esterne prese come sono)

| | predetto packed | predetto clean |
|---|---|---|
| **reale packed** | TP = 200 | FN = 0 |
| **reale clean** | FP = 8 | TN = 62 |

Precision **0.962** · Recall **1.000** · F1 **0.980**

## Recall per famiglia

| famiglia | rilevati | campioni |
|---|---|---|
| ASPack | 8 | 8 |
| Alienyze | 8 | 8 |
| Amber | 8 | 8 |
| BeRoEXEPacker | 8 | 8 |
| EXpressor | 8 | 8 |
| Enigma Virtual Box | 8 | 8 |
| Eronana Packer | 8 | 8 |
| Exe32pack | 8 | 8 |
| FSG | 8 | 8 |
| JDPack | 8 | 8 |
| MEW | 8 | 8 |
| MPRESS | 8 | 8 |
| Molebox | 8 | 8 |
| NSPack | 8 | 8 |
| Neolite | 8 | 8 |
| PECompact | 8 | 8 |
| PEtite | 8 | 8 |
| Packman | 8 | 8 |
| RLPack | 8 | 8 |
| TELock | 8 | 8 |
| Themida | 8 | 8 |
| UPX | 8 | 8 |
| WinUpack | 8 | 8 |
| Yoda-Crypter | 8 | 8 |
| Yoda-Protector | 8 | 8 |

## Disaccordi sui not-packed, scomposti

| categoria | campioni |
|---|---|
| SFX / archivio auto-estraente | 7 |
| installer | 1 |

Dettaglio:

- `md5v12005.exe` (outliers/not-packed) — DIE: sfx identificato (WinZip)
- `DTCPing.exe` (outliers/not-packed) — DIE: sfx identificato (Microsoft Cabinet)
- `md5v11027.exe` (outliers/not-packed) — DIE: sfx identificato (WinZip)
- `md5v11026.exe` (outliers/not-packed) — DIE: sfx identificato (WinZip)
- `cmbins.exe` (outliers/not-packed) — DIE: sfx identificato (Microsoft Cabinet)
- `md5v10.exe` (outliers/not-packed) — DIE: sfx identificato (WinZip)
- `md5v11.exe` (outliers/not-packed) — DIE: sfx identificato (WinZip)
- `pywin32-221.win32-py2.7.exe` (outliers/not-packed) — DIE: installer identificato (distutils)

## Falsi negativi

**Nessuno.**

