# pe-triage-unpacking

A two-phase framework for the static triage and automated unpacking of Windows PE
executables, developed as a bachelor's thesis in Computer Science. Phase 1 decides whether
a file is packed by reading its structure alone, without running it. Phase 2 attempts to
reconstruct the original payload with a cascade of tools ordered by cost, and measures the
result byte by byte against the original instead of trusting the exit status a tool
reports. This repository holds the pipeline, the frozen reports of the measured run and
the labels together with their oracle: **no samples**, neither malware nor packed binaries.

Section numbers below refer to the dissertation, *A two-phase framework for static triage
and automated unpacking of PE executables* (2026).

> The documents under `docs/` are in Italian — they are the method, the signed protocols
> and the session log. This README carries every figure they support, in English.

## The two phases

**Phase 1, static triage.** Eighteen signals are extracted from each PE: five strong,
twelve weak and one purely informative. Fourteen come from the file structure alone
(section names and entropy, entry point location and permissions, import count, overlay,
a recognisable decompression stub), four from the verdict of two third-party detectors,
Detect It Easy and YARA-Forge. The decision follows a two-level rule: **one strong signal
is enough** (a packer named by DIE or YARA, a section typical of a packer, a structural
stub, a suspiciously minimal IAT), otherwise **three concurring weak signals** are
required. The threshold of three was not picked after the fact: the sweep in §4.3.7 is
error-free at three and nowhere else, with 164 false positives at two and four lost
detections at four.

**Phase 2, unpacking.** A cascade tries the tools from cheapest to most expensive —
`upx -d`, archive extraction with 7-Zip or innounp, Unipacker, emulation with Qiling — and
stops at the first evaluable output. What matters is that **the correctness oracle is
separate from the screening**: a dump counts as `reconstructed` only if at least 95 % of
the bytes of the executable sections match the original, aligned by RVA. Code relocated to
a different base comes out `partial`, not `reconstructed`. The cost of not having that
oracle is measured in §5.3.1: the pipeline's own function-count criterion declared 210
successes, of which the comparison confirms 178.

## The figures, and the file that produces each one

Every number here was re-read from the reports in `reports/`, not copied from the thesis.
Reports are keyed to samples by the SHA-256 of their content, not by file name, so the
metrics can be re-checked without having the binaries.

### Phase 1 — internal set

| figure | thesis | report | produced by |
|---|---|---|---|
| one row per sample across 51 columns, 20 of which can raise a signal | §4.2 | `reports/report_analisi_lief.csv` | `scripts/parameters_info.py` |
| 3,923 rows matched to the manifest, 3,813 usable (110 `unknown` excluded) | §4.3.2 | `reports/validation_phase1.md` · `.json` | `scripts/validate_phase1.py` |
| 378 packed from four oracles, 3,435 clean from five; TP 378, FN 0, FP 0, TN 3,435 | §4.3.3, Table 4.3 | `reports/validation_phase1.md` | idem |
| Precision 1.000 · Recall 1.000 · F1 1.000 | §4.3.3 | `reports/validation_phase1.md` | idem |
| threshold sweep: 668 FP at 1, 164 at 2, **0 at 3**, 4 FN at 4, 5 from 5 on | §4.3.7, Table 4.5 | `reports/validation_phase1.md` | idem |
| per-signal separation: DIE named 92 % packed / 0 % clean, packer sections 67 % / 0 %, structural stub 41 % / 0 % | §4.3.5 | `reports/validation_phase1.md` | idem |
| 0 verdicts taken with a tool cut short by a timeout, against 73 of 189 in the full configuration | §4.3.1, Table 4.1 | `reports/validation_phase1.md`, from `reports/tool_diagnostics.jsonl` | idem |

> The labels of this set are built in-house (compiled with a recorded command, valid
> Microsoft Authenticode signature, packed with a recorded command), and §4.3.3 states
> what follows from that: since nothing was held out, the false alarm rate measures fit
> and not independent generalisation. The numbers that count as a test are the ones below.

### Phase 1 — external material

| figure | thesis | report | produced by |
|---|---|---|---|
| **Recall 0.9997** — 3,219 detected out of 3,220, on `packing-box/dataset-packed-pe` | §6.1 | `reports/validation_external_dataset_packed_pe.md` | `scripts/validate_external.py` |
| 142 out of 142 on the `outliers/packed` subset, the hard cases picked by the maintainers | §6.1 | idem | idem |
| families covered by a section prefix 901/901; **uncovered families 2,318/2,319** | §6.1, Table 6.1 | idem | idem |
| 155 out of 156 among samples on which **no signature raised a strong signal** | §6.1, §6.5 Table 6.3 | idem | idem |
| 2 files with an invalid magic, excluded and not counted as misses | §6.1 | idem | idem |
| 168 real MalwareBazaar samples, 114 flagged | §6.2, Table 6.2 | no frozen report — see below | `reports/report_analisi_lief.csv`, rows with `Dataset = wild_malwarebazaar` |
| independent clean class: 300 files, **none flagged**, no strong signal, weak indicators 203 / 76 / 21 | §6.3 | no frozen report — see below | same CSV, rows with `Dataset = holdout_clean_2026_10` |

### Phase 2 — reconstruction verified against the original

| figure | thesis | report | produced by |
|---|---|---|---|
| internal matrix, compressors and installers: **178/252 reconstructed (71 %)** | §5.3, Table 5.1 | `reports/validation_phase2.md` · `.csv` | `scripts/validate_phase2.py` |
| the same 252 excluding the 53 Inno Setup samples: 178/199 (89 %) | §5.3, Table 5.1 | idem | idem |
| 29 partial (26 Themida, 3 compressors), 0 false successes, 142/353 left to manual review | §5.3, Table 5.1 | idem | idem |
| virtualizing protectors: **0/101 reconstructed**, 26 made analyzable | §5.3, Table 5.2 | `reports/validation_phase2.md` | idem |
| by final tool: UPX 85, 7-Zip 53, Qiling 24, Unipacker 16 reconstructions | §5.3, Table 5.3 | `reports/validation_phase2.csv` | idem |
| external 64-bit control, 10 third-party executables through 5 packers: **28/28** | §6.4 | `reports/validation_set64.md` · `.csv` | `scripts/validate_phase2.py` over `scripts/build_set64_esterno.py` |
| external samples with a known original, 20 families none packed here: **6/26 (23 %)** | §6.4 | `reports/validation_phase2_esterna.md` · `.csv` | idem |
| no original available, four-condition proxy: output for **40 of 179**, 13 of those 40 pass, 13/179 overall | §6.4 | `reports/validation_fase_f_livello2.md` · `.csv` | `scripts/score_fase_f_livello2.py` |

> **The 71 % is the figure to quote.** §5.3 states why the 89 % is a secondary reading that
> must travel with its reason: no open-source extractor parses Inno Setup 6.7, since
> innounp 0.50 stops at 6.1.2 and innoextract 1.9 at 6.0.5, so those 53 failures record a
> gap in third-party tooling rather than a defect of the cascade, which recognised the
> container, routed it to extraction and declared a failure when the extractor refused the
> format. The 28/28 of the 64-bit control carries no Inno Setup sample either, so it speaks
> to the families that reconstruct and not to that gap.

> On protectors, `partial` is an outcome of the oracle and not a degree of success: those
> 26 match their originals on a median of 0.0678 of the compared bytes. The honest claim is
> that 26 of 101 became readable, not that they were nearly reconstructed.

## Reproducing the thesis figures

Everything in the two tables above is re-derivable from the files in this repository
without a single sample. Install the Phase 1 requirements and run the validator the
pipeline itself uses:

```bash
python -m pip install -r requirements-fase1.txt
python scripts/validate_phase1.py --csv reports/report_analisi_lief.csv --manifest reports/ground_truth.json --out-md /tmp/out.md --out-json /tmp/out.json
```

It regenerates `reports/validation_phase1.md` and the two agree on every metric: the
confusion matrix, the per-signal table and the whole threshold sweep. They differ on one
line, the CSV row total — **8,363 against the 8,063 of the frozen report** — and §4.3.2
accounts for it: the report holds one row per analysed file and is appended to as corpora
are added, so its total grows while the labelled subset the measurement reads does not.
The 300 extra rows are the independent clean class of §6.3, analysed after Chapter 4 was
frozen. The 3,923 matched rows, and therefore every figure of the confusion matrix, are
unchanged.

**The two sections with no pre-computed report.** §6.2 and §6.3 are measured in the thesis
but have no `validation_*` file, because they were produced by querying the CSV rather than
by a dedicated script. Both are still verifiable here, through the `Dataset` column:

| what to check | how |
|---|---|
| §6.3, none of the 300 flagged | the 300 rows with `Dataset = holdout_clean_2026_10` all carry `Is_Packed_Label = 0` and an empty `Strong_Signals`, and their weak indicators distribute 203 / 76 / 21, as §6.3 reports; the labels are in `config/holdout_clean_labels.json` and the protocol registered before collection is `docs/10_protocollo_holdout_pulito.md` |
| §6.2, 114 of 168 flagged | the 168 rows with `Dataset = wild_malwarebazaar` give the total. The **per-tag breakdown of Table 6.2 cannot be rebuilt from this repository**: the MalwareBazaar tags live in the manifest of that corpus, which is not distributed with the samples |

`reports/validation_external_v1_misto.md` reports a 270-sample run that **the thesis does
not use**. Those 270 samples are part of the external corpus of §6.1, where they appear in
the 3,664-entry answer key; the standalone report predates that measurement and computes a
precision over the `not-packed` half, which §3.6 and §6.1 declare not to be an oracle and
report only the recall row for. It is kept as a record of the earlier run, and its
precision figure should not be quoted.

## How to run the pipeline

Everything beyond the checks above needs the samples, which are not distributed. The check
that reports what is missing, naming the file and the constant to fix for each item:

```bash
python scripts/preflight.py --packer
```

Analysing a directory of PE files and regenerating the CSV:

```bash
python scripts/parameters_info.py --dir "<directory of PE files>" --phase1-only
```

`--reanalyze` archives the CSV and re-analyses everything, and is required after any
change to the signal logic: without it, files already in the history are skipped, because
the index is keyed on the SHA-256 of the content. For Phase 2, drop `--phase1-only`; it
needs `requirements-fase2.txt`, Ghidra and the unpackers.

Regenerating the corpora, easiest first:

```bash
python scripts/fetch_goodware_non_ms.py
python scripts/pack_samples.py
python scripts/build_set64_esterno.py
python scripts/tests/make_fixtures.py
python -m unittest discover -s scripts/tests -v
```

In order: 1,042 signed non-Microsoft PE files from public sources, with the upstream
digest verified; the 353-sample matrix of §4.3.2, which needs the full packer toolchain;
the 64-bit control of §6.4; the nine synthetic PE files used by the tests, which are not
committed; the 44 tests, one of which is an `expectedFailure` on purpose and documents a
known defect in its docstring.

`pandas` 3.0.3 is needed by `scripts/merge_csv.py` and `numpy` 2.4.6 by
`scripts/validate_phase2.py`: neither is pinned in the two `requirements-*.txt`, which
cover the analysis pipeline.

## Tool versions

The versions are not indicative. LIEF 1.x is not API-compatible with 0.x and the pipeline
will not start under 0.17; Qiling 1.4.11 is the version the localised hooks in
`subprocesses.py` were written against, and changing it invalidates those fixes.
`preflight.py` verifies both.

| tool | version | role |
|---|---|---|
| Python | 3.13.13 | tested on Windows 10 x64 |
| LIEF | 1.0.0 | PE/ELF parsing, mandatory |
| YARA | 4.5.4 with the YARA-Forge ruleset | strong signature-based signal |
| Detect It Easy | 3.21 portable (`diec.exe`) | strong signature-based signal |
| capa | 9.4.0 | **disabled** by default: it consumed 1,539 of the 1,599 seconds of the full configuration, 96 % of the time, and changed 0 verdicts (§4.3.1) |
| UPX | 5.1.1 | packing, and `-d` as the first rung of the cascade |
| 7-Zip | 26.00 | installer and SFX extraction |
| innounp | 0.50 | Inno Setup extraction, up to format 6.1.2 |
| Unipacker | 1.0.8 | emulated unpacking, invoked as a CLI |
| Qiling | 1.4.11 | emulation |
| Unicorn | 2.1.3 | Qiling's engine |
| Ghidra | 12.0.4 | headless analysis of the dumps |
| IDA Free | 9.4 | manual inspection |

## What is not here, and why

**No samples.** No malware, no binaries packed with commercial tools, no Microsoft system
PE files, and not even the synthetic test fixtures, which are `.exe` files all the same.
The measured corpora amount to roughly 15 GB over 3,941 files and are in part not
redistributable at all. Anyone wanting to reproduce the work regenerates the matrix from
their own masters with their own packers: `scripts/pack_samples.py` is the script that
does it, and the manifest records the command and the digest for every sample.

Third-party rulesets and rootfs images are absent too, since they are downloadable and
weigh more than the repository: YARA-Forge (20 MB of sources, 47 MB precompiled), the capa
rules, and Qiling's Windows rootfs (763 MB, which contains system DLLs). Where to put them
is documented in `docs/03_setup_e_esecuzione.md` §2.

`scripts/extraction.py` downloaded samples from MalwareBazaar with an API key, which here
is read from `MB_AUTH_KEY` and is not committed. Bring your own.

## Paths to configure

The paths of the external tools are constants at the top of the scripts rather than
entries in a configuration file: a known limitation, declared among the open ones. On a
different machine they have to be fixed by hand, and `python scripts/preflight.py` lists
them all, saying which ones do not exist.

| file | constants |
|---|---|
| `scripts/header_elf_lief.py` | `DIEC_PATH`, `CAPA_PATH` |
| `scripts/subprocesses.py` | `SEVENZIP_PATH`, `INNOUNP_PATH`, `ASPACKDIE_PATH`, `UNIPACKER_PATH`, `MAL_UNPACK_PATH`, `GHIDRA_HEADLESS_PATH`, `IDA_PATH`, `UPX_PATH` |
| `scripts/pack_samples.py` | `UPX_PATH`, `MPRESS_PATH`, `VMPROTECT_PATH`, `THEMIDA_X86`/`THEMIDA_X64`, `MAKENSIS_PATH`, `ISCC_PATH`, `SOURCES`, `MASTERS_DIR`, `OUTPUT_DIR` |
| `scripts/make_dataset_index.py` | `DEFAULT_ROOT` |

## What is committed and what is regenerated

The files in `reports/` are the **frozen output** of one run: they have not been
retouched, which is why they still contain the absolute paths of the machine that
produced them. They are the evidence behind the thesis figures and should be treated as
such, not as working files. `reports/pipeline_state.json` is the per-sample Phase 2 state
and is rebuilt by re-running the pipeline; `reports/report_analisi_lief.csv` is
regenerated with `--reanalyze`, and on different samples it will yield different rows.

Regenerable, and therefore absent: the test fixtures, the binaries compiled under
`build_samples/*/target` and `out/`, the third-party rulesets, and every dataset.

## License and citation

MIT, see [LICENSE](LICENSE). Third-party rulesets and tools carry their own licenses,
which this repository does not redistribute.

Tommaso Zini, *A two-phase framework for static triage and automated unpacking of PE
executables*, bachelor's thesis in Computer Science, 2026.
