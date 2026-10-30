# pe-triage-unpacking

A two-phase framework for the static triage and automated unpacking of Windows PE
executables, developed as a bachelor's thesis in Computer Science. Phase 1 decides whether
a file is packed by reading its structure alone, without running it. Phase 2 attempts to
reconstruct the original payload with a cascade of tools ordered by cost, and measures the
result byte by byte against the original instead of trusting the exit status a tool
reports. This repository holds the pipeline, the frozen reports of the measured run and
the labels together with their oracle: **no samples**, neither malware nor packed binaries.

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
required. The threshold of three was not picked after the fact: the sweep table in
`reports/validation_phase1.md` shows precision collapsing to 0.697 at two, and four true
positives being lost at four.

**Phase 2, unpacking.** A cascade tries the tools from cheapest to most expensive —
`upx -d`, archive extraction with 7-Zip or innounp, Unipacker, emulation with Qiling — and
stops at the first evaluable output. What matters is that **the correctness oracle is
separate from the screening**: a dump counts as `reconstructed` only if at least 95 % of
the bytes of the executable sections match the original, aligned by RVA. Code relocated to
a different base comes out `partial`, not `reconstructed`. Where no original exists (real
samples) a four-condition proxy criterion is used, and the report states explicitly that
it is not a measurement of correctness.

## The figures, and the file that produces each one

Every number in these tables was re-read from the reports in `reports/`, not copied from
the thesis. Reports are keyed to samples by the SHA-256 of their content, not by file
name, so the metrics can be re-checked without having the binaries.

### Phase 1 — internal set

| figure | report | produced by |
|---|---|---|
| 8,063 rows analysed, 51 columns per sample | `reports/report_analisi_lief.csv` | `scripts/parameters_info.py` |
| 3,923 matched to the manifest, 3,813 usable (110 `unknown` excluded) | `reports/validation_phase1.md` | `scripts/validate_phase1.py` |
| 378 packed / 3,435 clean labelled; TP 378, FN 0, FP 0, TN 3,435 | `reports/validation_phase1.md` · `.json` | `scripts/validate_phase1.py` |
| Precision 1.000 · Recall 1.000 · F1 1.000 | `reports/validation_phase1.md` | idem |
| weak-signal threshold sweep: 1 → P 0.361; 2 → P 0.697; **3 → P 1.000**; 4 → R 0.989 | `reports/validation_phase1.md` | idem |
| per-signal lift: DIE strong +92, DIE heuristic +82, section names +78 | `reports/validation_phase1.md` | idem |
| 0 rows out of 8,063 decided with a tool cut short by a timeout | `reports/validation_phase1.md`, from `reports/tool_diagnostics.jsonl` | idem |

> The labels of this set are built in-house (compiled with a recorded command, valid
> Microsoft Authenticode signature, packed with a recorded command), so the 1.000 should
> be read for what it is: the rule does not fail on a corpus whose every file has known
> provenance. The numbers that count as a test are the ones below, on third-party labels.
> The discussion is in `docs/05_protocollo_validazione_esterna.md`, signed before the run.

### Phase 1 — external sets, third-party labels

| figure | report | produced by |
|---|---|---|
| **Recall 0.9997** — 3,219 detected out of 3,220, on `packing-box/dataset-packed-pe` | `reports/validation_external_dataset_packed_pe.md` | `scripts/validate_external.py` |
| 142 out of 142 on the `outliers/packed` subset, the hard cases picked by others | idem | idem |
| 155 out of 156 among samples carrying **no strong signature-based signal** | idem | idem |
| families covered by a section prefix: 901/901; uncovered families: 2,318/2,319 | idem | idem |
| 2 files with an invalid magic, excluded and not counted as false negatives | idem | idem |
| 270 samples of `v1_misto` (200 packed, 70 not-packed): P 0.962 · R 1.000 · F1 0.980 | `reports/validation_external_v1_misto.md` | idem |
| the 8 disagreements on `not-packed` are 7 SFX and 1 installer, each one named | idem | idem |

### Phase 2 — reconstruction verified against the original

| figure | report | produced by |
|---|---|---|
| internal matrix, compressors and installers: **178/252 reconstructed (71 %)** | `reports/validation_phase2.md` · `.csv` | `scripts/validate_phase2.py` |
| of those same 252, the 53 Inno Setup samples are 0 reconstructed: **without Inno it is 178/199 (89 %)** | recomputed from the per-packer table of the same report | idem |
| protectors that virtualise code: **0/101 reconstructed**, 26 `partial` | `reports/validation_phase2.md` | idem |
| external 64-bit control, 3 families (MPRESS, NSIS, UPX): **28/28 (100 %)** | `reports/validation_set64.md` · `.csv` | `scripts/validate_phase2.py` over `scripts/build_set64_esterno.py` |
| external set `v1_misto` with originals, 19 families: **6/26 (23 %)** | `reports/validation_phase2_esterna.md` · `.csv` | idem |
| samples without an original, proxy criterion: **13/40 plausible (32 %)**, coverage 40/179 (22 %), 13/179 (7 %) over the whole set | `reports/validation_fase_f_livello2.md` · `.csv` | `scripts/score_fase_f_livello2.py` |

> The 100 % of the 64-bit control and the 71 % of the matrix **are not directly
> comparable**: the 64-bit set uses five packers and Inno Setup is not among them, whereas
> in the matrix the 53 Inno samples weigh in full on the denominator. The honest point of
> comparison is the 89 %.

> On protectors, `partial` is the good outcome rather than a failure: the original code no
> longer exists as a byte sequence, so byte-for-byte identity is not expected and those
> samples do not enter the reconstruction rate.

## How to reproduce

The Phase 1 metrics can be re-checked **immediately**, with no samples at all, because
the CSV and the manifest are joined on the hash:

```bash
python -m pip install -r requirements-fase1.txt
python scripts/validate_phase1.py --csv reports/report_analisi_lief.csv --manifest reports/ground_truth.json
```

Everything else needs the samples, which are not distributed. The check that reports what
is missing, naming the file and the constant to fix for each item:

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
digest verified; the 353-sample matrix, which needs the full packer toolchain; the 64-bit
control; the nine synthetic PE files used by the tests, which are not committed; the 44
tests, one of which is an `expectedFailure` on purpose and documents a known defect in
its docstring.

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
| capa | 9.4.0 | **disabled** by default: on 189 files it consumed 96 % of the phase time and changed 0 verdicts |
| UPX | 5.1.1 | packing, and `-d` as the first rung of the cascade |
| 7-Zip | 26.00 | installer and SFX extraction |
| innounp | 0.50 | Inno Setup extraction |
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
