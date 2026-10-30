# Phase 2 — Automated Unpacking

*Thesis text, English. Terminology and ordering follow `docs/figure/fase2_flow` and
`docs/figure/fase2_oracle`; code identifiers, column names and state values are left
untranslated, including the three outcome labels `ricostruito`, `parziale` and `fallito`.
Every figure is reproducible from the measurement reports without re-running the pipeline:
`Pipeline_Reports/validation_phase2.csv` (§5), `validation_set64.csv` (§5.2),
`validation_phase2_esterna.csv` and `validation_fase_f_livello2.csv` (§5.3).*

---

## 1. Purpose and scope

Phase 1 decides whether a Portable Executable is packed without running it. Phase 2 takes the
files it marked (`Is_Packed_Label = 1`) and attempts to recover the payload underneath, so that
an analyst receives code that can be read statically instead of a compressed or encrypted blob.

The objective is deliberately narrower than "defeat packing". It is to **reduce the number of
samples that require manual reverse engineering**, and to do so without ever claiming a success
that did not occur. The second half of that sentence is what most of this chapter is about:
an unpacking pipeline that cannot tell a correct result from a plausible one produces numbers
that cannot be used.

The scope is **PE only**, both `.exe` and `.dll`. ELF support is deferred to future work and is
not implemented: the binary-information routine returns nothing for a non-PE input and the
caller skips the file, recording it as `out_of_scope_not_pe`. One further component,
`mal_unpack`, is implemented but disabled, because it is the only step that would execute the
sample on the host rather than emulate it; it contributed no results and is therefore absent
from both the figure and the measurements, which describe the configuration that was actually
run.

## 2. Architecture: a cascade ordered by cost

Phase 2 is a cascade of tools applied in order of **increasing cost**, stopping at the first
success. The ordering is not a matter of taste. A static decompressor that inverts a known
format is both faster and more trustworthy than an emulator that must run adversarial code far
enough to observe its payload, so the cheap deterministic options are exhausted first and
emulation is a fallback, not a default.

Two decisions precede the cascade.

**Routing inherited from Phase 1.** The detection that Phase 1 already produced
(`Die_Packer_Type`, `Die_Packer_Name`, `Die_All_Packers`) is passed to Phase 2 as a hint, and it
determines **which branch is taken**, not merely the order of attempts within one branch. If any
detection describes the file as an installer or a self-extracting archive, the file is routed to
the container extractors and emulation is not attempted at all. The reason is that emulating an
installer produces the installer's own code, correctly unpacked and entirely useless: a wrong
answer that looks right. Containers are *opened*, never emulated.

**Resume and a disk guard.** Outcomes are keyed by SHA-256 in `pipeline_state.json`, so a batch
that stops can be resumed; files already resolved are skipped, while files left in
`needs_manual_review` are retried. Before each file, the pipeline checks for at least 500 MB of
free space and stops the batch otherwise. The asymmetry is intentional: a truncated measurement
is resumable, a corrupted one is not.

## 3. The path of a single file

### 3.1 Reading the figure

> **Figure N — Phase 2: the complete control flow.** The diagram shows the configuration that
> was actually measured: PE inputs only, with ELF out of scope and `mal_unpack` disabled. Four
> mechanisms are deliberately kept out of the nodes and explained in the text — why a container
> is opened rather than emulated (§2), the write-then-execute entry-point heuristic (§3.2), what
> the PE rebuild does and does not do (§3.2 and §7), and the Ghidra threshold (§3.2). The figure
> and this section are written to be read together; neither is self-contained.

The figure draws the whole of Phase 2 as a control flow, read from top to bottom. Although it
spans ten levels, its shape is simple, and seeing that shape first makes the rest of this section
easier to follow: a mostly linear descent, interrupted by one decision that chooses a branch
before any tool has run, a second decision that closes the only cycle in the diagram, and two
exits at the bottom. Everything else is detail hung on that skeleton.

What enters at the top is not a directory of files but a judgement that has already been made
elsewhere. Phase 1 has examined every binary without executing it and has marked a subset
`Is_Packed_Label = 1`; only those reach Phase 2, and they do not arrive alone. The same analysis
produced a detection — the three fields `Die_Packer_Type`, `Die_Packer_Name` and
`Die_All_Packers` — and that detection travels with the file. The first node states on its face
that this hint decides the route and not merely the order of attempts, because the claim is easy
to read past and the remainder of the diagram depends on it. The hint is not an optimisation that
saves a few seconds of trial and error; it determines which half of the system the file is handed
to, and handing it to the wrong half produces a result that looks correct and is not.

Immediately below, three preconditions are drawn as a single box because they act as a single
gate. The file must be a Portable Executable, since ELF is outside the implemented scope; its
SHA-256 must not already be recorded as resolved in `pipeline_state.json`, which is what allows an
interrupted batch to resume without redoing work; and at least 500 MB of disk space must remain.
A file failing any of the three leaves the flow sideways into a note rather than into a terminal
state, and the distinction is deliberate: nothing was attempted on it, so nothing may be concluded
about it either. The disk check earns a place in a diagram about unpacking for a reason that is
not self-evident. A batch that stops cleanly when space runs low can be resumed from where it
stopped, whereas one that runs out of space in the middle of writing a dump leaves behind
truncated files that are indistinguishable, to every later stage, from genuine results.

The first diamond is where the hint does its work, and it is the only branch taken before any tool
executes. The question it asks is whether *any* detection described the file as an installer or a
self-extracting archive — any, deliberately, and not only the primary one, because a single
detection naming a container is enough to make emulation the wrong instrument. The asymmetry has a
concrete cause. An installer that is emulated will run, and it will yield code: the installer's
own unpacking stub, correctly recovered and completely useless, since the payload the analyst
wants was never the installer. A container must therefore be *opened* rather than unpacked, and
the figure labels that edge accordingly.

The grey cluster beneath holds the two mutually exclusive branches and carries the rule that
governs both of them: the cascade stops at the first success. On the left, container extraction
with 7-Zip and InnoUnp. On the right, the packer cascade proper, ordered by increasing cost — UPX
first, because inverting a known format statically is both the fastest option and the only one
whose output needs no interpretation; then AspackDie, invoked only when the hint actually names
ASPack, since it is a graphical tool that would otherwise open a blocking window on anything it
does not recognise; and emulation last, Unipacker for 32-bit samples and Qiling for 64-bit. That
ordering is the architectural claim of the phase, and it is vindicated by the measurements: the
static branch accounts for most of what the system recovers. The two branches converge at once,
because from the pipeline's point of view the only question that matters next is whether something
came off.

If a layer did come off and the file still looks packed, the dashed edge carries the output back
to the routing diamond — and specifically to the diamond, not to the top of the cascade. That
target is the entire point of multi-layer handling. Each round re-asks what the file has now
become, so a UPX-compressed payload discovered inside an NSIS installer is routed to UPX on the
second pass rather than offered to the extractor a second time. The loop runs at most five times —
a ceiling set a priori and deliberately generous, which the measurements never approached: the
deepest chain observed removed two layers (§3.2). It is the only cycle in the figure.

The descent then reaches two steps that are not about finding the payload but about making it
usable and about deciding whether to believe it. A memory dump taken under emulation is not a
loadable file, so the PE rebuild repairs the entry point, realigns the sections and disables ASLR;
what it does not repair is the import table, which is the single most consequential limitation of
this phase and the reason the word "reconstructed" carries a narrower meaning here than it appears
to. Ghidra headless then opens the result and counts functions. It is worth being precise about
what that check is for: it does not establish that the unpacking was correct, only that the output
contains enough recognisable code to be worth an analyst's attention.

Two terminal states end the flow, and the figure keeps distinct the two different routes into the
second of them. A file becomes `unpacked_ok` when Ghidra is convinced. It becomes
`needs_manual_review` either because no automatic tool removed anything at all, or because
something was produced and did not convince — failures that look identical in a summary count and
are not the same thing, the first being an absence of coverage and the second a doubt about
quality. Both outcomes are written to `pipeline_state.json` keyed by SHA-256, which is what makes
the run resumable and what every later measurement reads.

The heavier box at the very bottom is deliberately outside all of this. `validate_phase2.py` is
not a pipeline step: it runs afterwards, reads the recorded outcomes and compares each produced
file against the clean original it was built from. It appears inside the same figure in order to
make one fact visible at a glance — that nothing upstream of it decides whether an unpacking was
correct. The verification inside the flow judges whether a result deserves an analyst's time; the
oracle at the bottom judges whether it is the right payload. Collapsing those two judgements into
one is precisely the error that an earlier version of this work made, and §4 and the companion
figure `fase2_oracle` are about keeping them apart.

### 3.2 The steps in detail

For a file that reaches the cascade, one round proceeds as follows.

**Containers** (if Phase 1 called it an installer or SFX): 7-Zip for NSIS, SFX, CAB and ZIP,
then InnoUnp for Inno Setup. The largest extracted payload is taken and the uninstaller is
excluded.

**Packers and protectors** (otherwise): UPX first, invoked twice — plain `-d`, then
`-d --force`, because the second recovers headers that packers deliberately alter. Then
AspackDie, but only if the hint actually names ASPack, since it is a graphical tool that opens a
blocking window on anything else. Then emulation: Unipacker for 32-bit samples, Qiling for
64-bit.

**Entry-point recovery under emulation.** The emulator must decide *when* the payload has been
unpacked, which is the hard part. The heuristic used is **write-then-execute**: a packer must
write the payload into memory before it can execute it, so the original entry point is the first
address executed inside a page that the process itself has rewritten. Two parameters keep this
from firing on noise — a 200-block warm-up, because the runtime's own start-up is not a jump
into the payload, and a 4 KB minimum of written bytes, because a relocation fix-up is not a
payload. If the heuristic never fires, a dump is still taken at the end of emulation rather than
losing the attempt entirely.

**Multi-layer iteration.** After a layer is removed, the file is re-examined: if it still looks
packed, the output is fed back into the cascade.

The ceiling of five rounds is a parameter set *a priori* and deliberately generous. It was not
derived from any measurement and is not claimed to be an optimum: it was chosen as headroom, so
that the runs themselves could establish how deep layering actually goes rather than having that
answer fixed in advance by a tight limit. The loop exits as soon as a round removes nothing or the
file stops showing signs of packing, so a ceiling that is not needed costs nothing.

It was never needed. Across the **607 samples** on which Phase 2 was attempted, the deepest chain
removed **two** layers; 43 samples reached that depth, 252 removed a single layer, and the limit
of five was **never reached** — `layer_limit_reached` is false for every sample in every run. The
generous ceiling is therefore reported here as a result rather than as a setting: in none of the
corpora examined in this work does packing nest beyond two levels. Correspondingly, nothing is
claimed about how the pipeline would behave at depths it was never asked to handle.

If no tool removed anything, the file goes to `needs_manual_review`.

**PE reconstruction** (Qiling only, since a memory dump is not a loadable file): the entry point
is rewritten, sections are realigned and ASLR is disabled. **The import table is not rebuilt.**
This is a declared limitation with a direct consequence for how results may be worded, discussed
in §7.

**Independent verification**: Ghidra headless must find at least five functions. The file then
ends as `unpacked_ok`, or as `needs_manual_review` and is opened in IDA Free — or, with
`--defer-ida`, simply queued, which is mandatory for any unattended batch because IDA otherwise
blocks the process on a window that nobody will close.

## 4. The correctness oracle

Everything above describes a pipeline. What makes its output a measurement is the oracle, and
this is the methodological core of the phase.

**The corpus was built, not collected.** 53 clean original programs were compiled in-house
across four toolchains (MSVC, MinGW, Go, Rust), then packed by `pack_samples.py` with six
packers and two chains, producing 353 samples whose manifest retains the `origin_sha256` of
every original. Because the clean original of every sample is known and on disk, the question
"did the unpacking work?" has a direct answer rather than a proxy.

`validate_phase2.py` compares the file that Phase 2 produced against the clean original. Both
are mapped as the loader would map them, so bytes are indexed **by RVA** and the comparison does
not depend on on-disk layout, which in a memory dump is necessarily different. Only the
executable sections of the original are compared. Three outcomes are distinguished, not two:

| outcome | meaning |
|---|---|
| `ricostruito` | matching bytes ≥ 95 %: the original payload is there |
| `parziale` | code is present but does not coincide |
| `fallito` | the section is missing or entirely zeros (non-zero bytes < 5 %) |

The middle category is the point. The criterion previously in use — "Ghidra found at least five
functions" — collapses `parziale` and `ricostruito` into a single "success", and that is not a
hypothetical concern: it had already promoted a dump whose code section was entirely zeros, in
which Ghidra declared 1011 functions.

**The ruler is checked before it is trusted.** A self-test compares a file with itself, which
must yield 1.0, and with a different file, which must yield substantially less. If those two
numbers are wrong there is no reason to look at any other number.

## 5. Results

On the internal matrix of 353 samples, every one of which was processed:

| | |
|---|---|
| `ricostruito` | **178 / 252 = 71 %** |
| excluding the 53 Inno samples (see §7) | 178 / 199 = 89 % |
| `parziale` | 29 |
| **false successes** | **0** |
| samples still requiring human review | 142 / 353 |

The 252 denominator excludes the 101 virtualizing-protector samples, for which byte identity is
not the target and is reported separately. The 71 % figure is the one to quote; the 89 % is a
secondary reading that must always travel with its label, since excluding Inno is defensible —
it is a defect of the corpus, not of the pipeline — but it is not the headline.

**By tool**, across all 353: UPX handled 85 samples and reconstructed all 85; 7-Zip 54 and
reconstructed 53; Qiling 50, producing 24 `ricostruito` and 26 `parziale` with no failures on
anything it attempted; Unipacker 22, producing 16, 3 and 3. UPX and 7-Zip together account for
138 of the 178 reconstructions, that is 78 %: the numerical result comes largely from **routing
correctly toward deterministic static tools**, not from emulation. Reading only that, however,
is misleading, because Qiling is the only tool that obtains anything at all from Themida, and
those 26 partial results could not be produced by any static tool by construction. The two
emulators produce fewer results, on ground that is theirs alone.

### 5.1 The distribution of outcomes is bimodal

The three labels suggest a continuum — reconstructed, then partial, then failed — and the corpus
says the opposite. Of the 210 comparisons actually measured, **141 match the original exactly
(1.0000)**, while the 26 Themida partials lie between 0.0370 and 0.1412 with a median of 0.0678.
Exactly **one sample out of 353** falls in between, at 0.857. Three consequences follow, and they
govern how every number above should be read.

**When the cascade works, the result is byte-identical, not approximate.** The 71 % does not mean
"71 % done imperfectly"; it means **71 % done exactly and 29 % not done at all**. The only
gradual degradation in the corpus is the 37 reconstructions below 1.0000 (minimum 0.9586), and it
has a single cause: the dump is a snapshot of memory, in which relocations are already applied
and the import table is not.

**`parziale` on a protector must always carry its number.** Stating that `parziale` is the good
outcome for Themida is correct but reads badly, suggesting a near-reconstruction. The median
match of those 26 samples is 0.0678. The original bytes are not there, because a protector does
not compress code, it replaces it with bytecode for its own virtual machine; the remaining 7 % is
incidental overlap — alignment padding, compiler boilerplate, runtime stubs. For a protector,
`ricostruito` is not a difficult target but an **ill-posed** one, and the defensible claim is
"analyzable", not "reconstructed".

**`fallito` almost always means "no file to compare", not "wrong file".** Of 143 failures, **140
carry the note `nessun output prodotto`**: the tool refused or stopped early and the oracle never
had anything in hand. Only three produced a file with a zeroed executable section. Phase 2's
failures are therefore **not reconstruction errors but refusals upstream**, each with a verified
diagnosis: 53 Inno, 48 VMProtect, 27 Themida at 32-bit, 9 MPRESS and 3 two-layer chains.

### 5.2 A control set on third-party programs

One objection to the 71 % is that the originals are small in-house test programs, whereas real
software is larger, has more imports, comes from different toolchains and has a less regular
section layout. To test this, 10 executables from six third-party projects — VLC, MSYS2/MinGW64,
Cygwin, Notepad++, PuTTY and curl — were packed with the same packers, yielding 48 samples, all
64-bit, which additionally exercises the Qiling branch.

The result is **28 / 28 on compressors and installers**, with 21 matching exactly, against
74 / 76 = 97 % for the same families at 64-bit on the internal matrix. **This is not an external
validation and must not be called one**: the packers are still ours, and only the original
programs changed. It is a robustness control, and it is reported separately and never summed with
the 71 %.

Its most useful outcome is not the 100 %. The 10 Themida samples land between 0.0501 and 0.0903,
median 0.0784 — the same band measured on the internal matrix, on different programs and a single
architecture, with nothing falling between 0.0903 and 0.9902. The bimodal distribution of §5.1 is
therefore reproduced on an independent corpus and is not an artefact of how the internal matrix
was built.

### 5.3 External validation: packers applied by third parties

The validation specified in `docs/07` was signed on commit `7379138` before execution, together
with two scope restrictions recorded in §13 of that protocol, also before any run: the manual
inspection of 30 samples was dropped, and level 2 was limited to the `v1_misto` corpus, leaving
145 real-malware samples unprocessed. Both restrictions are declared, and what they cost is
stated in §7.

**Level 1 — the strong oracle, 29 pairs, 20 packer families of which 17 unseen.** With the
unchanged oracle and the unchanged thresholds, the result is **6 / 26 = 23 %** on compressors,
the 3 Themida pairs being reported separately as before. This is the only figure in this work
directly comparable with the 71 %, and the distance between the two is precisely the limitation
that the internal corpus had declared.

The structure of the result matters more than the rate:

| | |
|---|---|
| pairs on families with a dedicated unpacker | **6 / 8 reconstructed** |
| pairs on families without one | **0 / 21** |

The six natively supported families were named in the protocol *before* the run. The generic
unpacker and the emulation branch contributed nothing on unseen families. **The external reach of
the pipeline is therefore not a measure of its engineering but of its tool inventory**: adding a
family means adding a tool, not redesigning the cascade.

The bimodal distribution of §5.1 appears here in its sharpest form. Five of the six
reconstructions match at exactly 1.0000 and the sixth at 0.9940; there are **zero partial
results**, and all 23 failures carry `nessun output prodotto`. Only six of the twenty-nine
comparisons were ever performed.

This also dissolves a weakness the protocol had declared in advance. §3.2 of the protocol warned that a `fallito`
on one of the eighteen families whose pairing could not be verified would be ambiguous between
"the pipeline failed" and "the pairing was wrong". Since every failure produced no file at all,
no comparison took place, and the pairing assumption cannot have contaminated the figure.

The pre-registered prediction was 30–50 %. It was wrong, and §9 of the protocol had fixed in
advance how to read that: a result below the internal corpus is not a failure of the work but the
measurement of how easy that corpus was.

**Level 2 — proxy criterion, not correctness.** On the 179 remaining packed samples of
`v1_misto`, the cascade produced an evaluable output for **40**; of those, **13** satisfy all four
pre-declared conditions — 13 / 40 of the samples with an output, 13 / 179 overall. The criterion
was never validated against human judgment, so this is coverage with a quality filter and not a
reconstruction rate.

Two observations. First, the condition that discriminates is the fourth: re-running Phase 1 on the
output still reports 27 of the 40 as packed, while the entry-point and Ghidra conditions pass on
all 40 and the entropy condition rejects 6. Three of the four separate almost nothing on this
corpus and the fourth does the work — which is the argument for having required all four rather
than the Ghidra count alone.

Second, and more serious: by tool, UPX scores 6 of 6 and 7-Zip 7 of 8, while **Unipacker scores 0
of 26**. Outside the families it natively supports, Unipacker does not fail — it emits a file that
is not the payload. That is the worst failure mode a tool in this cascade can have, and only the
oracle and the four-condition criterion keep it from inflating the result.

### 5.4 Quadro complessivo — interno ed esterno a confronto

*(Sezione in italiano, da tradurre insieme al resto. Tutte le cifre sono riproducibili dai
report in `Pipeline_Reports/` senza rieseguire la pipeline.)*

#### I tre corpora, e a cosa risponde ciascuno

| corpus | campioni | originali | packer | domanda |
|---|---|---|---|---|
| matrice interna | 353 | nostri (53, compilati in casa) | **nostri** (6 + 2 catene) | sappiamo disfare i packer che applichiamo noi? |
| controllo a 64 bit | 48 | **di terzi** (VLC, MSYS2, Cygwin, Notepad++, PuTTY, curl) | nostri | il 71% dipende dal fatto che gli originali sono programmi nostri? |
| validazione esterna | 29 coppie | di terzi | **di terzi** (20 famiglie, 17 mai viste) | quanto sopravvive su packer che non abbiamo applicato noi? |

#### Il risultato, nei tre corpora

| | matrice interna | controllo x64 | validazione esterna |
|---|---|---|---|
| **ricostruiti** | **178 / 252 = 71%** | **28 / 28 = 100%** | **6 / 26 = 23%** |
| parziali | 29 | 10 (tutti Themida) | **0** |
| falsi successi | **0** | **0** | **0** |
| corrispondenza esatta 1.0000 | 141 / 178 | 21 / 28 | 5 / 6 |
| carico manuale | 353 → 142 (**−60%**) | — | 208 → 162 (**−22%**) |

Il 71% sale all'89% escludendo i 53 campioni Inno, che sono un difetto del corpus e non della
pipeline (nessun estrattore libero supporta Inno Setup 6.7). Il numero da mettere in tabella resta
il 71%, con l'89% come lettura secondaria motivata.

#### Perché il tasso esterno è 23%, e cosa significa davvero

Il risultato è spiegato per intero da una sola variabile:

| | |
|---|---|
| coppie su famiglie **con** un unpacker dedicato | **6 / 8 ricostruite** |
| coppie su famiglie **senza** | **0 / 21** |

Le sei famiglie coperte nativamente — UPX, ASPack, FSG, MEW, MPRESS, PECompact — erano nominate
nel protocollo **prima** del run. Hanno funzionato tutte tranne PECompact e una delle due FSG;
fuori da quell'elenco, zero su ventuno. L'unpacker generico e il ramo di emulazione **non hanno
contribuito nulla** su famiglie mai incontrate.

Il 23% non misura quindi la qualità dell'instradamento ma l'ampiezza dell'**inventario degli
strumenti**: aggiungere una famiglia significa aggiungere un tool, non riprogettare la cascata.
La distanza fra il 71% e il 23% **è** il limite che la misura interna dichiarava di avere,
finalmente quantificato.

#### Confronto diretto sulle tre famiglie presenti in entrambi i corpora

| famiglia | interno | esterno |
|---|---|---|
| UPX | 42 / 44 | 2 / 2 |
| MPRESS | 40 / 50 | 1 / 1 |
| Themida | 0 / 53 (26 parziali) | 0 / 3 (0 parziali) |

Coerente, ma **una o due coppie per famiglia non sostengono un tasso**: va letto come "non
contraddice", non come conferma. È il limite principale della misura esterna, e il §5.5 indica
come superarlo.

#### Per strumento, sulla matrice interna

| strumento | gestiti | ricostruito | parziale | fallito |
|---|---|---|---|---|
| UPX | 85 | 85 | 0 | 0 |
| 7-Zip | 54 | 53 | 0 | 0 |
| Qiling | 50 | 24 | 26 | 0 |
| Unipacker | 22 | 16 | 3 | 3 |

UPX e 7-Zip da soli producono 138 dei 178 risultati, il **78%**: il risultato numerico viene in
gran parte dall'aver instradato correttamente verso strumenti statici e deterministici, non
dall'emulazione. Qiling è però l'unico che ottiene qualcosa da Themida, e non ha prodotto alcun
fallimento su ciò che ha tentato.

#### Le tre affermazioni che reggono su tutti e tre i corpora

**Zero falsi successi su 430 campioni** misurati contro un originale noto. In nessun corpus la
pipeline ha dichiarato un successo che non aveva.

**La distribuzione degli esiti è bimodale**, confermata tre volte in modo indipendente: o
corrispondenza prossima a 1.0000, o niente. Sulla matrice interna un solo campione su 353 cade in
mezzo (0.857); sul controllo a 64 bit nessuno fra 0.0903 e 0.9902; sulla validazione esterna
**zero parziali** su 29. I campioni Themida restano sempre nella stessa fascia — mediana 0.0678
sul corpus interno, 0.0784 su quello a 64 bit — perché un protector non comprime il codice ma lo
sostituisce con bytecode per una propria macchina virtuale.

**I fallimenti sono rifiuti a monte, non errori di ricostruzione:** 140 dei 143 interni e 23 su 23
esterni non hanno prodotto alcun file. Lo strumento si è rifiutato o si è fermato, e l'oracolo non
ha mai avuto niente da confrontare.

#### La formulazione per il capitolo dei risultati

> La pipeline ricostruisce **byte per byte** tutto ciò che il suo inventario di strumenti copre,
> con **zero falsi successi su 430 campioni**. Sul corpus interno il tasso di ricostruzione è
> **71%** e il carico manuale scende del **60%**; su packer applicati da terzi il tasso è **23%**
> e il carico scende del **22%**, differenza spiegata per intero da quali famiglie dispongano di
> un unpacker dedicato — 6 su 8 fra quelle coperte, 0 su 21 fra quelle scoperte.

Uno strumento che aiuta su una minoranza dei campioni e non dichiara mai un successo che non ha è
utilizzabile; uno che aiuta sulla maggioranza e ogni tanto sbaglia non lo è. Il contributo
metodologico di questa fase è l'oracolo che distingue i due casi, costruito dopo aver constatato
che il criterio precedente promuoveva a successo dei dump vuoti (§6).

## 6. Three episodes that belong in the method, not the results

Each of these is the reason a claim above is a measurement rather than an assertion.

**A dump of zeros declared a success.** Sample `awk_C57F` had a code section containing nothing
but zeros, and Ghidra reported 1011 functions in it. Under the function-count criterion it was a
success. This is what motivated building the oracle.

**Five installers at 2.6 %.** In an earlier run, five Inno Setup installers were approved by the
Ghidra criterion while matching the original on 2.6 % of bytes. In that same run Ghidra approved
15 samples and the oracle confirmed 7. A criterion that errs in this direction does not produce
optimistic numbers; it produces meaningless ones.

**The largest gain came from routing, not from emulation.** Two findings arrived together:
Unipacker was never actually being executed — its binary lives in the virtual environment's
`Scripts/` directory, which is absent from `PATH` when the pipeline is launched through the
interpreter directly, so 50 of 50 attempts failed instantly with a file-not-found error — and
7-Zip, which turned out to be the single largest contributor, was already installed. Fixing a
path and routing installers to an extractor moved more samples than any change to the emulation.

## 7. Declared limitations

**`ricostruito` does not mean "working executable".** The import table is not rebuilt: the code
bytes coincide, but calls to API functions remain raw addresses. The correct claim for this work
is therefore **restoring the static readability of the payload**, not restoring a runnable
binary.

**Virtualizing protectors are essentially unresolved**: 0 reconstructed out of 101. The accurate
statement is 26 of 101 "analyzable", 0 "reconstructed". VMProtect accounts for 48 of those and
fails for a specific, diagnosed reason: its stub maps its own file from disk and compares it with
memory, and under emulation that integrity check does not match, so the stub stops before
decompressing anything.

**Inno Setup is a corpus defect, not a pipeline defect.** The samples use Inno Setup 6.7, while
innounp 0.50 and innoextract 1.9 support up to 6.0.5. Both were verified. No free extractor
handles the version in the corpus, which is why those 53 samples are also reported with Inno
excluded.

**The internal corpus is easy and homogeneous**: 353 samples from 53 originals, six packers, one
version per packer, all applied by us. The 71 % states that the pipeline can undo the packers it
applied itself, and §5.3 quantifies what that is worth elsewhere: 23 % on third-party packers,
entirely accounted for by which families have a dedicated unpacker.

**Breadth is bounded by the tool inventory, and that is the honest claim.** On an arbitrary corpus
of unknown packers the pipeline will help with a minority of samples. What it will not do is claim
a success it does not have: across the three corpora of §5, §5.2 and §5.3 — 430 samples measured
against a known original — there are zero false successes. A tool that helps on a minority and
never misreports is usable; one that helps on most and occasionally misreports is not.

**One tool fails silently, and it is worth naming.** Outside the families it natively supports,
Unipacker returns a file that is not the payload rather than returning nothing: 0 of 26 at level 2
of §5.3. Every other tool in the cascade either succeeds or produces nothing. This is the single
most dangerous behaviour in the system, and it is contained only by the oracle, not by the tool.

**The Ghidra verification step earns very little, and the measurement says so.** It remains in the
cascade and runs on every file that produced an output — 295 across the three corpora — at a
median of **28 seconds each**, roughly 2.3 hours of wall clock in total. In exchange it rejected
**one** output of those 295. With a median function count of **480** against a threshold of
**five**, the threshold does not discriminate: in practice every file that yields a dump at all
yields one with hundreds of recognisable functions, and the single rejection had exactly one.

This is a measurement of a step that is usually assumed to be useful without being checked, and
the honest way to describe it is neither "Ghidra verifies the result" nor "Ghidra is unused". It
runs, it costs, and it almost never changes the outcome. Two things follow. First, it is **not** a
correctness check and must never be reported as one — that role belongs to the oracle of §4, and
conflating the two is the error documented in §6. Second, as a filter it is close to inert, and on
a larger corpus it would be a reasonable candidate for removal or for being made conditional. It
is retained here as a sanity check — a dump that genuinely contains no code would still be caught
— and because removing a step mid-measurement would have invalidated the comparison between runs.

**Two declared restrictions of the external validation.** Both were recorded in §13 of the
protocol before any run. The manual inspection of 30 samples was not carried out, so the level 2
figure has no measured agreement with human judgment and is reported as coverage only. The 145
real-malware samples were not processed, so **nothing in this work is measured on real malware**;
hypothesis 4 of the protocol — that the proxy rate would fall further on real malware — remains a
prediction that was never put to the test, and must be written as such.

**A timeout counts as a failure, not as "not measured".** From the standpoint of the stated
objective — reducing manual work — a file that does not finish in time remains on the analyst's
desk. The budgets are: UPX 15 s, AspackDie 8 s, InnoUnp 60 s, 7-Zip 120 s, Unipacker 300 s,
Qiling 600 s, Ghidra 600 s.
