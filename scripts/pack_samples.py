"""
pack_samples.py
===============
Generatore della MATRICE di campioni packed a label CERTA per la validazione
della Fase 1.

L'etichetta di questi campioni non e' un'inferenza di uno strumento: e' il fatto
di aver eseguito il packer. E' l'unica fonte di ground truth di packing certa al
100 %, ed e' anche l'unica APPAIATA (ogni campione conserva l'sha256 del suo
originale pulito), che permette il confronto diretto prima/dopo sullo stesso
binario.

Differenze rispetto alla versione precedente, tutte volute:
  - GENERAZIONE DETERMINISTICA: non piu' un sottoinsieme casuale senza seed, ma
    una matrice riproducibile (master x packer) con `--seed` fisso.
  - I master sono selezionati per PROPRIETA': PE, privi di Control Flow Guard
    (UPX rifiuta i file con CFG: `GUARD_CF enabled PE files are not supported`),
    bilanciati fra x86 e x64 per non lasciare l'architettura come confondente.
  - Ogni combinazione produce un file di OUTPUT DISTINTO: l'originale non viene
    mai toccato, cosi' un multilayer non dipende da un pack in-place precedente.
  - Packer verificati via CLI: UPX, MPRESS, VMProtect (console), Themida (con
    file di progetto .tmd), NSIS, Inno Setup. PECompact e ASPack sono esclusi
    perche' solo-GUI in queste build.
  - MANIFEST per SHA-256 in append, non piu' un report per-nome sovrascritto.

Uso:
    python scripts/pack_samples.py --masters 2            # smoke test: 2 master
    python scripts/pack_samples.py                        # matrice completa
    python scripts/pack_samples.py --packers UPX,MPRESS   # solo alcuni packer
    python scripts/pack_samples.py --no-multilayer
"""
import argparse
import csv
import hashlib
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

import lief
try:
    lief.logging.disable()
except Exception:
    pass

# ==========================================
# PERCORSI DEI TOOL (verificati via CLI)
# ==========================================
UPX_PATH = r"E:\Tools\upx\upx-5.1.1-win64\upx.exe"
MPRESS_PATH = r"E:\Tools\mpress\mpress.exe"
VMPROTECT_PATH = r"E:\Tools\VMProtect Demo\VMProtect_Con.exe"
THEMIDA_X86 = (r"E:\Tools\Themida.exe", r"E:\Tools\themida_x86.tmd")
THEMIDA_X64 = (r"E:\Tools\Themida64.exe", r"E:\Tools\themida_x64.tmd")
MAKENSIS_PATH = r"C:\Program Files (x86)\NSIS\makensis.exe"
ISCC_PATH = r"E:\Tools\Inno Setup 6\ISCC.exe"

# ==========================================
# CARTELLE
# ==========================================
SOURCES = [
    (r"E:\DATASET\03_NON_ETICHETTATI\legacy_misto", "mingw"),
    (r"E:\DATASET\01_LABEL_CERTA\system32", "msvc"),
]
MASTERS_DIR = r"E:\DATASET\02_MATERIA_PRIMA\masters"
OUTPUT_DIR = r"E:\DATASET\01_LABEL_CERTA\matrice_packed"
MANIFEST = os.path.join(OUTPUT_DIR, "manifest.csv")

# ==========================================
# SELEZIONE DEI MASTER
# ==========================================
IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000
MASTER_MIN_SIZE = 10_000
MASTER_MAX_SIZE = 3_000_000
ARCH_TARGET = 30            # master per architettura (x86 e x64)
MSVC_PER_ARCH = 10          # quota MSVC per architettura; il resto viene da MinGW
                            # (MSVC senza CFG e' scarso: il CFG e' default nelle toolchain
                            #  MSVC moderne, quindi il set master resta MinGW-dominante)

# Un master NON deve essere gia' pacchettizzato: se lo e', la label `layers` del
# campione generato e' sbagliata (es. "Themida" quando il file e' "UPX + Themida")
# e `origin_sha256` punta a un binario non pulito, cioe' il disegno appaiato salta.
# Misurato: 2 master su 56 del run del 24/09/2026 erano gia' UPX (NBHextract, RAIU),
# entrambi gia' etichettati `packed` in ground_truth.json.
# Fonte di verita' della tabella: header_elf_lief.PACKER_SECTION_PREFIXES (qui
# duplicata di proposito, per tenere il generatore indipendente dalla pipeline).
PACKER_SECTION_PREFIXES = (
    "upx", ".upx", ".mpress", ".aspack", ".adata", ".ndata", ".vmp", ".themida",
    ".winlice", ".petite", ".nsp", ".pec", ".packed", ".enigma", ".perplex", ".pelock",
)


def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(chunk), b""):
            h.update(c)
    return h.hexdigest()


def _sec_name(section):
    """Nome di sezione SEMPRE come str. LIEF restituisce `bytes` quando il nome non e'
    UTF-8 valido, che e' esattamente il caso dei packer (VMProtect 3.x randomizza i nomi
    con byte non stampabili): senza normalizzare, ogni .startswith() solleva TypeError e
    il controllo "gia' packato" fallirebbe proprio sui file che deve intercettare."""
    name = section.name
    if isinstance(name, (bytes, bytearray)):
        raw = bytes(name).strip(b"\x00")
        name = "".join(chr(c) if 0x20 <= c < 0x7f else f"\\x{c:02x}" for c in raw)
    return (name or "").strip("\x00")


def _already_packed(binary):
    """Nome del packer se una sezione tradisce un packing gia' applicato, altrimenti None."""
    for section in binary.sections:
        lname = _sec_name(section).lower()
        for prefix in PACKER_SECTION_PREFIXES:
            if lname.startswith(prefix):
                return _sec_name(section)
    return None


def _is_dotnet(binary):
    """True per un assembly managed. Il test e' la data directory CLR_RUNTIME_HEADER,
    NON l'import di mscoree.dll: gli assembly a 64 bit e quelli piu' recenti possono non
    avere alcuna import table. Misurato sul set master: mscoree ne trova 8 su 9, e il
    mancante (x64_msvc_3c4de3f013d4) e' proprio quello su cui UPX falliva con
    `CantPackException: .NET files are not yet supported`."""
    try:
        for directory in binary.data_directories:
            if "CLR" in str(directory.type) and directory.size > 0:
                return True
    except Exception:
        pass
    try:
        return "mscoree.dll" in [str(i.name).lower() for i in binary.imports]
    except Exception:
        return False


def pe_info(path):
    """(usable, arch, has_cfg, flags) senza sollevare. arch in {'x86','x64'}.

    usable=True solo per PE con sottosistema GUI/CUI: i binari NATIVE, EFI o
    boot (subsystem != 2,3) sono rifiutati dai packer user-mode (`CantPackException:
    subsystem 16 is not supported`, `unsupported subsystem`) e non sono master validi.

    flags["packed"]  nome della sezione di packer trovata, se il file e' GIA' packato
                     (il chiamante lo scarta: un master packato falsifica `layers`).
    flags["dotnet"]  assembly managed. NON viene scartato: UPX e MPRESS lo rifiutano,
                     ma Themida/VMProtect/NSIS/Inno lo avvolgono, e quei campioni sono
                     gli unici .NET packed a label certa del dataset. Va pero' REGISTRATO,
                     perche' un AnyCPU ha machine=I386 e finisce etichettato `x86` pur non
                     essendo un binario a 32 bit: senza questa colonna l'asse architettura
                     - che e' il confondente dichiarato - resta sporco."""
    flags = {"packed": None, "dotnet": False}
    try:
        b = lief.parse(path)
    except Exception:
        return False, None, False, flags
    if b is None or not isinstance(b, lief.PE.Binary):
        return False, None, False, flags
    sub = str(b.optional_header.subsystem)
    if "GUI" not in sub and "CUI" not in sub:
        return False, None, False, flags
    arch = "x64" if "64" in str(b.header.machine) else "x86"
    try:
        cfg = bool(int(b.optional_header.dll_characteristics) & IMAGE_DLLCHARACTERISTICS_GUARD_CF)
    except Exception:
        cfg = False
    flags["packed"] = _already_packed(b)
    flags["dotnet"] = _is_dotnet(b)
    return True, arch, cfg, flags


def gather_candidates():
    """Per ogni (sorgente, arch): elenco dei master idonei.
    Ritorna (cells, rejected): `cells` mappa (source, arch) -> lista di (path, dotnet),
    `rejected` conta i motivi di scarto, cosi' la selezione e' ispezionabile invece
    che silenziosa."""
    cells = {}
    rejected = {"non_pe_o_subsystem": 0, "cfg": 0, "gia_packato": []}
    for directory, source in SOURCES:
        if not os.path.isdir(directory):
            print(f"[!] sorgente mancante, saltata: {directory}")
            continue
        for name in sorted(os.listdir(directory)):
            if not name.lower().endswith(".exe"):
                continue
            path = os.path.join(directory, name)
            if not os.path.isfile(path):
                continue
            size = os.path.getsize(path)
            if not (MASTER_MIN_SIZE < size < MASTER_MAX_SIZE):
                continue
            usable, arch, cfg, flags = pe_info(path)
            if not usable:                             # non PE, o sottosistema non user-mode
                rejected["non_pe_o_subsystem"] += 1
                continue
            if cfg:                                    # UPX rifiuta i file con Control Flow Guard
                rejected["cfg"] += 1
                continue
            if flags["packed"]:                        # master gia' packato: falsifica `layers`
                rejected["gia_packato"].append((name, flags["packed"]))
                continue
            cells.setdefault((source, arch), []).append((path, flags["dotnet"]))
    return cells, rejected


def select_masters(seed, want_masters=None):
    """Copia i master scelti in MASTERS_DIR (deterministico) e ritorna la lista di dict."""
    cells, rejected = gather_candidates()
    if rejected["gia_packato"]:
        print(f"[!] {len(rejected['gia_packato'])} candidati SCARTATI perche' gia' packati "
              f"(un master packato falsifica la label `layers` del campione generato):")
        for name, sec in rejected["gia_packato"][:10]:
            print(f"      {name}  (sezione {sec})")
    print(f"[*] Scartati: {rejected['non_pe_o_subsystem']} non-PE/sottosistema, "
          f"{rejected['cfg']} con Control Flow Guard, {len(rejected['gia_packato'])} gia' packati")
    rng = random.Random(seed)
    chosen = []
    for arch in ("x86", "x64"):
        msvc = cells.get(("msvc", arch), [])[:]
        mingw = cells.get(("mingw", arch), [])[:]
        rng.shuffle(msvc)
        rng.shuffle(mingw)
        take_msvc = msvc[:MSVC_PER_ARCH]
        take_mingw = mingw[:max(0, ARCH_TARGET - len(take_msvc))]
        for p in take_msvc:
            chosen.append((p, arch, "msvc"))
        for p in take_mingw:
            chosen.append((p, arch, "mingw"))
    # Limite opzionale per lo smoke test: si mantiene il bilanciamento prendendo
    # alternativamente da x86 e x64.
    if want_masters is not None:
        x86 = [c for c in chosen if c[1] == "x86"]
        x64 = [c for c in chosen if c[1] == "x64"]
        chosen = []
        for i in range(want_masters):
            src = x86 if (i % 2 == 0 and x86) else (x64 if x64 else x86)
            if src:
                chosen.append(src.pop(0))

    os.makedirs(MASTERS_DIR, exist_ok=True)
    masters = []
    for (path, dotnet), arch, source in chosen:
        h = sha256(path)
        dst = os.path.join(MASTERS_DIR, f"{arch}_{source}_{h[:12]}.exe")
        if not os.path.exists(dst):
            shutil.copy2(path, dst)
        masters.append({"path": dst, "arch": arch, "source": source, "dotnet": dotnet,
                        "origin_sha256": h, "stem": f"{arch}_{source}_{h[:12]}"})
    n_net = sum(1 for m in masters if m["dotnet"])
    if n_net:
        print(f"[*] {n_net} master sono assembly .NET: UPX e MPRESS li rifiutano "
              f"(`.NET files are not yet supported`), Themida/VMProtect/NSIS/Inno no. "
              f"Un AnyCPU ha machine=I386 e risulta 'x86': vedi la colonna is_dotnet del manifest.")
    return masters


# ==========================================
# PACKER: (input, output, arch) -> (ok, messaggio)
# Ognuno lascia l'input intatto e scrive un file di output DISTINTO.
# ==========================================
def _run(cmd, timeout):
    return subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=timeout)


def pack_upx(src, out, arch):
    shutil.copy2(src, out)
    r = _run([UPX_PATH, "-9", "-f", "-q", out], 120)
    ok = r.returncode == 0 and os.path.exists(out)
    return ok, (r.stderr or r.stdout or "").strip()[:200] if not ok else ""


def pack_mpress(src, out, arch):
    # MPRESS lavora IN PLACE: si packa la copia di destinazione.
    # NB: l'opzione storica "-r" NON e' "overwrite" ma "do not compress resources"
    # (help di MPRESS 2.19): va tolta, riduce solo la compressione.
    shutil.copy2(src, out)
    try:
        r = _run([MPRESS_PATH, "-q", out], 60)
    except subprocess.TimeoutExpired:
        subprocess.run(["taskkill", "/F", "/IM", "mpress.exe"], capture_output=True)
        return False, "MPRESS in timeout (si blocca sugli x64 gia' compressi con UPX)"
    ok = r.returncode == 0 and os.path.exists(out)
    return ok, (r.stdout or r.stderr or "").strip()[:200] if not ok else ""


def pack_vmprotect(src, out, arch):
    r = _run([VMPROTECT_PATH, src, out], 900)
    ok = r.returncode == 0 and os.path.exists(out)
    return ok, (r.stdout or r.stderr or "").strip()[:200] if not ok else ""


def pack_themida(src, out, arch):
    exe, proj = THEMIDA_X64 if arch == "x64" else THEMIDA_X86
    if not (os.path.isfile(exe) and os.path.isfile(proj)):
        return False, f"Themida {arch}: exe o progetto .tmd mancante"
    r = _run([exe, "/protect", proj, "/inputfile", src, "/outputfile", out,
              "/q", "/shareconsole"], 1200)
    ok = os.path.exists(out)
    return ok, (r.stdout or r.stderr or "").strip()[:200] if not ok else ""


def pack_nsis(src, out, arch):
    """Wrapping in un installer NSIS self-extracting silenzioso (dropper)."""
    if not os.path.isfile(MAKENSIS_PATH):
        return False, "makensis non trovato"
    tmp = tempfile.mkdtemp(prefix="nsis_")
    try:
        payload = os.path.join(tmp, "payload.exe")
        shutil.copy2(src, payload)
        nsi = os.path.join(tmp, "w.nsi")
        with open(nsi, "w", encoding="utf-8") as f:
            f.write(f'''Unicode true
SilentInstall silent
RequestExecutionLevel user
OutFile "{out}"
Section
    InitPluginsDir
    SetOutPath "$PLUGINSDIR"
    File "{payload}"
    ExecWait '"$PLUGINSDIR\\payload.exe"'
SectionEnd
''')
        r = _run([MAKENSIS_PATH, "/V2", nsi], 120)
        ok = r.returncode == 0 and os.path.exists(out)
        return ok, (r.stdout or r.stderr or "").strip()[:200] if not ok else ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def pack_inno(src, out, arch):
    """Wrapping in un installer Inno Setup. ISCC compila uno script .iss che
    include il payload e produce un setup.exe in OUTPUT_DIR."""
    if not os.path.isfile(ISCC_PATH):
        return False, "ISCC non trovato"
    base = os.path.splitext(os.path.basename(out))[0]
    tmp = tempfile.mkdtemp(prefix="inno_")
    try:
        payload = os.path.join(tmp, "payload.exe")
        shutil.copy2(src, payload)
        iss = os.path.join(tmp, "w.iss")
        # ISCC scrive in OutputDir\OutputBaseFilename.exe: si punta ESATTAMENTE a `out`,
        # che durante un multilayer vive in una cartella temporanea, non in OUTPUT_DIR.
        out_dir = os.path.dirname(os.path.abspath(out))
        with open(iss, "w", encoding="utf-8") as f:
            f.write(f'''[Setup]
AppName=Sample
AppVersion=1.0
DefaultDirName={{tmp}}\\sample
Uninstallable=no
OutputDir={out_dir}
OutputBaseFilename={base}
[Files]
Source: "{payload}"; DestDir: "{{app}}"; Flags: ignoreversion
''')
        r = _run([ISCC_PATH, "/Q", iss], 180)
        ok = r.returncode == 0 and os.path.exists(out)
        return ok, (r.stdout or r.stderr or "").strip()[:200] if not ok else ""
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


PACKERS = {
    "UPX": pack_upx,
    "MPRESS": pack_mpress,
    "VMProtect": pack_vmprotect,
    "Themida": pack_themida,
    "NSIS": pack_nsis,
    "Inno": pack_inno,
}

# Combinazioni multilayer a due strati (il secondo si applica sull'output del primo).
# `archs` limita la combinazione alle architetture su cui si e' scelto di tentarla.
# CORREZIONE 24/09/2026: la restrizione x86-only era motivata con "MPRESS si BLOCCA su un
# x64 gia' compresso con UPX". Rimisurato: MPRESS NON si blocca, esce in 0 s con rc 7/9/10
# e non scrive nulla - e rifiuta anche 11 dei 19 x86 gia' compressi con UPX (resa reale
# 8/30). Non e' quindi una proprieta' dell'architettura ma dell'input gia' compresso.
# La restrizione resta come scelta deliberata (evita 26 tentativi a resa attesa bassa);
# per tentare anche gli x64 basta aggiungere "x64" alla tupla: il costo e' ~0 s per
# fallimento. I wrapper (NSIS/Inno) incapsulano qualunque payload, quindi valgono per
# entrambe.
MULTILAYER = [
    {"stack": ("UPX", "MPRESS"), "archs": ("x86",)},
    {"stack": ("UPX", "NSIS"), "archs": ("x86", "x64")},
]


# ==========================================
# GENERAZIONE
# ==========================================
def load_manifest():
    """Righe gia' presenti + set dei filename gia' generati (lo skip e' per nome).
    Le righe prodotte prima dell'aggiunta di `is_dotnet` vengono completate leggendo
    il master corrispondente: senza il backfill la colonna resterebbe vuota per tutti
    i campioni gia' su disco, cioe' inutilizzabile senza rigenerare la matrice."""
    seen = set()
    rows = []
    if not os.path.exists(MANIFEST):
        return rows, seen
    cache = {}
    with open(MANIFEST, "r", encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            if not row.get("is_dotnet"):
                stem = row["filename"].rsplit("_", 1)[0]
                if stem not in cache:
                    master = os.path.join(MASTERS_DIR, stem + ".exe")
                    cache[stem] = pe_info(master)[3]["dotnet"] if os.path.isfile(master) else ""
                row["is_dotnet"] = "1" if cache[stem] is True else ("0" if cache[stem] is False else "")
            rows.append(row)
            seen.add(row["filename"])
    return rows, seen


MANIFEST_FIELDS = ["filename", "sha256", "layers", "origin_sha256", "arch", "source",
                   "is_dotnet", "size_in", "size_out", "generated_at"]


def write_manifest(rows):
    # restval="": le righe scritte da una versione precedente non hanno `is_dotnet`
    # e non devono far fallire la riscrittura (il backfill le completa, vedi load_manifest).
    with open(MANIFEST, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS, restval="")
        w.writeheader()
        w.writerows(rows)


def apply_stack(master, stack, work_dir):
    """Applica in sequenza i packer di `stack`. Ritorna (output_path | None, messaggio)."""
    cur = master["path"]
    tmp_files = []
    for i, packer in enumerate(stack):
        nxt = os.path.join(work_dir, f"{master['stem']}_{'-'.join(stack[:i+1])}.exe")
        ok, msg = PACKERS[packer](cur, nxt, master["arch"])
        if not ok:
            for t in tmp_files:
                if os.path.exists(t):
                    os.remove(t)
            return None, f"{packer}: {msg}"
        if cur != master["path"]:
            tmp_files.append(cur)
        cur = nxt
    for t in tmp_files:                        # ripulisce gli intermedi, tiene solo il finale
        if os.path.exists(t) and t != cur:
            os.remove(t)
    return cur, ""


def build(masters, packers, do_multilayer):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    rows, seen = load_manifest()
    work = tempfile.mkdtemp(prefix="packwork_")
    single = [[p] for p in packers]
    multi = []
    if do_multilayer:
        multi = [ml for ml in MULTILAYER if all(p in packers for p in ml["stack"])]

    stats = {"ok": 0, "fail": 0, "skip": 0}
    fails = []
    try:
        for m in masters:
            print(f"\n[master] {m['stem']}  ({m['arch']}, {m['source']})")
            # i multilayer sono filtrati per architettura (vedi MULTILAYER)
            stacks = single + [list(ml["stack"]) for ml in multi if m["arch"] in ml["archs"]]
            for stack in stacks:
                label = "-".join(stack)
                final_name = f"{m['stem']}_{label}.exe"
                if final_name in seen:
                    stats["skip"] += 1
                    continue
                out_final = os.path.join(OUTPUT_DIR, final_name)
                produced, msg = apply_stack(m, stack, work)
                if produced is None:
                    stats["fail"] += 1
                    fails.append((final_name, msg))
                    print(f"   [-] {label:<14} FALLITO: {msg}")
                    continue
                if os.path.abspath(produced) != os.path.abspath(out_final):
                    shutil.move(produced, out_final)
                row = {"filename": final_name, "sha256": sha256(out_final),
                       "layers": " + ".join(stack), "origin_sha256": m["origin_sha256"],
                       "arch": m["arch"], "source": m["source"],
                       "is_dotnet": "1" if m["dotnet"] else "0",
                       "size_in": os.path.getsize(m["path"]), "size_out": os.path.getsize(out_final),
                       "generated_at": time.strftime("%Y-%m-%d %H:%M:%S")}
                rows.append(row)
                seen.add(final_name)
                stats["ok"] += 1
                write_manifest(rows)          # incrementale: un'interruzione non perde il lavoro
                ratio = 100 * row["size_out"] // max(row["size_in"], 1)
                print(f"   [+] {label:<14} {row['size_in']} -> {row['size_out']} B ({ratio}%)")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    print("\n" + "=" * 60)
    print(f"MATRICE: {stats['ok']} generati, {stats['fail']} falliti, {stats['skip']} gia' presenti")
    print(f"manifest: {MANIFEST}  ({len(rows)} campioni totali)")
    if fails:
        print("Falliti (packer: motivo):")
        for name, msg in fails[:20]:
            print(f"   {name}: {msg}")
    print("=" * 60)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seed", type=int, default=20260923, help="Seed per la selezione dei master.")
    ap.add_argument("--masters", type=int, default=None,
                    help="Limita il numero di master (smoke test). Default: matrice completa.")
    ap.add_argument("--packers", default=None,
                    help="Sottoinsieme di packer separati da virgola (default: tutti).")
    ap.add_argument("--no-multilayer", action="store_true", help="Salta le combinazioni a due strati.")
    args = ap.parse_args()

    packers = list(PACKERS)
    if args.packers:
        packers = [p.strip() for p in args.packers.split(",") if p.strip() in PACKERS]
        if not packers:
            ap.error(f"nessun packer valido; scegli fra: {', '.join(PACKERS)}")

    masters = select_masters(args.seed, args.masters)
    if not masters:
        print("[-] Nessun master selezionato: verifica le cartelle sorgente.")
        return
    n_x86 = sum(1 for m in masters if m["arch"] == "x86")
    print(f"[*] Master selezionati: {len(masters)} (x86={n_x86}, x64={len(masters) - n_x86}) -> {MASTERS_DIR}")
    print(f"[*] Packer: {', '.join(packers)} | multilayer: {not args.no_multilayer}")
    build(masters, packers, not args.no_multilayer)


if __name__ == "__main__":
    main()
