"""
fetch_goodware_non_ms.py
========================
Costruisce la classe negativa NON-Microsoft di `01_LABEL_CERTA` scaricando
binari PE da repository UFFICIALI upstream ed estraendone solo `.exe` e `.dll`.

Perche' la provenienza e non uno scanner
----------------------------------------
Etichettare "clean" con un altro detector (VirusTotal, DIE, un dataset
accademico pre-filtrato) rende la misura tautologica: staremmo valutando il
nostro triage contro l'output di chi ha costruito la label. Qui l'oracolo e' la
PROVENIENZA: il file arriva dal repository ufficiale del progetto che lo
produce, e dove il repository pubblica un digest lo verifichiamo prima di
accettare l'archivio (MSYS2 -> `%SHA256SUM%` del database pacman; Cygwin ->
sha512 di `setup.ini`; VLC/PuTTY -> file `.sha256`/`sha256sums` upstream).
Resta un oracolo di provenienza, NON una verifica strutturale: va dichiarato
come tale in tesi, esattamente come per `pypi`.

Cosa NON entra, per costruzione
-------------------------------
- Tool di reverse engineering / packer (FLARE VM & co.): inquinerebbero la
  classe negativa con binari legittimamente protetti. Nessun pacchetto del
  genere e' in SOURCES e `SKIP_NAME_RE` fa da rete di sicurezza.
- INSTALLER e self-extracting archive (`*setup*.exe`, NSIS, Inno, SFX): sono
  STRUTTURALMENTE packed - `matrice_packed` usa proprio Inno e NSIS come
  packer. Un installer benigno etichettato "clean" sarebbe un falso negativo
  iniettato a mano nel ground truth. Per questo si scaricano solo archivi
  "piatti" (.zip, .tar.xz, .pkg.tar.zst) di binari gia' compilati, mai gli
  installer che gli stessi progetti pubblicano.
- Sysinternals e altri binari firmati Microsoft: sono goodware, ma sono MS e
  li copre gia' l'oracolo `authenticode-ms` su `system32`. Qui servono
  toolchain diverse (MinGW-w64, Cygwin, MSVC di terze parti, llvm-mingw).

Uso
---
    python scripts/fetch_goodware_non_ms.py --list
    python scripts/fetch_goodware_non_ms.py --dry-run
    python scripts/fetch_goodware_non_ms.py                     # tutte le sorgenti
    python scripts/fetch_goodware_non_ms.py --only msys2_mingw64 cygwin
    python scripts/fetch_goodware_non_ms.py --cache             # tiene gli archivi per i rerun

Poi, per far entrare i file nel ground truth della pipeline:

    python scripts/build_ground_truth.py \
        --import-labels config/goodware_non_ms_labels.json \
        --labels-dir "E:/DATASET/01_LABEL_CERTA/goodware_non_ms" --stats
"""
import argparse
import csv
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile

import requests

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

from pipeline_utils import setup_logger, PARENT_DIR  # noqa: E402

log = setup_logger("GoodwareNonMS")

DEST_ROOT = os.environ.get("GOODWARE_NON_MS_ROOT",
                           os.path.join("E:" + os.sep, "DATASET", "01_LABEL_CERTA",
                                        "goodware_non_ms"))
MANIFEST_CSV = "manifest.csv"
MANIFEST_FIELDS = ["filename", "sha256", "source", "type", "size",
                   "archive", "archive_sha256", "archive_verified", "member"]
LABELS_JSON = os.path.join(PARENT_DIR, "config", "goodware_non_ms_labels.json")
LABEL_ORACLE = "dist-ufficiale-non-ms"

HEADERS = {"User-Agent": "tesi-packing-dataset/1.0 (ricerca accademica)"}
TIMEOUT = (15, 180)          # (connect, read): un mirror lento non deve bloccare il run
RETRIES = 3
PE_EXT = (".exe", ".dll")

# Rete di sicurezza: anche se un archivio ufficiale contenesse un installer o un
# packer, non finisce nel dataset. Meglio perdere un campione che iniettare un
# binario strutturalmente packed nella classe "clean".
# I nomi vanno riconosciuti come TOKEN, non come sottostringhe: `mpress` dentro
# `opj_decompress.exe` e `libcompressor_plugin.dll` non e' il packer MPRESS, e
# `install.exe` e' la `install` di GNU coreutils, non un installer. Il primo
# tentativo, senza i confini, scartava cinque binari legittimi.
SKIP_NAME_RE = re.compile(
    r"(?<![a-z0-9])("
    r"setup|sfx|7zs\w*|unins\w*|installer|installshield"           # installer/SFX
    r"|upx|mpress|aspack|petite|themida|vmprotect|enigma|molebox"    # packer/protector
    r"|obsidium|pecompact|nsis|inno"
    r")(?![a-z])", re.I)


# ==========================================
# HTTP
# ==========================================
def http_get(url, stream=False):
    """GET con retry/backoff. Solleva requests.RequestException dopo RETRIES."""
    last = None
    for attempt in range(1, RETRIES + 1):
        try:
            r = requests.get(url, headers=HEADERS, timeout=TIMEOUT, stream=stream)
            r.raise_for_status()
            return r
        except requests.RequestException as e:
            last = e
            if attempt < RETRIES:
                wait = 2 ** attempt
                log.warning("  GET %s fallita (%s). Riprovo fra %ds [%d/%d]"
                            % (url[:90], type(e).__name__, wait, attempt, RETRIES))
                time.sleep(wait)
    raise last


def final_url(url):
    """URL dopo i redirect (per le sorgenti che espongono un 'latest')."""
    r = requests.head(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=True)
    r.raise_for_status()
    return r.url


def file_digest(path, algo):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 256), b""):
            h.update(chunk)
    return h.hexdigest()


def download(url, dest, expected=None, algo="sha256"):
    """Scarica in streaming calcolando il digest. Ritorna l'hex digest.

    Se `expected` e' noto e non combacia, il file viene CANCELLATO e si solleva
    ValueError: un archivio che non corrisponde al digest pubblicato dal
    repository non ha provenienza certa, quindi non ha nulla da fare qui.
    """
    h = hashlib.new(algo)
    r = http_get(url, stream=True)
    tmp = dest + ".part"
    try:
        with open(tmp, "wb") as f:
            for chunk in r.iter_content(1024 * 256):
                h.update(chunk)
                f.write(chunk)
    finally:
        r.close()
    got = h.hexdigest()
    if expected and got.lower() != expected.lower():
        os.remove(tmp)
        raise ValueError("digest %s non corrisponde: atteso %s..., ottenuto %s..."
                         % (algo, expected[:16], got[:16]))
    os.replace(tmp, dest)
    return got


# ==========================================
# RISOLUTORI (evitano URL che invecchiano)
# ==========================================
def _sums_lookup(text, suffix):
    """Cerca in un file di checksum la riga che termina con `suffix`."""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].endswith(suffix):
            return parts[0]
    return None


def resolve_vlc():
    """videolan.org pubblica lo zip portatile + il proprio .sha256 (e .asc)."""
    base = "https://get.videolan.org/vlc/last/win64/"
    names = re.findall(r'href="(vlc-[\d.]+-win64\.zip)"', http_get(base).text)
    if not names:
        raise RuntimeError("nessuno zip win64 nell'indice VLC")
    name = sorted(names)[-1]
    return [{"url": base + name,
             "sha256": http_get(base + name + ".sha256").text.split()[0]}]


def resolve_putty():
    """Il tag 'latest' redirige alla versione corrente; i sums sono upstream."""
    base = "https://the.earth.li/~sgtatham/putty/latest/"
    return [{"url": base + "w64/putty.zip",
             "sha256": _sums_lookup(http_get(base + "sha256sums").text, "w64/putty.zip")}]


def resolve_notepadpp():
    """La release ufficiale sta su GitHub: uso il redirect di /releases/latest per
    ricavare il tag (l'API REST e' rate-limited e qui non serve)."""
    tag = final_url("https://github.com/notepad-plus-plus/notepad-plus-plus/"
                    "releases/latest").rsplit("/", 1)[-1]
    ver = tag.lstrip("v")
    return [{"url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/"
                    "download/%s/npp.%s.portable.x64.zip" % (tag, ver)}]


def resolve_curl_for_win():
    """curl.se/windows: build ufficiali del progetto curl (llvm-mingw).
    Pubblica solo firme PGP, non un .sha256: l'hash lo registriamo noi."""
    return [{"url": final_url("https://curl.se/windows/latest.cgi?p=win64-mingw.zip")}]

def resolve_nodejs():
    """nodejs.org/dist pubblica SHASUMS256.txt accanto agli archivi. Il nome del file
    lo leggo dalla riga stessa del digest: cosi' non puo' sfasarsi dalla versione."""
    base = "https://nodejs.org/dist/latest/"
    for line in http_get(base + "SHASUMS256.txt").text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].endswith("-win-x64.zip"):
            return [{"url": base + parts[-1], "sha256": parts[0]}]
    raise RuntimeError("nessuno zip win-x64 in SHASUMS256.txt di Node.js")


def resolve_golang():
    """go.dev/dl?mode=json espone filename e sha256 di ogni archivio ufficiale.
    Prendo la release stabile piu' recente, archivio zip windows/amd64."""
    for release in http_get("https://go.dev/dl/?mode=json").json():
        for f in release.get("files", []):
            if (f.get("os") == "windows" and f.get("arch") == "amd64"
                    and f.get("kind") == "archive" and f.get("sha256")
                    and f["filename"].endswith(".zip")):
                return [{"url": "https://dl.google.com/go/" + f["filename"],
                         "sha256": f["sha256"]}]
    raise RuntimeError("nessun archivio windows/amd64 nel feed di go.dev")


def resolve_temurin():
    """API Adoptium: per ogni asset pubblica link e checksum sha256 del pacchetto.
    Chiedo il JDK Windows x64 della LTS 21 in forma di archivio zip, non l'installer."""
    url = ("https://api.adoptium.net/v3/assets/latest/21/hotspot"
           "?os=windows&architecture=x64&image_type=jdk")
    for asset in http_get(url).json():
        pkg = asset.get("binary", {}).get("package", {})
        if pkg.get("link", "").endswith(".zip") and pkg.get("checksum"):
            return [{"url": pkg["link"], "sha256": pkg["checksum"]}]
    raise RuntimeError("nessun pacchetto zip nel feed Adoptium")

def _parse_desc(desc):
    """Un record `desc` di pacman: %CHIAVE% seguita dai suoi valori."""
    keys = re.findall(r"%([A-Z0-9]+)%", desc)
    blocks = re.split(r"%[A-Z0-9]+%", desc)[1:]
    return {k: (b.strip().splitlines()[0] if b.strip() else "")
            for k, b in zip(keys, blocks)}


def resolve_pacman(repo, db, packages):
    """Database pacman di MSYS2: da' filename E %SHA256SUM% ufficiale.
    Leggerlo evita di cablare versioni che diventano 404 fra due mesi."""
    import zstandard  # opzionale: solo le sorgenti MSYS2 ne hanno bisogno

    raw = zstandard.ZstdDecompressor().decompress(
        http_get("%s/%s" % (repo, db)).content, max_output_size=512 * 1024 * 1024)
    wanted, found = set(packages), {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        for member in tf.getmembers():
            if not member.name.endswith("/desc"):
                continue
            fields = _parse_desc(tf.extractfile(member).read().decode("utf-8", "replace"))
            name = fields.get("NAME")
            if name in wanted and name not in found:
                found[name] = {"url": "%s/%s" % (repo, fields["FILENAME"]),
                               "sha256": fields.get("SHA256SUM") or None}
    for missing in sorted(wanted - set(found)):
        log.warning("  pacchetto non trovato nel db %s: %s" % (db, missing))
    return [found[k] for k in sorted(found)]


def resolve_cygwin(mirror, arch, packages):
    """setup.ini di Cygwin: la PRIMA riga `install:` dopo `@ <pkg>` e' la release
    corrente (poi seguono le sezioni [test]/[prev]). Terzo campo = sha512."""
    ini = http_get("%s/%s/setup.ini" % (mirror, arch)).text
    out = []
    for pkg in packages:
        block = ini.split("\n@ %s\n" % pkg, 1)
        if len(block) < 2:
            log.warning("  pacchetto non presente in setup.ini: %s" % pkg)
            continue
        for line in block[1].splitlines():
            if line.startswith("["):        # sezione [test]/[prev]: troppo tardi
                break
            if line.startswith("install:"):
                parts = line.split()
                out.append({"url": "%s/%s" % (mirror, parts[1]),
                            "sha512": parts[3] if len(parts) > 3 else None})
                break
        else:
            log.warning("  nessuna riga install: per %s" % pkg)
    return out
def resolve_dotnet_sdk():
    """I metadati di release .NET pubblicano url e hash sha512 di ogni file.
    Prendo l'SDK Windows x64 in archivio zip, non l'installer, del canale LTS."""
    index = http_get("https://builds.dotnet.microsoft.com/dotnet/"
                     "release-metadata/releases-index.json").json()
    lts = [c for c in index["releases-index"]
           if c.get("release-type") == "lts"
           and c.get("support-phase") in ("active", "maintenance")]
    if not lts:
        raise RuntimeError("nessun canale LTS attivo nell'indice .NET")
    channel = sorted(lts, key=lambda c: c["channel-version"])[-1]
    release = http_get(channel["releases.json"]).json()["releases"][0]
    for f in release.get("sdk", {}).get("files", []):
        if f.get("rid") == "win-x64" and f["name"].endswith(".zip"):
            return [{"url": f["url"], "sha512": f["hash"]}]
    raise RuntimeError("nessun SDK win-x64 zip nella release .NET")


def resolve_php():
    """windows.php.net pubblica un solo sha256sum.txt per tutte le release correnti.
    Prendo il runtime x64, escludendo i pacchetti debug e devel."""
    base = "https://windows.php.net/downloads/releases/"
    for line in http_get(base + "sha256sum.txt").text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"php-\d+\.\d+\.\d+-Win32-vs\d+-x64\.zip",
                                            parts[-1]):
            return [{"url": base + parts[-1], "sha256": parts[0]}]
    raise RuntimeError("nessun runtime PHP x64 in sha256sum.txt")


def resolve_julia():
    """versions.json di julialang elenca ogni release con url e sha256 per file.
    Prendo l'archivio zip winnt/x86_64 della versione stabile piu' recente."""
    data = http_get("https://julialang-s3.julialang.org/bin/versions.json").json()
    stable = sorted((v for v, info in data.items()
                     if info.get("stable") and re.fullmatch(r"\d+\.\d+\.\d+", v)),
                    key=lambda v: [int(x) for x in v.split(".")])
    if not stable:
        raise RuntimeError("nessuna versione stabile in versions.json di Julia")
    for f in data[stable[-1]]["files"]:
        if (f.get("os") == "winnt" and f.get("arch") == "x86_64"
                and f.get("kind") == "archive" and f["url"].endswith(".zip")):
            return [{"url": f["url"], "sha256": f["sha256"]}]
    raise RuntimeError("nessun archivio zip winnt/x86_64 per Julia")


# ==========================================
# SORGENTI (aggiungerne una = aggiungere un dict)
# ==========================================
MSYS2_MINGW64 = ["mingw-w64-x86_64-" + p for p in (
    "curl", "openssl", "sqlite3", "zlib", "xz", "zstd", "bzip2", "expat",
    "libpng", "libjpeg-turbo", "giflib", "libtiff", "freetype", "harfbuzz",
    "libxml2", "libxslt", "pcre2", "gettext-tools", "libiconv", "libarchive",
    "libwebp", "openjpeg2", "cairo", "glib2", "nghttp2", "libssh2", "brotli",
    "lua", "nasm", "graphviz", "gnutls",
)]
MSYS2_MSYS = ("msys2-runtime", "bash", "coreutils", "findutils", "grep", "sed",
              "gawk", "tar", "gzip", "diffutils", "less", "file", "which",
              "patch", "make", "openssh", "rsync")
CYGWIN = ("cygwin", "coreutils", "bash", "findutils", "grep", "sed", "gawk",
          "tar", "gzip", "xz", "diffutils", "less", "file", "which", "patch",
          "make", "openssl", "curl", "rsync", "cygutils")

SOURCES = [
    {"name": "msys2_mingw64",
     "note": "repo ufficiale MSYS2 mingw64 (GCC MinGW-w64), digest dal db pacman",
     "resolve": lambda: resolve_pacman("https://repo.msys2.org/mingw/mingw64",
                                       "mingw64.db", MSYS2_MINGW64)},
    {"name": "msys2_msys",
     "note": "repo ufficiale MSYS2 msys (runtime Cygwin-like), digest dal db pacman",
     "resolve": lambda: resolve_pacman("https://repo.msys2.org/msys/x86_64",
                                       "msys.db", MSYS2_MSYS)},
    {"name": "cygwin",
     "note": "mirror ufficiale Cygwin (sourceware/kernel.org) x86_64, sha512 da setup.ini",
     "resolve": lambda: resolve_cygwin("https://mirrors.kernel.org/sourceware/cygwin",
                                       "x86_64", CYGWIN)},
    {"name": "vlc",
     "note": "zip portatile ufficiale VideoLAN (get.videolan.org) + .sha256 upstream",
     "resolve": resolve_vlc},

    {"name": "notepadpp",
     "note": "zip portable ufficiale della release GitHub di Notepad++ (MSVC)",
     "resolve": resolve_notepadpp},

    {"name": "putty",
     "note": "zip ufficiale PuTTY (the.earth.li/~sgtatham) + sha256sums upstream",
     "resolve": resolve_putty},

    {"name": "curl_for_win",
     "note": "build ufficiali curl per Windows (curl.se/windows, llvm-mingw)",
     "resolve": resolve_curl_for_win},

    {"name": "nodejs",
     "note": "zip ufficiale nodejs.org + SHASUMS256.txt upstream",
     "resolve": resolve_nodejs},

    {"name": "nodejs",
     "note": "zip ufficiale nodejs.org + SHASUMS256.txt upstream (MSVC)",
     "resolve": resolve_nodejs},

    {"name": "golang",
     "note": "archivio zip ufficiale go.dev, sha256 dal feed JSON (toolchain Go)",
     "resolve": resolve_golang},

    {"name": "temurin",
     "note": "JDK Windows x64 di Eclipse Adoptium, checksum dall'API v3 (MSVC + bundling)",
     "resolve": resolve_temurin},

    {"name": "dotnet_sdk",
     "note": "SDK .NET LTS win-x64, url e sha512 dai metadati di release ufficiali",
     "resolve": resolve_dotnet_sdk},

    {"name": "php",
     "note": "runtime PHP x64 di windows.php.net + sha256sum.txt upstream",
     "resolve": resolve_php},

    {"name": "julia",
     "note": "archivio zip ufficiale JuliaLang, sha256 da versions.json",
     "resolve": resolve_julia},
     
]


# ==========================================
# PE: riconoscimento e estrazione
# ==========================================
def looks_pe(head):
    """MZ + e_lfanew -> 'PE\\0\\0'. Se e_lfanew cade oltre l'head letto ci si
    ferma a MZ + estensione: serve a scartare script/dati, non a fare triage."""
    if head[:2] != b"MZ" or len(head) < 0x40:
        return False
    off = int.from_bytes(head[0x3C:0x40], "little")
    if off <= 0 or off + 4 > len(head):
        return True
    return head[off:off + 4] == b"PE\0\0"


def iter_members(archive):
    """(nome, apri()) per ogni file dell'archivio. Streaming: i .pkg.tar.zst non
    vengono mai materializzati in RAM."""
    low = archive.lower()
    if low.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    yield info.filename, lambda i=info: zf.open(i)
        return
    fh = None
    if low.endswith(".zst"):
        import zstandard
        fh = open(archive, "rb")
        tf = tarfile.open(fileobj=zstandard.ZstdDecompressor().stream_reader(fh),
                          mode="r|")
    else:
        tf = tarfile.open(archive, mode="r|*")
    try:
        for member in tf:
            if member.isfile():
                yield member.name, lambda m=member: tf.extractfile(m)
    finally:
        tf.close()
        if fh:
            fh.close()


def flat_name(member):
    """Il percorso interno entra nel nome: due `bin/openssl.exe` di pacchetti
    diversi non si sovrascrivono e resta tracciabile da dove vengono."""
    name = re.sub(r"[\\/]+", "__", member.lstrip("./"))
    name = re.sub(r"[^A-Za-z0-9._+-]", "_", name)
    if len(name) > 180:
        stem, ext = os.path.splitext(name)
        name = stem[:180 - len(ext)] + ext
    return name


def extract_pe(archive, dest_dir, seen, source, archive_sha, verified, rows):
    """Estrae SOLO i PE .exe/.dll: il resto non viene mai scritto su disco, quindi
    non c'e' nulla da ripulire dopo. Dedup per SHA-256, perche' la stessa dll
    ricorre in molti pacchetti e i duplicati falserebbero i conteggi."""
    kept = dup = 0
    for member, opener in iter_members(archive):
        base = os.path.basename(member)
        if not base.lower().endswith(PE_EXT):
            continue
        if SKIP_NAME_RE.search(base):
            log.info("  [skip] %s (nome da installer/packer)" % base)
            continue
        stream = opener()
        if stream is None:
            continue
        try:
            head = stream.read(4096)
            if not looks_pe(head):
                log.debug("  scartato non-PE: %s" % member)
                continue
            out_name = "%s__%s" % (source, flat_name(member))
            tmp = os.path.join(dest_dir, out_name + ".part")
            h, size = hashlib.sha256(head), len(head)
            with open(tmp, "wb") as f:
                f.write(head)
                while True:
                    chunk = stream.read(1024 * 256)
                    if not chunk:
                        break
                    h.update(chunk)
                    size += len(chunk)
                    f.write(chunk)
        finally:
            stream.close()
        sha = h.hexdigest()
        if sha in seen:
            os.remove(tmp)
            dup += 1
            continue
        seen.add(sha)
        os.replace(tmp, os.path.join(dest_dir, out_name))
        rows.append({"filename": out_name, "sha256": sha, "source": source,
                     "type": os.path.splitext(base)[1].lower().lstrip("."),
                     "size": size, "archive": os.path.basename(archive),
                     "archive_sha256": archive_sha,
                     "archive_verified": "yes" if verified else "no",
                     "member": member})
        kept += 1
    return kept, dup


# ==========================================
# MANIFEST E LABEL
# ==========================================
def load_seen(manifest_path):
    """Hash gia' nel manifest: rende il rerun idempotente e incrementale."""
    seen = set()
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                if row.get("sha256"):
                    seen.add(row["sha256"])
        log.info("Manifest esistente: %d hash gia' presenti" % len(seen))
    return seen


def append_manifest(manifest_path, rows):
    """Append + flush + fsync a fine sorgente: se il run muore a meta', quello che
    e' finito su disco e' comunque gia' descritto nel manifest."""
    if not rows:
        return
    new = not os.path.exists(manifest_path)
    with open(manifest_path, "a", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
        if new:
            w.writeheader()
        w.writerows(rows)
        f.flush()
        os.fsync(f.fileno())


def dedup_manifest(manifest_path):
    """Riscrive il manifest tenendo una riga per SHA-256.

    L'append durante il run serve a sopravvivere a un'interruzione, ma non
    garantisce l'unicita': due run sovrapposti (accaduto: un processo creduto
    morto stava ancora scrivendo) raddoppiano le righe. La chiave primaria e'
    l'hash, quindi la condizione da far valere e' "una riga per hash".
    """
    if not os.path.exists(manifest_path):
        return 0
    with open(manifest_path, "r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    unique, seen = [], set()
    for r in rows:
        if r["sha256"] not in seen:
            seen.add(r["sha256"])
            unique.append(r)
    removed = len(rows) - len(unique)
    if removed:
        tmp = manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
            w.writeheader()
            w.writerows(unique)
        os.replace(tmp, manifest_path)
        log.warning("Manifest: rimosse %d righe duplicate (%d campioni unici)"
                    % (removed, len(unique)))
    return removed


def write_labels(manifest_path):
    """File di label per `build_ground_truth.py --import-labels`: l'oracolo vive
    in un file versionato nel repo, non in comandi una tantum.

    Si rigenera dal MANIFEST, non dalle righe di questo run: cosi' il file resta
    coerente con il dataset anche se un run precedente e' morto a meta'."""
    labels = {}
    with open(manifest_path, "r", encoding="utf-8", newline="") as f:
        for r in csv.DictReader(f):
            labels[r["filename"]] = {
                "label": "clean",
                "packers": [],
                "source": LABEL_ORACLE,
                "note": ("Binario da distribuzione ufficiale non-Microsoft '%s' "
                         "(archivio %s, sha256 %s..., digest upstream %s; membro %s). "
                         "Oracolo di PROVENIENZA, non verifica strutturale: da "
                         "dichiarare come tale."
                         % (r["source"], r["archive"], r["archive_sha256"][:16],
                            "verificato" if r["archive_verified"] == "yes"
                            else "NON pubblicato", r["member"])),
            }
    os.makedirs(os.path.dirname(LABELS_JSON), exist_ok=True)
    tmp = LABELS_JSON + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(labels, f, indent=2, ensure_ascii=False, sort_keys=True)
    os.replace(tmp, LABELS_JSON)
    log.info("Label scritte: %s (%d voci)" % (LABELS_JSON, len(labels)))


# ==========================================
# MAIN
# ==========================================
def run_source(src, dest_root, cache_dir, keep_cache, seen, dry_run):
    name = src["name"]
    log.info("=== %s: %s" % (name, src["note"]))
    try:
        targets = src["resolve"]()
    except Exception as e:
        log.error("  risoluzione fallita (%s: %s): sorgente saltata"
                  % (type(e).__name__, str(e)[:160]))
        return []
    log.info("  %d archivi da scaricare" % len(targets))
    if dry_run:
        for t in targets:
            has = t.get("sha256") or t.get("sha512")
            log.info("    %s%s" % (t["url"], "" if has else "   [!] nessun digest upstream"))
        return []

    dest_dir = os.path.join(dest_root, name)
    os.makedirs(dest_dir, exist_ok=True)
    rows = []
    for t in targets:
        url = t["url"]
        archive = os.path.join(cache_dir, os.path.basename(url.split("?")[0]))
        algo, expected = (("sha512", t["sha512"]) if t.get("sha512")
                          else ("sha256", t.get("sha256")))
        try:
            if os.path.exists(archive):
                log.info("  [cache] %s" % os.path.basename(archive))
                got = file_digest(archive, algo)
                if expected and got.lower() != expected.lower():
                    raise ValueError("archivio in cache non combacia col digest upstream")
            else:
                got = download(url, archive, expected, algo)
            verified = bool(expected)
            if not verified:
                log.warning("  [!] %s: nessun digest upstream verificabile, registro "
                            "il nostro" % os.path.basename(archive))
            archive_sha = got if algo == "sha256" else file_digest(archive, "sha256")
            kept, dup = extract_pe(archive, dest_dir, seen, name, archive_sha,
                                   verified, rows)
            log.info("  %s -> %d PE nuovi (%d duplicati scartati)"
                     % (os.path.basename(archive), kept, dup))
        except (requests.RequestException, ValueError, tarfile.TarError,
                zipfile.BadZipFile, OSError, RuntimeError, ImportError) as e:
            log.error("  %s: %s (%s) - archivio saltato"
                      % (os.path.basename(url), type(e).__name__, str(e)[:160]))
        finally:
            if not keep_cache and os.path.exists(archive):
                os.remove(archive)
    append_manifest(os.path.join(dest_root, MANIFEST_CSV), rows)
    return rows


def main():
    ap = argparse.ArgumentParser(
        description="Dataset di goodware non-Microsoft a provenienza certa.")
    ap.add_argument("--dest", default=DEST_ROOT,
                    help="Radice di output (default: %(default)s)")
    ap.add_argument("--only", nargs="+", metavar="NOME", help="Esegui solo queste sorgenti.")
    ap.add_argument("--list", action="store_true", help="Elenca le sorgenti e esci.")
    ap.add_argument("--dry-run", action="store_true", help="Risolvi gli URL e mostra "
                    "quali hanno un digest upstream, senza scaricare nulla.")
    ap.add_argument("--cache", action="store_true", help="Tieni gli archivi scaricati "
                    "nella temp di sistema per i rerun (default: cancellati subito).")
    args = ap.parse_args()

    if args.list:
        for s in SOURCES:
            print("  %-16s %s" % (s["name"], s["note"]))
        return 0

    sources = SOURCES
    if args.only:
        unknown = set(args.only) - {s["name"] for s in SOURCES}
        if unknown:
            ap.error("sorgenti sconosciute: %s (usa --list)" % ", ".join(sorted(unknown)))
        sources = [s for s in SOURCES if s["name"] in set(args.only)]

    # Gli archivi NON stanno sotto <dest>: make_dataset_index.py fa os.walk sulla
    # cartella del dataset e conterebbe uno .zip come campione non etichettato.
    cache_dir = os.path.join(tempfile.gettempdir(), "goodware_non_ms_cache")
    lock = os.path.join(tempfile.gettempdir(), "goodware_non_ms.lock")
    if not args.dry_run:                    # --dry-run non deve creare nulla su disco
        os.makedirs(cache_dir, exist_ok=True)
        # Due run sovrapposti si pestano i piedi: stessi file di destinazione e
        # righe di manifest raddoppiate. E' gia' capitato, quindi non e' teorico.
        try:
            os.close(os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        except FileExistsError:
            sys.exit("Un altro run e' in corso (oppure e' morto lasciando %s: "
                     "verifica e cancella quel file)." % lock)
    seen = load_seen(os.path.join(args.dest, MANIFEST_CSV))

    by_source, t0 = {}, time.time()
    try:
        for src in sources:
            rows = run_source(src, args.dest, cache_dir, args.cache, seen, args.dry_run)
            if rows:
                by_source[src["name"]] = rows
    finally:
        if not args.dry_run:
            if not args.cache:
                shutil.rmtree(cache_dir, ignore_errors=True)
            os.unlink(lock)

    manifest_path = os.path.join(args.dest, MANIFEST_CSV)
    if os.path.exists(manifest_path):
        dedup_manifest(manifest_path)
        write_labels(manifest_path)
    total = sum(len(r) for r in by_source.values())
    log.info("FATTO: %d PE nuovi in %s in %.0fs" % (total, args.dest, time.time() - t0))
    for name, rows in sorted(by_source.items()):
        exe = sum(1 for r in rows if r["type"] == "exe")
        log.info("  %-16s %4d file (%d exe, %d dll)" % (name, len(rows), exe, len(rows) - exe))
    return 0


if __name__ == "__main__":
    sys.exit(main())
