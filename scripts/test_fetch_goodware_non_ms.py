"""
test_fetch_goodware_non_ms.py
=============================
Self-check OFFLINE di `fetch_goodware_non_ms.py`: nessuna rete, nessun
framework. Copre i quattro punti dove un bug silenzioso sporcherebbe il
dataset senza che nessuno se ne accorga:

  1. `looks_pe`      -> uno script con estensione .exe non deve entrare;
  2. `SKIP_NAME_RE`  -> un installer/SFX non deve entrare (e' packed);
  3. dedup + estrazione -> la stessa dll in due archivi conta una volta sola;
  4. `resolve_cygwin` -> deve prendere la release CORRENTE, non le [test]/[prev].

    python scripts/test_fetch_goodware_non_ms.py
"""
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fetch_goodware_non_ms as g  # noqa: E402


def fake_pe(tag=b"A"):
    """PE minimo credibile: MZ, e_lfanew a 0x80, firma PE\\0\\0."""
    head = bytearray(b"\0" * 0x100)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x80).to_bytes(4, "little")
    head[0x80:0x84] = b"PE\0\0"
    return bytes(head) + tag * 64


def test_looks_pe():
    assert g.looks_pe(fake_pe())
    assert not g.looks_pe(b"#!/bin/sh\necho ciao\n" + b"\0" * 200)   # script
    assert not g.looks_pe(b"MZ")                                    # troncato
    mz_no_pe = bytearray(fake_pe())
    mz_no_pe[0x80:0x84] = b"XXXX"
    assert not g.looks_pe(bytes(mz_no_pe))                          # DOS stub, non PE


def test_skip_name_re_lavora_su_token():
    """Il primo tentativo scartava `opj_decompress.exe` perche' *co-mpress-or*
    contiene `mpress`, e la `install` di GNU coreutils perche' contiene
    `install`. I nomi dei packer sono token, non sottostringhe."""
    tieni = ("opj_compress.exe", "opj_decompress.exe", "compress.dll",
             "libcompressor_plugin.dll", "install.exe", "curl.exe",
             "innocuo.dll", "setupapi_helper.dll")
    scarta = ("vlc-setup.exe", "setup.exe", "npp.installer.exe", "unins000.exe",
              "uninstall.exe", "7zS.sfx", "upx.exe", "mpress.exe", "themida.dll",
              "VMProtect.exe")
    assert not [n for n in tieni if g.SKIP_NAME_RE.search(n)]
    assert not [n for n in scarta if not g.SKIP_NAME_RE.search(n)]


def test_dedup_manifest():
    """Due run sovrapposti raddoppiano le righe: la chiave primaria e' l'hash,
    quindi il manifest deve tornare a una riga per hash."""
    import csv
    with tempfile.TemporaryDirectory() as tmp:
        man = os.path.join(tmp, "manifest.csv")
        row = {k: "" for k in g.MANIFEST_FIELDS}
        a = dict(row, filename="a.exe", sha256="11" * 32, source="s", type="exe")
        b = dict(row, filename="b.dll", sha256="22" * 32, source="s", type="dll")
        g.append_manifest(man, [a, b])
        g.append_manifest(man, [a, b])                  # il run "morto" che scriveva ancora
        assert g.dedup_manifest(man) == 2
        with open(man, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
        assert [r["sha256"] for r in rows] == ["11" * 32, "22" * 32], rows
        assert g.dedup_manifest(man) == 0               # idempotente


def test_flat_name():
    assert g.flat_name("mingw64/bin/curl.exe") == "mingw64__bin__curl.exe"
    assert g.flat_name("./usr/bin/x.exe") == "usr__bin__x.exe"
    assert g.flat_name("a b/c+d.dll") == "a_b__c+d.dll"
    assert len(g.flat_name("x" * 400 + ".dll")) <= 180


def test_parse_desc():
    d = g._parse_desc("%FILENAME%\nfoo-1.0-any.pkg.tar.zst\n\n%NAME%\nfoo\n\n"
                      "%SHA256SUM%\n" + "ab" * 32 + "\n")
    assert d["NAME"] == "foo"
    assert d["FILENAME"] == "foo-1.0-any.pkg.tar.zst"
    assert d["SHA256SUM"] == "ab" * 32


def test_cygwin_prende_la_release_corrente():
    ini = ("\n@ coreutils\nversion: 9.0-1\n"
           "install: x86_64/release/coreutils/coreutils-9.0-1.tar.xz 27 " + "aa" * 64 + "\n"
           "source: x86_64/release/coreutils/coreutils-9.0-1-src.tar.xz 5 " + "bb" * 64 + "\n"
           "[test]\nversion: 9.9-1\n"
           "install: x86_64/release/coreutils/coreutils-9.9-1.tar.xz 29 " + "cc" * 64 + "\n"
           "\n@ assente-solo-in-test\n")
    orig = g.http_get
    g.http_get = lambda url, stream=False: type("R", (), {"text": ini})()
    try:
        out = g.resolve_cygwin("http://m", "x86_64", ("coreutils", "inesistente"))
    finally:
        g.http_get = orig
    assert len(out) == 1, out
    assert out[0]["url"].endswith("coreutils-9.0-1.tar.xz"), out      # non la [test]
    assert out[0]["sha512"] == "aa" * 64


def test_estrazione_filtra_e_deduplica():
    with tempfile.TemporaryDirectory() as tmp:
        arch = os.path.join(tmp, "src.zip")
        with zipfile.ZipFile(arch, "w") as z:
            z.writestr("bin/ok.exe", fake_pe(b"A"))
            z.writestr("bin/ok.dll", fake_pe(b"B"))
            z.writestr("bin/copia.dll", fake_pe(b"A"))       # duplicato di ok.exe
            z.writestr("bin/script.exe", b"#!/bin/sh\n" + b"\0" * 300)   # non PE
            z.writestr("bin/vlc-setup.exe", fake_pe(b"C"))   # installer: escluso
            z.writestr("bin/readme.txt", b"non e' un PE")
        dest = os.path.join(tmp, "out")
        os.makedirs(dest)
        rows, seen = [], set()
        kept, dup = g.extract_pe(arch, dest, seen, "t", "ff" * 32, True, rows)
        assert (kept, dup) == (2, 1), (kept, dup)
        assert sorted(os.listdir(dest)) == ["t__bin__ok.dll", "t__bin__ok.exe"]
        assert {r["type"] for r in rows} == {"exe", "dll"}
        assert all(r["size"] == len(fake_pe()) for r in rows)

        # rerun: il manifest e' la memoria del dedup -> zero file nuovi
        manifest = os.path.join(tmp, "manifest.csv")
        g.append_manifest(manifest, rows)
        kept2, dup2 = g.extract_pe(arch, dest, g.load_seen(manifest), "t",
                                   "ff" * 32, True, [])
        assert (kept2, dup2) == (0, 3), (kept2, dup2)
        assert not [f for f in os.listdir(dest) if f.endswith(".part")]


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print("OK  %s" % name)
    print("tutti i check passati")
