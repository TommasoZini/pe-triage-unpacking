"""
test_phase1_signals.py
======================
Suite di test della Fase 1 (triage statico). Si lancia con:

    .venv\\Scripts\\python.exe scripts\\tests\\test_phase1_signals.py

Usa `unittest` della standard library (niente pytest da installare) e NON
richiede capa, DIE, YARA ne' campioni di malware: le fixture sono PE32
sintetici generati da make_fixtures.py, quindi la suite e' deterministica e
riproducibile su qualunque macchina.

Due categorie di test:

  1. Test che devono PASSARE: fissano il comportamento corretto attuale, cosi'
     un refactoring che lo rompe viene visto subito.

  2. Test marcati @unittest.expectedFailure: documentano un difetto NOTO e gia'
     identificato in revisione. Restano B8 (vedi la sua docstring). Falliscono "come
     previsto" e la suite resta verde; quando il difetto viene corretto il test
     diventa UNEXPECTED SUCCESS, che unittest segnala come fallimento della
     suite. A quel punto si toglie il decoratore. E' la tracciabilita' fra
     difetto trovato e difetto risolto.
"""
import os
import sys
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.dirname(TESTS_DIR)
sys.path.insert(0, SCRIPTS_DIR)
sys.path.insert(0, TESTS_DIR)

import make_fixtures                      # noqa: E402
import header_elf_lief as HL              # noqa: E402

FIXTURES = None


def setUpModule():
    """Rigenera le fixture a ogni run: cosi' il test non dipende mai da file
    residui di una versione precedente del generatore."""
    global FIXTURES
    FIXTURES = make_fixtures.generate()


def analyze(fixture_name):
    """Analizza una fixture con i soli strumenti interni (niente YARA/DIE/capa),
    per isolare la logica di scoring dalla disponibilita' dei tool esterni."""
    path = FIXTURES[fixture_name]
    return HL.analyze_with_lief(fixture_name, path, compiled_rules=None,
                                capa_ready=False, die_ready=False)


def results(**overrides):
    """Un dict di risultati 'pulito' su cui iniettare un singolo segnale."""
    res = HL._empty_results("synthetic")
    res.update(overrides)
    return res


def signals(res, packer_sections=(), is_pe=True, lief_ok=True, filepath=__file__):
    return HL._packing_signals(res, filepath, list(packer_sections), is_pe, lief_ok)


# ==========================================================================
# 1. Funzioni pure di supporto
# ==========================================================================
class TestTextNormalization(unittest.TestCase):
    """_txt(): LIEF restituisce `bytes` per i nomi non-UTF8, tipici dei packer.
    Senza normalizzazione ogni .lower() sollevava TypeError e il file veniva
    scartato in silenzio (2 file su 16 nel batch reale)."""

    def test_bytes_non_utf8_reso_come_escape(self):
        self.assertEqual(HL._txt(b"\xc0\xde\xff\x01"), "\\xc0\\xde\\xff\\x01")

    def test_bytes_ascii_restano_leggibili(self):
        self.assertEqual(HL._txt(b"UPX0"), "UPX0")

    def test_null_padding_rimosso(self):
        self.assertEqual(HL._txt(b".text\x00\x00\x00"), ".text")

    def test_none_e_stringhe(self):
        self.assertEqual(HL._txt(None), "")
        self.assertEqual(HL._txt(".data"), ".data")

    def test_non_solleva_mai(self):
        for value in (b"", bytearray(b"\xff"), "", None, "\x00\x00"):
            HL._txt(value)


class TestSectionNaming(unittest.TestCase):
    def test_nomi_standard_riconosciuti(self):
        for name in (".text", ".TEXT", ".rdata", ".eh_frame", ".debug_info",
                     ".note.gnu.build-id", ".text.unlikely", "/4", "/19"):
            self.assertTrue(HL.is_standard_section_name(name), name)

    def test_nomi_non_standard(self):
        for name in ("UPX0", ".themida", "pack0", ".vmp0"):
            self.assertFalse(HL.is_standard_section_name(name), name)

    def test_etichetta_packer_da_nome_sezione(self):
        self.assertEqual(HL.packer_label_from_section_name("UPX1"), "UPX")
        self.assertEqual(HL.packer_label_from_section_name(".themida"), "Themida")
        self.assertEqual(HL.packer_label_from_section_name(".MPRESS1"), "MPRESS")
        self.assertIsNone(HL.packer_label_from_section_name(".text"))
        self.assertIsNone(HL.packer_label_from_section_name("pack0"))


class TestEntropy(unittest.TestCase):
    def test_vuoto(self):
        self.assertEqual(HL.shannon_entropy(b""), 0.0)

    def test_costante(self):
        self.assertEqual(HL.shannon_entropy(b"A" * 1000), 0.0)

    def test_uniforme_massima(self):
        self.assertAlmostEqual(HL.shannon_entropy(bytes(range(256))), 8.0, places=6)


class TestClassification(unittest.TestCase):
    def test_un_segnale_forte_basta(self):
        self.assertEqual(HL._classify_packing(["forte"], []), (100, True))

    def test_soglia_dei_deboli(self):
        n = HL.WEAK_SIGNALS_REQUIRED
        score, packed = HL._classify_packing([], ["w"] * n)
        self.assertTrue(packed)
        self.assertGreaterEqual(score, HL.PACKING_THRESHOLD)

    def test_sotto_soglia_non_e_packed(self):
        n = HL.WEAK_SIGNALS_REQUIRED - 1
        score, packed = HL._classify_packing([], ["w"] * n)
        self.assertFalse(packed)
        self.assertLess(score, HL.PACKING_THRESHOLD)

    def test_nessun_segnale(self):
        self.assertEqual(HL._classify_packing([], []), (0, False))


# ==========================================================================
# 2. Segnali, su dict sintetici (nessun file coinvolto)
# ==========================================================================
class TestSignalsPure(unittest.TestCase):
    def test_binario_pulito_nessun_segnale(self):
        strong, weak, _ = signals(results(Total_Imports=120, EP_Section=".text"))
        self.assertEqual(strong, [])
        self.assertEqual(weak, [])

    def test_sezione_di_packer_e_forte(self):
        strong, _, _ = signals(results(Total_Imports=120, EP_Section=".text"),
                               packer_sections=["UPX0->UPX"])
        self.assertTrue(any("sezione tipica" in s for s in strong))

    def test_die_nominato_e_forte(self):
        strong, _, _ = signals(results(Total_Imports=120, EP_Section=".text",
                                       Die_Packer_Match="SI", Die_Packer_Name="ASPack",
                                       Die_Packer_Type="packer"))
        self.assertTrue(any(s.startswith("DIE:") for s in strong))

    def test_iat_minimale_con_compressione_e_forte(self):
        """IAT minimale CORROBORATA da entropia alta: segnale forte."""
        strong, _, _ = signals(results(Total_Imports=4, EP_Section=".text",
                                       Suspicious_IAT="SI", Max_Entropy_No_Rsrc=7.6))
        self.assertTrue(any("IAT minimale" in s for s in strong))

    def test_iat_minimale_senza_compressione_e_solo_debole(self):
        """IAT minimale con entropia NORMALE e sezioni regolari: NON e' un segnale forte.

        Contro-prova permanente di due falsi positivi reali: malware MSVC con .text a
        entropia 5.45 e 6.20, sezioni tutte regolari, import limitati a GetProcAddress +
        LoadLibraryA + ExitProcess. E' risoluzione dinamica degli import, cioe' evasione,
        non compressione: il codice e' in chiaro. E' la stessa lezione di Lab03-01 (B8)."""
        strong, weak, _ = signals(results(Total_Imports=3, EP_Section=".text",
                                          Suspicious_IAT="SI", Max_Entropy_No_Rsrc=6.2))
        self.assertFalse(any("IAT minimale" in s for s in strong),
                         "IAT minimale senza compressione non deve essere un segnale forte")
        self.assertTrue(any("risoluzione dinamica" in w for w in weak),
                        "l'informazione deve restare come segnale debole, non sparire")

    def test_sezioni_delphi_sono_standard(self):
        """`.itext` e `.didata` sono prodotte dal compilatore Delphi, non da un packer.

        Contro-prova di un falso positivo reale: malware Delphi con 188 import e .text a
        entropia 6.43, segnalato solo perche' quei due nomi risultavano non standard."""
        for nome in (".itext", ".didata"):
            self.assertTrue(HL.is_standard_section_name(nome),
                            f"{nome} e' una sezione standard di Delphi")

    def test_stub_strutturale(self):
        strong, _, _ = signals(results(Total_Imports=120, EP_Section="pack1",
                                       EP_Section_Entropy=7.9, EP_Section_WX="SI"))
        self.assertTrue(any("stub strutturale" in s for s in strong))

    def test_stub_strutturale_ripiego_dotnet(self):
        """Un assembly .NET ha AddressOfEntryPoint = 0, quindi nessuna sezione di EP e
        EP_Section_Entropy = 0.0: il segnale ancorato all'EP non puo' scattare.

        Caso reale a label certa (x64_msvc_3c4de3f013d4_VMProtect.exe): .text e .kA^
        eseguibili e svuotate, .7lh a entropia 7.16. Con i soli segnali deboli passava
        con un margine di un segnale sopra la soglia."""
        strong, _, _ = signals(results(Total_Imports=0, EP_Section="UNKNOWN",
                                       EP_Section_Entropy=0.0, Has_CLR_Header="SI",
                                       Exec_High_Entropy_Sections=[".7lh"],
                                       Anomalous_Size_Sections=[".text", ".kA^"]))
        self.assertTrue(any("stub strutturale" in s for s in strong),
                        "il ripiego .NET deve produrre un segnale forte")

    def test_ripiego_dotnet_non_scatta_senza_header_clr(self):
        """Il ripiego vale SOLO dove l'EP manca per costruzione. Senza header CLR un
        EP_Section UNKNOWN e' un'anomalia diversa, gia' coperta da EP_Outside_Sections."""
        strong, _, _ = signals(results(Total_Imports=0, EP_Section="UNKNOWN",
                                       Exec_High_Entropy_Sections=[".7lh"],
                                       Anomalous_Size_Sections=[".text"]))
        self.assertFalse(any("stub strutturale" in s for s in strong))

    def test_ripiego_dotnet_richiede_due_sezioni_distinte(self):
        """La sezione compressa e quella svuotata devono essere due: una sola sezione
        che e' insieme compressa e sproporzionata e' una sola evidenza, non due."""
        strong, _, _ = signals(results(Total_Imports=0, EP_Section="UNKNOWN",
                                       Has_CLR_Header="SI",
                                       Exec_High_Entropy_Sections=[".7lh"],
                                       Anomalous_Size_Sections=[".7lh"]))
        self.assertFalse(any("stub strutturale" in s for s in strong))

    def test_dotnet_pulito_non_scatta(self):
        """Un assembly .NET normale ha l'header CLR e l'EP_Section UNKNOWN come quello
        packato: senza sezioni compresse E svuotate non deve succedere niente."""
        strong, _, _ = signals(results(Total_Imports=1, EP_Section="UNKNOWN",
                                       Has_CLR_Header="SI", Is_DotNet="SI"))
        self.assertFalse(any("stub strutturale" in s for s in strong))

    def test_dotnet_non_conta_i_pochi_import(self):
        """Un assembly .NET importa solo mscoree: senza questa eccezione erano
        5 falsi positivi su 30 benigni."""
        _, weak, _ = signals(results(Total_Imports=1, EP_Section=".text", Is_DotNet="SI"))
        self.assertFalse(any("import basso" in w for w in weak))

    def test_capa_anti_analysis_e_informativo_non_debole(self):
        """capa anti-analysis discrimina poco (26% benigni vs 31% packed):
        va registrato ma non deve contare nello score."""
        _, weak, info = signals(results(Total_Imports=120, EP_Section=".text",
                                        Capa_Anti_Analysis_Match="SI"))
        self.assertEqual(weak, [])
        self.assertTrue(any("anti-analysis" in i for i in info))

    def test_capa_generico_e_debole(self):
        _, weak, _ = signals(results(Total_Imports=120, EP_Section=".text",
                                     Capa_Packer_Match="GENERICO"))
        self.assertTrue(any("packing generico" in w for w in weak))

    # ---------------- difetti noti, documentati ----------------

    def test_B6_capa_nominato_e_evidenza_named(self):
        """B6 - _record_classification cerca solo 'sezione tipica', 'YARA packer'
        e 'DIE:': un packer riconosciuto per NOME dalla sola capa finisce in
        'structural', e la Fase 2 riceve un instradamento sbagliato."""
        res = results(Total_Imports=120, EP_Section=".text",
                      Capa_Packer_Match="SI", Capa_Status="ok")
        strong, weak, info = signals(res)
        HL._record_classification(res, "x", strong, weak, info)
        self.assertEqual(res["Packing_Evidence"], "named")

    def test_B7_entry_point_fuori_da_ogni_sezione(self):
        """B7 - un EP con RVA non nullo che non cade in nessuna sezione e' un'anomalia
        e deve produrre un segnale."""
        strong, weak, _ = signals(results(Total_Imports=120, EP_Section="UNKNOWN",
                                          EP_Outside_Sections="SI"))
        self.assertTrue(any("fuori da ogni sezione" in w for w in weak),
                        "EP fuori da ogni sezione non genera segnali")

    def test_B7_dll_con_ep_nullo_non_e_anomala(self):
        """Contro-prova indispensabile: una DLL con AddressOfEntryPoint = 0 produce lo
        STESSO EP_Section 'UNKNOWN', ma e' il caso normale. Se il segnale si basasse su
        'UNKNOWN' invece che su EP_Outside_Sections, scatterebbe su ogni DLL di sistema
        - erano 1.051 file nel solo set clean."""
        strong, weak, _ = signals(results(Total_Imports=120, EP_Section="UNKNOWN",
                                          EP_Outside_Sections="NO"))
        self.assertEqual(strong, [])
        self.assertFalse(any("fuori da ogni sezione" in w for w in weak))

    @unittest.expectedFailure
    def test_B8_iat_completamente_assente_e_forte(self):
        """B8 - Suspicious_IAT pretende LoadLibrary+GetProcAddress, quindi un PE con
        import directory distrutta (0 import) vale MENO di uno con IAT minimale: il caso
        piu' estremo produce l'evidenza minore.

        RESTA expectedFailure DI PROPOSITO. Il campione PMA Lab03-01 ha un solo import
        (ExitProcess) ma NON e' pacchettizzato: il disassemblato del suo entry point mostra
        'mov eax,0x400400; call eax' verso codice in chiaro in .data, cioe' risoluzione
        dinamica degli import, non compressione (entropia .data 6.65). Promuovere "pochissimi
        import" a segnale forte creerebbe un falso positivo proprio su quel file. La
        correzione corretta e' condizionale (pochi import PIU' entropia alta o sezioni
        anomale), e richiede campioni che oggi non abbiamo."""
        strong, _, _ = signals(results(Total_Imports=0, EP_Section=".text"))
        self.assertTrue(strong, "0 import in un PE non e' un segnale forte")

    def test_B12_regola_yara_generica_non_e_packer_nominato(self):
        """B12 - KNOWN_PACKER_KEYWORDS contiene 'packer_', 'mew', 'fsg' e il
        match e' per sottostringa sul nome della regola: una regola generica
        diventa segnale FORTE."""
        strong, weak = HL.classify_yara_matches(["SUSP_Packer_Entropy_Generic"])
        self.assertEqual(strong, [])
        self.assertEqual(weak, ["SUSP_Packer_Entropy_Generic"])


# ==========================================================================
# 3. End-to-end sulle fixture (PE reali, tool esterni disattivati)
# ==========================================================================
class TestEndToEnd(unittest.TestCase):
    def test_controllo_negativo_pulito(self):
        r = analyze("clean_basic.exe")
        self.assertEqual(r["Parse_Status"], "ok")
        self.assertEqual(r["Executable_Type"], "PE (Windows)")
        self.assertEqual(r["Total_Imports"], 21)
        self.assertEqual(r["Is_Packed_Label"], 0)
        self.assertEqual(r["Strong_Signals"], "")
        self.assertEqual(r["Weak_Signals"], "")
        self.assertEqual(r["Packing_Evidence"], "none")

    def test_packer_nominato_da_nome_sezione(self):
        r = analyze("upx_like.exe")
        self.assertEqual(r["Is_Packed_Label"], 1)
        self.assertEqual(r["Packing_Evidence"], "named")
        self.assertIn("sezione tipica", r["Strong_Signals"])

    def test_stub_strutturale_senza_nome_di_packer(self):
        r = analyze("stub_structural.exe")
        self.assertEqual(r["Is_Packed_Label"], 1)
        self.assertEqual(r["Packing_Evidence"], "structural")
        self.assertIn("stub strutturale", r["Strong_Signals"])

    def test_nome_sezione_binario_non_scarta_il_file(self):
        """Regressione sul bug che faceva sparire dal CSV i binari piu' offuscati."""
        r = analyze("sec_name_bytes.exe")
        self.assertEqual(r["Parse_Status"], "ok")
        self.assertIn("\\xc0", r["Suspicious_Sections"])
        self.assertEqual(r["Is_Packed_Label"], 1)
        self.assertEqual(r["Packing_Evidence"], "weak_only")

    def test_file_non_eseguibile_escluso_dal_triage(self):
        r = analyze("not_executable.exe")
        self.assertEqual(r["Parse_Status"], "not_executable")
        self.assertEqual(r["Is_Packed_Label"], 0)
        self.assertIn("NON_EXECUTABLE", r["Executable_Type"])

    def test_overlay_grande_e_compresso_viene_misurato(self):
        """Il wrapper tipo SFX/NSIS ha sezioni normali e payload nell'overlay."""
        r = analyze("overlay_high_entropy.exe")
        self.assertGreater(r["Overlay_Size"], 65536)
        self.assertGreaterEqual(r["Overlay_Entropy"], 7.2)
        self.assertIn("overlay grande", r["Weak_Signals"])

    def test_overlay_da_solo_non_basta_a_classificare_packed(self):
        """Comportamento ATTUALE, documentato di proposito: overlay compresso +
        pochi import = 2 segnali deboli, sotto WEAK_SIGNALS_REQUIRED = 3. E'
        esattamente il motivo per cui i due campioni UPX+NSIS del ground truth
        non vengono intercettati. Se si ritara la soglia, questo test cambia."""
        r = analyze("overlay_high_entropy.exe")
        self.assertEqual(r["Is_Packed_Label"], 0)

    def test_dll_con_entry_point_nullo_non_rompe(self):
        r = analyze("dll_ep_zero.dll")
        self.assertEqual(r["Parse_Status"], "ok")
        self.assertEqual(r["EP_Section"], "UNKNOWN")
        self.assertEqual(r["EP_Outside_Sections"], "NO")   # EP nullo = normale per una DLL
        self.assertEqual(r["Is_Packed_Label"], 0)

    def test_entry_point_fuori_sezione_viene_rilevato(self):
        r = analyze("ep_outside_sections.exe")
        self.assertEqual(r["Parse_Status"], "ok")
        self.assertEqual(r["EP_Section"], "UNKNOWN")
        self.assertEqual(r["EP_Outside_Sections"], "SI")
        self.assertIn("fuori da ogni sezione", r["Weak_Signals"])

    def test_schema_csv_completo_per_ogni_fixture(self):
        """Ogni riga prodotta deve avere ESATTAMENTE le colonne dichiarate:
        una chiave mancante o di troppo corromperebbe il CSV in append."""
        for name in FIXTURES:
            with self.subTest(fixture=name):
                r = analyze(name)
                self.assertEqual(sorted(r.keys()), sorted(HL.CSV_FIELDNAMES))


if __name__ == "__main__":
    unittest.main(verbosity=2)
