"""
test_phase2_oracle.py
=====================
Controlli minimi sullo Step 0 della Fase 2. Si lancia con:

    .venv\\Scripts\\python.exe scripts\\tests\\test_phase2_oracle.py

Come la suite di Fase 1: solo `unittest` della standard library, e nessun
campione reale - si riusano le fixture PE32 sintetiche di make_fixtures.py,
quindi gira su qualunque macchina anche senza il disco dei dataset.

Copre le tre cose che, se si rompono, fanno sbagliare i numeri in silenzio:
  1. il verdetto a tre vie (una sezione a zeri non deve mai essere "ricostruito");
  2. il confronto per RVA (un file con se' stesso = 1.0, due file diversi no);
  3. il salvataggio dello stato (il difetto per cui gli esiti della Fase 2
     sparivano su ogni run piu' corta di SAVE_EVERY file).
"""
import os
import sys
import tempfile
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.dirname(TESTS_DIR)
FIXTURES = os.path.join(TESTS_DIR, "fixtures")
sys.path.insert(0, SCRIPTS_DIR)

import validate_phase2 as V  # noqa: E402
from pipeline_utils import PipelineState  # noqa: E402


def fx(name):
    return os.path.join(FIXTURES, name)


class TestVerdetto(unittest.TestCase):
    """Il verdetto a tre vie. E' la regola che sostituisce '>= 5 funzioni Ghidra'."""

    def test_sezione_a_zeri_e_sempre_fallito(self):
        # Il caso reale che ha motivato tutto: awk_C57F aveva 1011 funzioni
        # dichiarate da Ghidra e il .text interamente a zeri.
        self.assertEqual(V.verdict(match=0.99, nonzero=0.0), "fallito")
        self.assertEqual(V.verdict(match=1.0, nonzero=V.NONZERO_MIN / 2), "fallito")

    def test_codice_presente_ma_diverso_e_parziale(self):
        self.assertEqual(V.verdict(match=0.50, nonzero=0.90), "parziale")
        self.assertEqual(V.verdict(match=V.MATCH_OK - 0.01, nonzero=0.90), "parziale")

    def test_coincide_con_originale_e_ricostruito(self):
        self.assertEqual(V.verdict(match=V.MATCH_OK, nonzero=0.90), "ricostruito")
        self.assertEqual(V.verdict(match=1.0, nonzero=0.90), "ricostruito")


class TestConfronto(unittest.TestCase):
    """Il metro stesso, prima di fidarsi di cosa misura."""

    def test_file_con_se_stesso_da_identita(self):
        match, nonzero, n = V.compare(fx("clean_basic.exe"), fx("clean_basic.exe"))
        self.assertGreater(n, 0, "nessuna sezione eseguibile confrontata: fixture inadatta")
        self.assertEqual(match, 1.0)
        self.assertGreater(nonzero, V.NONZERO_MIN)
        self.assertEqual(V.verdict(match, nonzero), "ricostruito")

    def test_file_diversi_non_risultano_identici(self):
        match, _, n = V.compare(fx("clean_basic.exe"), fx("upx_like.exe"))
        self.assertGreater(n, 0)
        self.assertLess(match, V.MATCH_OK)


class TestPerimetro(unittest.TestCase):
    """Un non-PE deve essere scartato, non scambiato per un PE a 64 bit."""

    @classmethod
    def setUpClass(cls):
        try:
            import subprocesses
        except Exception as e:      # stack di emulazione non installato
            raise unittest.SkipTest(f"subprocesses non importabile: {e}")
        cls.UT = subprocesses

    def test_non_pe_ritorna_none(self):
        self.assertIsNone(self.UT.get_binary_info(fx("not_executable.exe")))

    def test_pe32_ritorna_32bit(self):
        self.assertEqual(self.UT.get_binary_info(fx("clean_basic.exe")), (True, False))


class TestStatoPersistito(unittest.TestCase):
    """Regressione del difetto che faceva sparire gli esiti della Fase 2.

    PipelineState.save() e' batched (SAVE_EVERY): senza flush() finale, una run
    piu' corta di SAVE_EVERY file non scriveva NULLA su disco, in silenzio e
    con exit code 0."""

    def test_flush_scrive_anche_una_run_corta(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            state = PipelineState(path=path)
            state.update("a" * 64, unpack_attempted=True, unpack_method="upx")

            self.assertFalse(os.path.exists(path),
                             "presupposto del test caduto: save() non e' piu' batched")
            state.flush()
            self.assertTrue(os.path.exists(path), "flush() non ha scritto lo stato")
            self.assertTrue(PipelineState(path=path).get("a" * 64)["unpack_attempted"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
