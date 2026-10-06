"""
Unit-Tests für die KB-Extraktion im WindowsPatchFilter.
Validiert das Erkennen und Normalisieren von Microsoft Knowledge Base (KB) Nummern
aus verschiedenen Textformaten.
"""

from app.services.windows_patch_filter import WindowsPatchFilter


class TestKBExtraction:
    """
    Testklasse für die statische Methode zur Extraktion von KB-Nummern.
    """

    def test_extract_kb_with_prefix(self):
        """
        Prüft die Extraktion einer KB-Nummer mit dem Standard-Präfix 'KB'.
        """
        hint = "Installiere KB5001234"
        result = WindowsPatchFilter.extract_kb_numbers(hint)
        assert result == ["KB5001234"]

    def test_extract_multiple_kbs(self):
        """
        Stellt sicher, dass mehrere KB-Nummern in einem Text korrekt erkannt werden.
        """
        hint = "KB5001234 oder KB5001235 werden benötigt."
        result = WindowsPatchFilter.extract_kb_numbers(hint)
        assert set(result) == {"KB5001234", "KB5001235"}

    def test_extract_kb_without_prefix(self):
        """
        Verifiziert die Normalisierung von rein numerischen KB-Hinweisen (ohne 'KB'-Präfix).
        """
        hint = "5001234, 5001235"
        result = WindowsPatchFilter.extract_kb_numbers(hint)
        assert set(result) == {"KB5001234", "KB5001235"}

    def test_extract_empty_string(self):
        """
        Prüft das Verhalten bei leeren Eingabestrings (keine KB-Nummern gefunden).
        """
        result = WindowsPatchFilter.extract_kb_numbers("")
        assert result == []
