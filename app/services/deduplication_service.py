"""
Dieses Modul bietet Logik zur Deduplizierung von Findings vor der Speicherung.
Es stellt sicher, dass redundante Informationen zusammengefasst werden, um die
Datenbank sauber zu halten und die Ticket-Anzahl zu optimieren.
"""

from __future__ import annotations

from collections import defaultdict

from app.models.findings import Finding as PydanticFinding


class DeduplicationService:
    """
    Service zur Zusammenführung von redundanten Findings.

    Die Deduplizierung erfolgt in zwei Stufen:
    1. Gruppierung nach Mandant (Tenant) und Schwachstellen-Identifikator (CVE oder Name).
    2. Zusammenführung innerhalb dieser Gruppen basierend auf dem Zielsystem (Target).

    Dabei werden Risikowerte maximiert und Mengen (Amounts) addiert.
    """

    @staticmethod
    def deduplicate(findings: list[PydanticFinding]) -> list[PydanticFinding]:
        """
        Führt eine Deduplizierung auf einer Liste von Findings durch.

        Args:
            findings (list[PydanticFinding]): Die ursprüngliche Liste der Findings.

        Returns:
            list[PydanticFinding]: Die bereinigte und zusammengefasste Liste der Findings.
        """
        if not findings:
            return []

        # Stufe 1: Gruppierung nach Tenant und CVE (bzw. Name als Fallback)
        by_cve: dict[tuple[str, str], list[PydanticFinding]] = defaultdict(list)
        for f in findings:
            # Wenn keine CVE vorhanden ist, nutzen wir den Namen zur Gruppierung
            key = (f.tenant, f.cve_id or f.name)
            by_cve[key].append(f)

        result: list[PydanticFinding] = []

        for (_tenant, _cve_key), cluster in by_cve.items():
            # Stufe 2: Zusammenführung innerhalb der Gruppen (nach Target)
            merged = DeduplicationService._merge_unique_keys(cluster)
            result.extend(merged)

        return result

    @staticmethod
    def _merge_unique_keys(cluster: list[PydanticFinding]) -> list[PydanticFinding]:
        """
        Interne Hilfsmethode zur Zusammenführung von Findings innerhalb eines Clusters.

        Findings mit gleichem Target und Namen werden zu einem Eintrag zusammengefasst.
        - Risk: Der höchste gefundene Wert wird übernommen.
        - Amount: Die Summe aller Einzelmengen.
        - Produkte: Eine Liste aller einzigartigen betroffenen Produkte.

        Args:
            cluster (list[PydanticFinding]): Eine Liste von Findings derselben Schwachstelle.

        Returns:
            list[PydanticFinding]: Die zusammengeführten Findings für dieses Cluster.
        """
        merged: dict[tuple[str, str], PydanticFinding] = {}

        for f in cluster:
            key = (f.target, f.name)

            if key not in merged:
                # Erster Fund für dieses Target/Name-Paar: Kopie erstellen,
                # damit Originale unverändert bleiben
                merged[key] = f.model_copy()
            else:
                existing = merged[key]
                # Geschäftsregeln für Merging:
                # 1. Höchstes Risiko gewinnt (Worst-Case-Betrachtung)
                existing.risk = max(existing.risk, f.risk)
                # 2. Anzahl der Vorkommen addieren
                existing.amount += f.amount
                # 3. Produktliste ergänzen und Duplikate entfernen
                existing.products = list(set(existing.products + f.products))

        return list(merged.values())
