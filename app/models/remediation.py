"""
Dieses Modul definiert Pydantic-Modelle für die KI-gestützte Behebung von
Schwachstellen (Remediation). Es umfasst Datenstrukturen für Anfragen an KI-Services
(wie Copilot Studio) und deren Antworten.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class RemediationGuide(BaseModel):
    """
    Repräsentiert einen von der KI generierten Leitfaden zur Behebung einer Schwachstelle.
    """

    model_config = ConfigDict(extra="allow")

    instructions: str = ""  # Menschlich lesbare Anweisungen der KI
    confidence_score: float = 0.0  # Vertrauenswürdigkeit der Antwort (0.0 - 1.0)
    cve_id: str | None = None  # Zugehörige CVE-ID
    content: str | None = None  # Alias für instructions (für Kompatibilität)
    conversation_id: str | None = None  # Interne ID des KI-Dialogs

    @field_validator("confidence_score")
    @classmethod
    def validate_confidence(cls, value: float) -> float:
        """
        Stellt sicher, dass der confidence_score im Bereich [0.0, 1.0] liegt.
        """
        if value < 0.0:
            return 0.0
        if value > 1.0:
            return 1.0
        return value

    @model_validator(mode="after")
    def sync_content_and_instructions(self) -> RemediationGuide:
        """
        Synchronisiert die Felder 'content' und 'instructions'.
        Stellt sicher, dass beide Felder denselben Wert enthalten, wenn eines davon gesetzt wurde.
        """
        if self.content is not None and not self.instructions:
            self.instructions = self.content
        elif self.instructions and self.content is None:
            self.content = self.instructions
        return self


class RemediationRequest(BaseModel):
    """
    Strukturierte Daten für eine Anfrage zur Erstellung eines Remediation-Leitfadens.
    """

    cve_id: str = ""
    product_name: str = ""
    product_version: str = ""
    severity: str = ""
    cvss_score: float | None = None
    affected_hosts: list[str] = Field(default_factory=list)
    description: str = ""

    def to_prompt(self) -> str:
        """
        Generiert aus den vorliegenden Daten einen natürlichsprachlichen Prompt für die KI.
        Der Prompt ist auf Deutsch formuliert.
        """
        parts = []
        if self.cve_id:
            parts.append(f"CVE: {self.cve_id}.")
        if self.product_name:
            product = self.product_name
            if self.product_version:
                product += f" {self.product_version}"
            parts.append(f"Produkt: {product}.")
        if self.severity:
            parts.append(f"Schweregrad: {self.severity}.")
        if self.cvss_score is not None:
            parts.append(f"CVSS Score: {self.cvss_score}.")
        if self.affected_hosts:
            # Begrenzung der Hosts im Prompt zur Vermeidung von Token-Überschreitungen
            hosts = ", ".join(self.affected_hosts[:5])
            parts.append(f"Betroffene Systeme: {hosts}.")
        if self.description:
            parts.append(f"Beschreibung: {self.description}.")

        # Aufforderung zur Generierung einer deutschen Anleitung hinzufügen
        parts.append(
            "Bitte liefere eine kurze, klare Anleitung (auf Deutsch) zur Behebung der "
            "Schwachstelle."
        )
        return " ".join(parts)
