---
title: API‑Referenz – Modelle
---

# API‑Referenz – Modelle

Dieser Abschnitt dokumentiert die Datenmodelle des Projekts automatisch. Die folgenden Direktiven werden vom **mkdocstrings**‑Plugin ausgewertet und zeigen Klassen, Attribute und Docstrings direkt aus dem Quellcode.

## ORM‑Modelle (`app.db.models`)

::: app.db.models
    options:
      members:
        - Tenant
        - Asset
        - Product
        - CVE
        - ImportRun
        - TicketBatch
        - Finding
        - FindingProduct
        - FindingCVE
        - Ticket
        - AuditLog
      show_root_full_path: false
      docstring_style: google

## Pydantic‑Modelle (`app.models`)

::: app.models.findings
    options:
      members:
        - Finding
        - FindingsEnvelope
        - UnifiedFindingsInput

::: app.models.enrichment
    options:
      members:
        - CVSSVector
        - NVDEnrichment
        - EnrichedFinding

::: app.models.remediation
    options:
      members:
        - RemediationGuide
        - RemediationRequest