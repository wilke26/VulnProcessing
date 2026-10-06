---
title: API‑Referenz – Services
---

# API‑Referenz – Services

Die Service‑Klassen implementieren die Geschäftslogik der Anwendung. Im Folgenden werden sie automatisch aus dem Quellcode dokumentiert.

::: app.services.enrichment_service
    options:
      members:
        - EnrichmentService

::: app.services.deduplication_service
    options:
      members:
        - DeduplicationService

::: app.services.prioritization_service
    options:
      members:
        - PriorityConfig
        - PrioritizationService

::: app.services.windows_patch_filter
    options:
      members:
        - DeviceCheckResult
        - WindowsPatchFilter

::: app.services.batch_ticketing_service
    options:
      members:
        - BatchTicketingService

::: app.services.ticket_preparation
    options:
      members:
        - TicketPreparationService

::: app.services.remediation_service
    options:
      members:
        - RemediationService

::: app.services.intake
    options:
      members:
        - load_any
        - load_and_store
        - validate_data
        - normalize_unified_input

::: app.services.db_intake
    options:
      members:
        - intake_findings
        - save_findings