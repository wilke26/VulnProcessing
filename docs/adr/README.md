# Architecture Decision Records

## Zweck

Die ADRs dokumentieren die prägenden Architekturentscheidungen von VulnProcessing.
Ein Teil wurde nachträglich aus dem erhaltenen Repository rekonstruiert, weil frühere
GitHub-Metadaten wie Issues, Reviews und Diskussionen nicht vollständig verfügbar sind.

Zum Zeitpunkt der Rekonstruktion am 6. Oktober 2026 enthielt `origin/main` weiterhin
118 Commits ab dem 10. November 2025. Der Commit-Graph, Quellcode und Tests sind daher
wesentliche Evidenz; nicht belegbare damalige Absichten oder Alternativen werden nicht
erfunden.

## Status und Vertrauensgrad

- **Accepted (reconstructed):** Die Entscheidung ist im heutigen Code klar erkennbar,
  ihre ursprüngliche Begründung wurde jedoch nachträglich rekonstruiert.
- **Accepted:** Die Entscheidung und ihr Kontext sind durch erhaltene Reviews,
  Dokumentation oder eine aktuelle Entscheidung belegt.
- **Proposed:** Zielbild, das noch nicht vollständig umgesetzt ist.
- **Superseded:** Durch ein späteres ADR ersetzt.

Der Vertrauensgrad bewertet nur die historische Rekonstruktion:

- **High:** Einführung und Wirkung sind durch Code, Tests und Commits belegt.
- **Medium:** Die technische Entscheidung ist belegt, die ursprüngliche Motivation
  jedoch nur teilweise.
- **Low:** Wesentliche Teile beruhen auf Erinnerung oder technischer Plausibilität.

## Evidenzregeln

Evidenz wird in dieser Reihenfolge gewichtet:

1. heutiger Code und Tests;
2. Commits, Dateieinführungen und Blame;
3. erhaltene Pull Requests und Review-Kommentare;
4. bestehende Dokumentation und Konfiguration;
5. ausdrücklich gekennzeichnete Erinnerung;
6. technische Plausibilität.

Fehlt Evidenz für ursprünglich erwogene Alternativen, nennt das ADR diese Lücke, statt
eine nachträgliche Entscheidungsstory zu konstruieren.

## Index

| ADR | Entscheidung | Status | Vertrauensgrad |
|---|---|---|---|
| [0001](0001-persistent-domain-state.md) | Persistenter Domänenzustand mit SQLAlchemy auf SQLite | Accepted (reconstructed) | High |
| [0002](0002-unified-findings-contract.md) | Einheitlicher Pydantic-Vertrag für Findings | Accepted (reconstructed) | High |
| [0003](0003-external-systems-behind-adapters.md) | Externe Systeme hinter Adaptern und Composition Roots | Accepted (reconstructed) | Medium |
| [0004](0004-tenant-scoped-ticket-batches.md) | Tenantbezogene Ticket-Batches | Accepted (reconstructed) | High |
| [0005](0005-dispatch-bound-webhook-confirmation.md) | Dispatchgebundene Webhook-Bestätigung | Accepted | High |
| [0006](0006-reference-client-not-dummy-integration.md) | Referenz-Client statt Dummy-Integration | Accepted | High |
| [0007](0007-curated-portfolio-reference.md) | Kuratierte, nicht produktive Bewerbungsreferenz | Accepted | High |
| [0008](0008-secure-management-and-deployment-boundary.md) | Sichere Management- und Deployment-Grenze | Proposed | High |

## Vorgehen ab jetzt

Neue wesentliche Entscheidungen werden vor oder zusammen mit ihrer Implementierung als
`Proposed` angelegt und nach der Umsetzung auf `Accepted` gesetzt. Rekonstruierte ADRs
werden nur geändert, wenn neue Evidenz auftaucht; die Änderung wird im ADR vermerkt.
