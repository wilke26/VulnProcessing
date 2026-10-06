# ADR-0003: Externe Systeme hinter Adaptern und Composition Roots kapseln

- Status: Accepted (reconstructed)
- Ursprünglicher Zeitraum: November 2025 bis Februar 2026
- Rekonstruiert: 2026-10-06
- Vertrauensgrad: Medium

## Kontext

Die Verarbeitung kann NVD-, N-Central- und Copilot-Daten verwenden und Findings an
DocBee oder MKS über E-Mail beziehungsweise REST übergeben. Fachliche Verarbeitung soll
nicht direkt an einen einzelnen Anbieter gebunden sein.

## Entscheidung

Externe Dienste werden durch Connectoren oder Ticket-Client-Protokolle gekapselt.
Composition Roots lesen Feature-Flags und Konfiguration, erstellen die aktivierten
Clients und injizieren sie in Ticketvorbereitung und Dispatcher.

## Konsequenzen

- Integrationen können einzeln aktiviert, getestet oder ersetzt werden.
- Konfiguration, Credentials, TLS, Timeouts und Retry-Verhalten gehören zur jeweiligen
  Adaptergrenze.
- Der Dispatcher muss Ergebnisse pro Finding und Client sichtbar machen; das heutige
  Verschlucken einzelner Fehler ist Architekturarbeit, keine gewünschte Semantik.
- Mehrere aktivierte Clients bedeuten mehrere externe Nebenwirkungen pro Finding.

## Historische Evidenz

- Commit `6ec7753` vom 15. November 2025 führte Dispatcher und Copilot-Komponenten ein.
- Commit `b5a6db6` vom 17. November 2025 führte N-Central und Ticketvorbereitung ein.
- Commit `4742709` vom 28. November 2025 führte NVD-Anreicherung ein.
- Commit `3fe0da7` vom 2. Dezember 2025 führte E-Mail- und Ticket-Connectoren ein.
- Commit `6a08076` vom 6. Februar 2026 führte die heutige Composition Root ein.
- Die ursprüngliche Diskussion über alternative Integrationsarchitekturen ist nicht
  erhalten; deshalb ist der Vertrauensgrad für die Motivation nur `Medium`.
