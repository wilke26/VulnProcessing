# ADR-0007: VulnProcessing als kuratierte Bewerbungsreferenz veröffentlichen

- Status: Accepted
- Datum: 2026-10-06
- Vertrauensgrad: High

## Kontext

Das Projekt wird nicht mehr als Produktivsystem weiterentwickelt. Die erhaltene private
Historie enthält wertvolle Entwicklungsevidenz, aber auch nicht zur Veröffentlichung
bestimmte Betriebs- und personenbezogene Metadaten. Ein öffentliches Umschalten des
bestehenden Repositories würde diese Historie offenlegen. Gleichzeitig soll die Referenz
ehrlich zeigen, welche Teile implementiert, geplant oder unvollständig sind.

## Entscheidung

Die öffentliche Bewerbungsreferenz wird als kuratierter, sicherheitsgeprüfter Snapshot
bereitgestellt. Das private Ursprungsrepository bleibt Evidenzarchiv. Der öffentliche
Snapshot enthält keine produktiven Daten, Secrets oder ungeprüfte Historie und behauptet
weder aktuellen Produktivbetrieb noch eine vollständige Cloud-Bereitstellung.

Die Veröffentlichung dient ausschließlich der Einsicht und Bewertung als
Bewerbungsreferenz. Sie erfolgt bewusst ohne Open-Source-Lizenz; sämtliche Rechte am
Code und an der Dokumentation bleiben vorbehalten. Die durch die GitHub-Nutzungsbedingungen
für GitHub-Funktionen gewährten Rechte bleiben davon unberührt.

Die Architekturhistorie wird aus erhaltenem Code, Tests, Commits und Reviews
rekonstruiert. Rekonstruierte Entscheidungen werden ausdrücklich gekennzeichnet; Lücken
werden nicht durch erfundene Begründungen geschlossen.

## Konsequenzen

- Historische PRs und Commits müssen nicht Teil des öffentlichen Showcase-Repositories
  sein.
- README und Architektur nennen Projektstatus und Grenzen deutlich.
- Beispieldaten müssen eindeutig synthetisch sein.
- Ein öffentlicher Snapshot benötigt eigene CI, einen ausdrücklichen Rechtehinweis und
  eine Releaseprüfung.
- Neue Arbeiten können weiterhin über nachvollziehbare PRs und ADRs erfolgen.

## Evidenz

- Entscheidung des Repository-Eigentümers vom 6. Oktober 2026.
- Entscheidung des Repository-Eigentümers vom 7. Oktober 2026, keine
  Open-Source-Nutzungsrechte einzuräumen.
- Sicherheitsprüfung des privaten Repositories vor der geplanten Veröffentlichung.
- Der erhaltene `origin/main`-Commit-Graph dient als private Rekonstruktionsquelle.
