# Future Work

Die aktuelle Lösung bildet den stabilen Grundprozess zur Validierung und Weiterverarbeitung der Findings ab. Perspektivisch kann die Architektur erweitert werden um:

* asynchrone Verarbeitung durch einen separaten Worker (Celery / Queue Trigger)
* Erweiterung der vorhandenen CVSS- und Produktregeln um dynamischen Asset- und
  Kundenkontext
* Container-basierte Bereitstellung in Azure Container Apps für Lastspitzen
* Microsoft Sentinel / SIEM Integration als Datenverbraucher

Diese Punkte wurden nicht implementiert, sind jedoch durch die klare Data-Contract-Struktur modular anschließbar.
