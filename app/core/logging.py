"""
Zentrale Logging-Konfiguration für VulnProcessing.

Dieses Modul bietet Hilfsfunktionen zur Konfiguration des globalen Loggings
und zum Abrufen von Loggern im gesamten Projekt. Es implementiert zudem einen
kontextbasierten Mechanismus, um eine Request- oder Korrelations-ID an alle
Log-Einträge anzuhängen, was die Rückverfolgbarkeit von Anfragen erleichtert.

Beispiel für die Verwendung:

    from app.core.logging import setup_logging, get_logger, set_request_id

    setup_logging()  # Handler und Formatter einmalig beim Start konfigurieren
    set_request_id("abcd-1234")  # Optional: Request-ID in einer Middleware setzen
    logger = get_logger(__name__)
    logger.info("Hallo Welt!")

Die Log-Ausgabe enthält Zeitstempel, Log-Level, Modulnamen und die Request-ID (falls gesetzt).
"""

from __future__ import annotations

import contextvars
import logging
import os
import sys

try:
    import structlog
except Exception:  # pragma: no cover - optional dependency
    structlog = None

__all__ = ["setup_logging", "get_logger", "set_request_id", "get_request_id"]

# Kontextvariable zum Speichern einer ID pro Anfrage.
# Eine ASGI-Middleware kann diese Variable zu Beginn jeder Anfrage setzen.
_request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)


class RequestIdFilter(logging.Filter):
    """
    Ein Logging-Filter, der die aktuelle Request-ID in jeden Log-Eintrag injiziert.
    Wenn keine Request-ID gesetzt ist, wird das Attribut `request_id` auf `None` gesetzt.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_var.get()
        return True


def setup_logging(level: str = "INFO", fmt: str | None = None) -> None:
    """
    Konfiguriert den Root-Logger mit einem Stream-Handler und einem Formatter.

    Ein wiederholter Aufruf dieser Funktion hat keine Auswirkungen, wenn bereits
    Handler konfiguriert wurden. Das Standardformat umfasst Zeitstempel, Level,
    Modulname, Request-ID und die Nachricht.

    Args:
        level (str, optional): Das zu setzende Log-Level (Standard: "INFO").
        fmt (str, optional): Ein benutzerdefiniertes Format für Log-Nachrichten.
                             Falls nicht angegeben, wird ein Standardformat verwendet.
    """

    root = logging.getLogger()
    if root.handlers:
        # Vermeidung doppelter Konfiguration bei wiederholten Aufrufen
        return

    # Log-Level ermitteln
    numeric_level = logging.getLevelName(level.upper())
    if not isinstance(numeric_level, int):
        numeric_level = logging.INFO
    root.setLevel(numeric_level)

    # Stream-Handler erstellen, der nach stdout schreibt
    handler = logging.StreamHandler(stream=sys.stdout)

    # Standard-Formatstring erstellen, falls keiner angegeben wurde
    if fmt is None:
        fmt = "%(asctime)s | %(levelname)s | %(name)s | request_id=%(request_id)s | %(message)s"

    formatter = logging.Formatter(fmt=fmt, datefmt="%Y-%m-%dT%H:%M:%S")
    handler.setFormatter(formatter)

    # Filter hinzufügen, um die Request-ID in die Log-Einträge einzufügen
    handler.addFilter(RequestIdFilter())
    root.addHandler(handler)

    if structlog is not None:
        use_json = os.getenv("STRUCTLOG_JSON", "0").lower() in {"1", "true", "yes"}
        renderer = (
            structlog.processors.JSONRenderer(sort_keys=True)
            if use_json
            else structlog.dev.ConsoleRenderer()
        )

        structlog.configure(
            processors=[
                structlog.contextvars.merge_contextvars,
                _add_request_id_to_event,
                _add_logger_name,
                _add_process_thread,
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.format_exc_info,
                renderer,
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )


def get_logger(name: str):
    """
    Gibt einen Logger mit dem angegebenen Namen zurück.

    Diese Hilfsfunktion stellt sicher, dass Logger die Konfiguration des Root-Loggers
    erben und keine zusätzlichen eigenen Handler hinzufügen.

    Args:
        name (str): Name des Loggers (üblicherweise `__name__`).

    Returns:
        logging.Logger: Eine konfigurierte Logger-Instanz.
    """
    if structlog is not None:
        return structlog.get_logger(name)
    return logging.getLogger(name)


def set_request_id(request_id: str | None) -> None:
    """
    Setzt die Request- oder Korrelations-ID für den aktuellen Kontext.

    Die Übergabe von `None` löscht die Request-ID für den aktuellen Kontext.
    Diese Funktion kann von einer Middleware vor der Verarbeitung einer Anfrage
    aufgerufen werden.

    Args:
        request_id (str, optional): Die ID, die an die Log-Einträge angehängt werden soll.
    """
    _request_id_var.set(request_id)
    if structlog is not None:
        if request_id is None:
            structlog.contextvars.unbind_contextvars("request_id")
        else:
            structlog.contextvars.bind_contextvars(request_id=request_id)


def get_request_id() -> str | None:
    """
    Ruft die aktuelle Request-ID ab, falls eine gesetzt ist.

    Returns:
        str | None: Die aktuelle Request-ID oder None.
    """
    return _request_id_var.get()


def _add_request_id_to_event(_logger, _method_name: str, event_dict: dict) -> dict:
    event_dict.setdefault("request_id", _request_id_var.get())
    return event_dict


def _add_logger_name(_logger, _method_name: str, event_dict: dict) -> dict:
    event_dict.setdefault("logger", getattr(_logger, "name", None))
    return event_dict


def _add_process_thread(_logger, _method_name: str, event_dict: dict) -> dict:
    import os
    import threading

    event_dict.setdefault("pid", os.getpid())
    event_dict.setdefault("thread", threading.current_thread().name)
    return event_dict
