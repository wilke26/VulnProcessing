"""
Haupteinstiegspunkt für die VulnProcessing-Anwendung.
Dieses Modul initialisiert die FastAPI-App, konfiguriert die Lebenszyklus-Events (Lifespan)
und registriert alle API-Router für die verschiedenen Funktionsbereiche.
"""

import logging
import os
from contextlib import asynccontextmanager

from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI

from app.api.routes_health import router as health_router
from app.api.routes_import import router as import_router
from app.api.routes_tickets import router as tickets_router
from app.api.routes_version import router as version_router
from app.core.config import settings
from app.core.resource_limits import RequestBodyLimitMiddleware
from app.db import init_db
from app.services.intake import load_and_store

# Logging konfigurieren
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def run_scheduled_import():
    """
    Führt den Import der Lywand-JSON-Datei durch.
    Der Pfad wird aus den globalen Settings bezogen und Tilde-Zeichen aufgelöst.
    """
    path = settings.LYWAND_JSON_PATH
    if not path:
        logger.warning("LYWAND_JSON_PATH ist nicht konfiguriert. Überspringe Import.")
        return

    # Tilde (~) und Umgebungsvariablen auflösen
    expanded_path = os.path.abspath(os.path.expanduser(path))

    if not os.path.exists(expanded_path):
        logger.error(f"Import fehlgeschlagen: Datei nicht gefunden unter {expanded_path}")
        return

    try:
        logger.info(f"Starte automatischen Import von: {expanded_path}")
        count = load_and_store(expanded_path)
        logger.info(f"Automatischer Import erfolgreich: {count} Findings verarbeitet.")
    except Exception as e:
        logger.exception(f"Fehler beim automatischen Import von {expanded_path}: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Verwaltet den Lebenszyklus der FastAPI-Anwendung.
    Führt beim Start Initialisierungsaufgaben wie das Anlegen der Datenbanktabellen durch
    und startet den Hintergrund-Scheduler für regelmäßige Imports.
    """
    # Startup: Sicherstellen, dass die Datenbank und Tabellen existieren
    init_db()

    # Scheduler einrichten
    scheduler = BackgroundScheduler()

    # 1. Sofortiger Import beim Start
    run_scheduled_import()

    # 2. Monatlicher Import einplanen (jeden 1. des Monats um 03:00 Uhr)
    scheduler.add_job(run_scheduled_import, "cron", day=1, hour=3, minute=0)

    scheduler.start()

    yield

    # Shutdown
    scheduler.shutdown()


def create_app() -> FastAPI:
    """
    Erstellt und konfiguriert die FastAPI-Instanz.

    Returns:
        FastAPI: Die konfigurierte Anwendung mit allen registrierten Routern.
    """
    documentation_url = "/docs" if settings.DEBUG else None
    app = FastAPI(
        title="VulnProcessing",
        lifespan=lifespan,
        docs_url=documentation_url,
        redoc_url="/redoc" if settings.DEBUG else None,
        openapi_url="/openapi.json" if settings.DEBUG else None,
    )
    app.add_middleware(RequestBodyLimitMiddleware)

    # Router für die verschiedenen API-Module registrieren
    app.include_router(health_router)
    app.include_router(version_router)
    app.include_router(import_router)
    app.include_router(tickets_router)

    return app


# Globale ASGI-Anwendung für den Betrieb mit Uvicorn oder Gunicorn
app = create_app()
