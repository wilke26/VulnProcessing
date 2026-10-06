"""
Dieses Modul definiert die globalen Einstellungen der Anwendung unter Verwendung von
Pydantic Settings. Es lädt Konfigurationswerte aus Umgebungsvariablen oder einer
.env-Datei und validiert deren Konsistenz.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ManagementCredential(BaseModel):
    """Opaque management credential with server-side authorization scopes."""

    subject: str = Field(min_length=1)
    token: SecretStr
    tenants: list[str] = Field(min_length=1)
    operations: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def validate_scopes(self) -> ManagementCredential:
        token = self.token.get_secret_value()
        if len(token) < 32:
            raise ValueError("Management tokens must contain at least 32 characters")
        if any(not value.strip() for value in self.tenants):
            raise ValueError("Management tenant scopes must not be empty")
        if any(not value.strip() for value in self.operations):
            raise ValueError("Management operation scopes must not be empty")
        return self


class Settings(BaseSettings):
    """
    Hält alle Konfigurationseinstellungen für die Anwendung.
    Die Werte werden automatisch aus Umgebungsvariablen (case-sensitive)
    oder einer .env-Datei geladen.
    """

    # Pydantic v2 Konfiguration (ersetzt class Config)
    model_config = SettingsConfigDict(
        env_file=".env",  # .env-Datei im Projektroot suchen
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # --- Datenbank ---
    # URL zur Datenbankverbindung
    DATABASE_URL: str = "sqlite:///./data/vulnprocessing.sqlite3"

    # --- Allgemeine Einstellungen ---
    APP_NAME: str = "VulnProcessing"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # --- Management API ---
    # Opaque bearer credentials with server-side tenant and operation scopes.
    # Empty configuration intentionally disables all management routes.
    MANAGEMENT_CREDENTIALS: list[ManagementCredential] = Field(default_factory=list)

    # --- Copilot / AI Integration ---
    # Gibt an, ob die Copilot-Integration aktiviert ist
    COPILOT_ENABLED: bool = False
    # Basis-URL für das Copilot Studio
    COPILOT_STUDIO_URL: str | None = None
    # API-Secret für die Authentifizierung am Copilot Studio
    COPILOT_STUDIO_SECRET: str | None = None
    # Time-to-Live für den Copilot-Cache in Sekunden
    COPILOT_CACHE_TTL: int = 3600
    # Maximale Anzahl gleichzeitiger Anfragen an Copilot
    COPILOT_CONCURRENT_REQUESTS: int = Field(default=5, gt=0, le=50)
    COPILOT_TIMEOUT_SECONDS: int = Field(default=30, gt=0, le=300)

    # --- DocBee Integration ---
    # Basis-URL der DocBee-Instanz
    DOCBEE_URL: str | None = None
    # API-Schlüssel für den Zugriff auf DocBee
    DOCBEE_API_KEY: str | None = None
    # Aktiviert REST-Ticketing fuer DocBee
    DOCBEE_REST_ENABLED: bool = False
    # Aktiviert E-Mail-Ticketing fuer DocBee
    DOCBEE_EMAIL_ENABLED: bool = False

    # --- MKS Integration ---
    # Basis-URL der MKS-Instanz
    MKS_URL: str | None = None
    # Benutzername für die MKS-Authentifizierung
    MKS_USERNAME: str | None = None
    # Passwort für die MKS-Authentifizierung
    MKS_PASSWORD: str | None = None
    # Aktiviert REST-Ticketing fuer MKS
    MKS_REST_ENABLED: bool = False
    # Aktiviert E-Mail-Ticketing fuer MKS
    MKS_EMAIL_ENABLED: bool = False

    # --- N-Central API Integration ---
    # Basis-URL der N-Central API
    NCENTRAL_API_URL: str = ""
    # API-Schlüssel für N-Central
    NCENTRAL_API_KEY: str = ""
    # Timeout für API-Anfragen an N-Central in Sekunden
    NCENTRAL_TIMEOUT: int = Field(default=30, gt=0, le=300)

    # --- Nist NVD ---
    # API-Schlüssel für die NVD-API
    NVD_API_KEY: str | None = None
    NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    NVD_RATE_LIMIT: int = 5
    NVD_RATE_LIMIT_WITH_KEY: int = 50
    NVD_TIMEOUT: int = Field(default=30, gt=0, le=300)
    NVD_CACHE_TTL: int = 86400

    # --- SMTP / E-Mail Konfiguration ---
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_USE_TLS: bool = True
    SMTP_TIMEOUT_SECONDS: int = Field(default=30, gt=0, le=300)
    SMTP_FROM_ADDRESS: str = "vulnprocessing@localhost"

    # --- Ticket-Systeme (E-Mail) ---
    DOCBEE_TICKET_EMAIL: str = "tickets@docbee.localhost"
    MKS_TICKET_EMAIL: str = "tickets@mks.localhost"

    # --- Batch-Verarbeitung ---
    BATCH_SIZE: int = 10
    MAX_RETRIES: int = 3
    BATCH_CONFIRM_WEBHOOK_SECRET: str = ""
    BATCH_CONFIRM_WEBHOOK_MAX_AGE_SECONDS: int = Field(default=300, gt=0)
    BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS: int = Field(default=30, ge=0)

    # --- Import-Limits ---
    MAX_REQUEST_BYTES: int = Field(default=11 * 1024 * 1024, gt=0)
    MAX_IMPORT_BYTES: int = Field(default=10 * 1024 * 1024, gt=0)
    MAX_FINDINGS_PER_IMPORT: int = Field(default=10_000, gt=0)
    MAX_FINDINGS_PER_TICKET_OPERATION: int = Field(default=500, gt=0, le=10_000)
    MAX_BATCH_CANDIDATES_PER_OPERATION: int = Field(default=50, gt=0, le=500)
    MAX_CONCURRENT_MANAGEMENT_OPERATIONS: int = Field(default=4, gt=0, le=100)

    # --- Pfade ---
    DATA_DIR: str = "./data"
    TEMPLATES_DIR: str = "./app/templates"

    # --- Celery ---
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # --- Monitoring ---
    ENABLE_METRICS: bool = False
    METRICS_PORT: int = 9090

    # --- Feature-Flags ---
    # Aktiviert oder deaktiviert die Filterung von Windows-Patches über N-Central
    ENABLE_WINDOWS_PATCH_FILTER: bool = False

    # --- JSON Import ---
    # Pfad zur JSON-Datei mit Schwachstellendaten (unterstützt ~ für Home-Verzeichnis)
    LYWAND_JSON_PATH: str | None = None

    # --- Retry-Konfiguration ---
    RETRY_ATTEMPTS: int = 3
    RETRY_MIN_SECONDS: int = 1
    RETRY_MAX_SECONDS: int = 8

    @model_validator(mode="after")
    def validate_config(self) -> Settings:
        """
        Führt globale Konsistenzprüfungen für die geladene Konfiguration durch.
        Wird automatisch nach der Initialisierung des Modells aufgerufen.

        Returns:
            Settings: Die validierte Instanz.

        Raises:
            ValueError: Wenn Pflichtfelder für aktivierte Features fehlen.
        """

        # 1. Copilot-Validierung: Wenn aktiviert, müssen URL und Secret vorhanden sein
        if self.COPILOT_ENABLED:
            missing: list[str] = []

            if not self.COPILOT_STUDIO_URL:
                missing.append("COPILOT_STUDIO_URL")
            if not self.COPILOT_STUDIO_SECRET:
                missing.append("COPILOT_STUDIO_SECRET")

            if missing:
                raise ValueError(
                    "Copilot ist aktiviert, aber folgende Einstellungen fehlen: "
                    + ", ".join(missing)
                )

        # 2. DocBee-Validierung: Wenn eine URL gesetzt ist, ist auch ein API-Key erforderlich
        if self.DOCBEE_URL and not self.DOCBEE_API_KEY:
            raise ValueError(
                "DOCBEE_URL ist gesetzt, aber DOCBEE_API_KEY fehlt. Bitte beide setzen "
                "oder DOCBEE_URL entfernen."
            )
        if self.DOCBEE_REST_ENABLED and (not self.DOCBEE_URL or not self.DOCBEE_API_KEY):
            raise ValueError(
                "DOCBEE_REST_ENABLED ist gesetzt, aber DOCBEE_URL und/oder DOCBEE_API_KEY fehlen. "
                "Bitte DOCBEE_URL und DOCBEE_API_KEY setzen oder DOCBEE_REST_ENABLED deaktivieren."
            )

        # 3. MKS-Validierung: Wenn eine URL gesetzt ist, sind Benutzername und Passwort erforderlich
        if self.MKS_URL and (not self.MKS_USERNAME or not self.MKS_PASSWORD):
            raise ValueError(
                "MKS_URL ist gesetzt, aber MKS_USERNAME und/oder MKS_PASSWORD fehlen. "
                "Bitte alle drei Werte setzen oder MKS_URL entfernen."
            )
        if self.MKS_REST_ENABLED and (
            not self.MKS_URL or not self.MKS_USERNAME or not self.MKS_PASSWORD
        ):
            raise ValueError(
                "MKS_REST_ENABLED ist gesetzt, aber MKS_URL, MKS_USERNAME und/oder "
                "MKS_PASSWORD fehlen. "
                "Bitte alle drei Werte setzen oder MKS_REST_ENABLED deaktivieren."
            )

        # 4. N-Central-Validierung: Die Integration ist optional, aber ihre
        # Konfiguration muss vollständig sein, sobald sie verwendet werden soll.
        ncentral_url_configured = bool(self.NCENTRAL_API_URL)
        ncentral_key_configured = bool(self.NCENTRAL_API_KEY)

        if ncentral_url_configured != ncentral_key_configured:
            raise ValueError(
                "NCENTRAL_API_URL und NCENTRAL_API_KEY müssen gemeinsam gesetzt "
                "oder gemeinsam weggelassen werden."
            )

        if self.ENABLE_WINDOWS_PATCH_FILTER and not ncentral_url_configured:
            raise ValueError(
                "ENABLE_WINDOWS_PATCH_FILTER ist aktiviert, aber NCENTRAL_API_URL "
                "und NCENTRAL_API_KEY fehlen."
            )

        if (
            self.BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS
            >= self.BATCH_CONFIRM_WEBHOOK_MAX_AGE_SECONDS
        ):
            raise ValueError(
                "BATCH_CONFIRM_WEBHOOK_CLOCK_SKEW_SECONDS muss kleiner als "
                "BATCH_CONFIRM_WEBHOOK_MAX_AGE_SECONDS sein."
            )

        if self.MAX_REQUEST_BYTES < self.MAX_IMPORT_BYTES + 64 * 1024:
            raise ValueError(
                "MAX_REQUEST_BYTES muss mindestens 64 KiB größer als MAX_IMPORT_BYTES "
                "sein, damit Multipart-Metadaten zusätzlich zur Importdatei Platz haben."
            )

        subjects: set[str] = set()
        tokens: set[str] = set()
        for credential in self.MANAGEMENT_CREDENTIALS:
            token = credential.token.get_secret_value()
            if credential.subject in subjects:
                raise ValueError("Management credential subjects must be unique")
            if token in tokens:
                raise ValueError("Management credential tokens must be unique")
            subjects.add(credential.subject)
            tokens.add(token)

        return self

    @property
    def smtp_configured(self) -> bool:
        """Prüft, ob SMTP konfiguriert ist."""
        return bool(self.SMTP_HOST and self.SMTP_USER and self.SMTP_PASSWORD)

    @property
    def nvd_rate_limit_effective(self) -> int:
        """Gibt das effektive NVD Rate Limit zurück."""
        return self.NVD_RATE_LIMIT_WITH_KEY if self.NVD_API_KEY else self.NVD_RATE_LIMIT


# Globale Instanz der Einstellungen, die projektweit importiert werden kann
settings = Settings()
