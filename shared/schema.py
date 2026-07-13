from sqlalchemy import inspect, text

from shared.db import engine
from shared.models import Base


SCHEMA_COLUMNS = {
    "projects": {
        "authorization_confirmed": "INTEGER DEFAULT 0",
        "default_scan_mode": "VARCHAR(50) DEFAULT 'safe_validation'",
        "credentials_encrypted": "JSON",
        "origin_ip": "VARCHAR(255)",
        "origin_scan_confirmed": "INTEGER DEFAULT 0",
    },
    "scans": {
        "scan_mode": "VARCHAR(50) DEFAULT 'safe_validation'",
        "phase": "VARCHAR(50) DEFAULT 'queued'",
        "model": "VARCHAR(100)",
        "methodology_commit": "VARCHAR(100)",
        "selected_skills": "JSON",
        "checklist": "JSON",
        "token_usage": "JSON",
        "estimated_cost": "VARCHAR(50)",
        "approval_requests": "JSON",
        "warnings": "JSON",
        "tool_status": "JSON",
        "normalized_outputs": "JSON",
        "scan_metadata": "JSON",
    },
    "scan_steps": {
        "stderr_summary": "TEXT",
        "stdout_summary": "TEXT",
        "actual_input_count": "INTEGER DEFAULT 0",
        "failure_category": "VARCHAR(50)",
    },
}


def ensure_schema() -> None:
    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table_name, columns in SCHEMA_COLUMNS.items():
            if not inspector.has_table(table_name):
                continue
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, column_type in columns.items():
                if column_name not in existing:
                    connection.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
