from sqlalchemy import inspect, text

from shared.db import engine
from shared.models import Base


SCHEMA_COLUMNS = {
    "projects": {
        "origin_ip": "VARCHAR(255)",
        "origin_scan_confirmed": "INTEGER DEFAULT 0",
    },
    "scans": {
        "warnings": "JSON",
        "tool_status": "JSON",
        "normalized_outputs": "JSON",
        "scan_metadata": "JSON",
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
