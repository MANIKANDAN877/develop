from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

from .config import settings

engine_kwargs = {}
if settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    engine_kwargs["poolclass"] = StaticPool

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def ensure_database_schema(bind_engine=None):
    target_engine = bind_engine or engine
    if not str(target_engine.url).startswith("sqlite"):
        return

    inspector = inspect(target_engine)
    needs_migration = {}
    if "paypal_transactions" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("paypal_transactions")}
        if "order_id" not in columns:
            needs_migration.setdefault("paypal_transactions", []).append("order_id VARCHAR")
    if "fraud_alerts" in inspector.get_table_names():
        columns = {column["name"] for column in inspector.get_columns("fraud_alerts")}
        if "risk_score" not in columns:
            needs_migration.setdefault("fraud_alerts", []).append("risk_score INTEGER DEFAULT 0")

    if not needs_migration:
        return

    with target_engine.begin() as conn:
        for table_name, column_defs in needs_migration.items():
            for column_def in column_defs:
                conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_def}"))


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
