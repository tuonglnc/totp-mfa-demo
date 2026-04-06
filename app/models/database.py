"""
app/models/database.py — SQLite Database Connection & Initialization
"""

import sqlite3
import os
from pathlib import Path
from flask import g, current_app


def get_db() -> sqlite3.Connection:
    """
    Get the database connection for the current Flask request context.
    The connection is stored in Flask's 'g' object and reused within a request.
    """
    if "db" not in g:
        db_path = current_app.config["DATABASE_PATH"]
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        g.db = sqlite3.connect(
            db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        g.db.row_factory = sqlite3.Row     # rows behave like dicts
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
    return g.db


def close_db(e=None) -> None:
    """Close the database connection at end of request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app) -> None:
    """Initialize the database schema from schema.sql."""
    with app.app_context():
        db_path = app.config["DATABASE_PATH"]
        os.makedirs(os.path.dirname(db_path), exist_ok=True)

        schema_path = app.config["SCHEMA_PATH"]
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        with open(schema_path, "r") as f:
            conn.executescript(f.read())
        conn.commit()
        conn.close()


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    """Execute a SELECT and return the first row, or None."""
    return get_db().execute(sql, params).fetchone()


def query_all(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    """Execute a SELECT and return all rows."""
    return get_db().execute(sql, params).fetchall()


def execute(sql: str, params: tuple = ()) -> sqlite3.Cursor:
    """Execute an INSERT/UPDATE/DELETE and commit."""
    db = get_db()
    cursor = db.execute(sql, params)
    db.commit()
    return cursor
