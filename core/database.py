import sqlite3
from datetime import datetime
from pathlib import Path


DATA_DIR = Path("data")
DATABASE_PATH = DATA_DIR / "argus.db"


def get_connection():
    """
    Create and return a connection to the ARGUS database.
    """
    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


def initialize_database():
    """
    Create the ARGUS database tables if they
    do not already exist.
    """
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            mac TEXT,
            hostname TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS observations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL,
            status TEXT NOT NULL,
            observed_at TEXT NOT NULL,

            FOREIGN KEY (asset_id)
                REFERENCES assets(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            observation_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            name TEXT,
            product TEXT,
            version TEXT,

            FOREIGN KEY (observation_id)
                REFERENCES observations(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS baselines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            asset_id INTEGER NOT NULL UNIQUE,
            observation_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,

            FOREIGN KEY (asset_id)
                REFERENCES assets(id),

            FOREIGN KEY (observation_id)
                REFERENCES observations(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            asset_id INTEGER NOT NULL,
            observation_id INTEGER NOT NULL,
            baseline_observation_id INTEGER,

            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            investigation_status TEXT NOT NULL DEFAULT 'new',

            port INTEGER,
            protocol TEXT,
            service_name TEXT,
            product TEXT,
            version TEXT,

            message TEXT NOT NULL,
            created_at TEXT NOT NULL,

            FOREIGN KEY (asset_id)
                REFERENCES assets(id),

            FOREIGN KEY (observation_id)
                REFERENCES observations(id),

            FOREIGN KEY (baseline_observation_id)
                REFERENCES observations(id)
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            asset_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,

            port INTEGER,
            protocol TEXT,

            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',

            first_observation_id INTEGER NOT NULL,
            latest_observation_id INTEGER NOT NULL,

            occurrence_count INTEGER NOT NULL DEFAULT 1,

            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            resolved_at TEXT,

            FOREIGN KEY (asset_id)
                REFERENCES assets(id),

            FOREIGN KEY (first_observation_id)
                REFERENCES observations(id),

            FOREIGN KEY (latest_observation_id)
                REFERENCES observations(id)
        )
        """
    )

    # ------------------------------------------------------------------
    # Database migration
    # ------------------------------------------------------------------
    #
    # Existing ARGUS databases already have the events table.
    # CREATE TABLE IF NOT EXISTS will not modify that table.
    #
    # Add investigation_status only when it is missing.
    #
    cursor.execute(
        """
        PRAGMA table_info(events)
        """
    )

    event_columns = {
        row["name"]
        for row in cursor.fetchall()
    }

    if "investigation_status" not in event_columns:
        cursor.execute(
            """
            ALTER TABLE events
            ADD COLUMN investigation_status
            TEXT NOT NULL DEFAULT 'new'
            """
        )

    connection.commit()
    connection.close()


def get_or_create_asset(connection, asset):
    """
    Find an existing asset by IP address or create
    a new asset if ARGUS has never seen it before.
    """
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM assets
        WHERE ip = ?
        """,
        (asset.ip,)
    )

    result = cursor.fetchone()

    current_time = datetime.now().isoformat(
        timespec="seconds"
    )

    if result:
        asset_id = result[0]

        cursor.execute(
            """
            UPDATE assets
            SET mac = COALESCE(?, mac),
                hostname = COALESCE(?, hostname),
                last_seen = ?
            WHERE id = ?
            """,
            (
                asset.mac,
                asset.hostname,
                current_time,
                asset_id,
            )
        )

        return asset_id

    cursor.execute(
        """
        INSERT INTO assets (
            ip,
            mac,
            hostname,
            first_seen,
            last_seen
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            asset.ip,
            asset.mac,
            asset.hostname,
            current_time,
            current_time,
        )
    )

    return cursor.lastrowid


def create_observation(connection, asset_id, asset):
    """
    Create a historical observation for an asset.
    """
    cursor = connection.cursor()

    observed_at = datetime.now().isoformat(
        timespec="seconds"
    )

    cursor.execute(
        """
        INSERT INTO observations (
            asset_id,
            status,
            observed_at
        )
        VALUES (?, ?, ?)
        """,
        (
            asset_id,
            asset.status,
            observed_at,
        )
    )

    return cursor.lastrowid


def save_services(connection, observation_id, services):
    """
    Store services associated with an observation.
    """
    cursor = connection.cursor()

    for service in services:
        cursor.execute(
            """
            INSERT INTO services (
                observation_id,
                port,
                protocol,
                name,
                product,
                version
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                observation_id,
                service.port,
                service.protocol,
                service.name,
                service.product,
                service.version,
            )
        )


def save_asset_observation(asset):
    """
    Save one complete ARGUS asset observation,
    including its discovered services.
    """
    connection = get_connection()

    try:
        asset_id = get_or_create_asset(
            connection,
            asset
        )

        observation_id = create_observation(
            connection,
            asset_id,
            asset
        )

        save_services(
            connection,
            observation_id,
            asset.services
        )

        connection.commit()

        return observation_id

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def set_asset_baseline(ip_address, observation_id):
    """
    Set an existing observation as the reference
    baseline for an asset.

    If the asset already has a baseline, replace it.
    """
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id
            FROM assets
            WHERE ip = ?
            """,
            (ip_address,)
        )

        asset_result = cursor.fetchone()

        if asset_result is None:
            raise ValueError(
                f"Asset not found: {ip_address}"
            )

        asset_id = asset_result[0]

        cursor.execute(
            """
            SELECT id
            FROM observations
            WHERE id = ?
              AND asset_id = ?
            """,
            (
                observation_id,
                asset_id,
            )
        )

        observation_result = cursor.fetchone()

        if observation_result is None:
            raise ValueError(
                "The selected observation does not "
                "belong to this asset."
            )

        created_at = datetime.now().isoformat(
            timespec="seconds"
        )

        cursor.execute(
            """
            INSERT INTO baselines (
                asset_id,
                observation_id,
                created_at
            )
            VALUES (?, ?, ?)

            ON CONFLICT(asset_id)
            DO UPDATE SET
                observation_id = excluded.observation_id,
                created_at = excluded.created_at
            """,
            (
                asset_id,
                observation_id,
                created_at,
            )
        )

        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_asset_baseline(ip_address):
    """
    Return the reference baseline observation
    configured for an asset.
    """
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                baselines.observation_id,
                baselines.created_at
            FROM baselines

            JOIN assets
                ON assets.id = baselines.asset_id

            WHERE assets.ip = ?
            """,
            (ip_address,)
        )

        result = cursor.fetchone()

        if result is None:
            return None

        return {
            "observation_id": result[0],
            "created_at": result[1],
        }

    finally:
        connection.close()