from datetime import datetime

from core.database import get_connection
from core.notifier import notify_alert


INVESTIGATION_STATUSES = {
    "new",
    "investigating",
    "resolved",
}


def find_active_alert(
    connection,
    asset_id,
    event_type,
    port,
    protocol,
):
    """
    Find an active alert representing the same
    ongoing condition.
    """
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT
            id,
            latest_observation_id,
            occurrence_count
        FROM alerts
        WHERE asset_id = ?
          AND event_type = ?
          AND port IS ?
          AND protocol IS ?
          AND status = 'active'
        LIMIT 1
        """,
        (
            asset_id,
            event_type,
            port,
            protocol,
        )
    )

    return cursor.fetchone()


def create_alert(
    connection,
    asset_id,
    event_type,
    severity,
    observation_id,
    port=None,
    protocol=None,
):
    """
    Create a new active alert.
    """
    cursor = connection.cursor()

    current_time = datetime.now().isoformat(
        timespec="seconds"
    )

    cursor.execute(
        """
        INSERT INTO alerts (
            asset_id,
            event_type,
            port,
            protocol,
            severity,
            status,
            first_observation_id,
            latest_observation_id,
            occurrence_count,
            first_seen,
            last_seen,
            resolved_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            asset_id,
            event_type,
            port,
            protocol,
            severity,
            "active",
            observation_id,
            observation_id,
            1,
            current_time,
            current_time,
            None,
        )
    )

    return cursor.lastrowid


def update_alert(
    connection,
    alert_id,
    latest_observation_id,
):
    """
    Update an existing active alert when the same
    condition is observed again.

    Do not increase the occurrence count if the
    same observation is processed more than once.
    """
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT latest_observation_id
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,)
    )

    result = cursor.fetchone()

    if result is None:
        raise ValueError(
            f"Alert not found: {alert_id}"
        )

    previous_observation_id = result[0]

    if previous_observation_id == latest_observation_id:
        return False

    current_time = datetime.now().isoformat(
        timespec="seconds"
    )

    cursor.execute(
        """
        UPDATE alerts
        SET latest_observation_id = ?,
            occurrence_count = occurrence_count + 1,
            last_seen = ?
        WHERE id = ?
        """,
        (
            latest_observation_id,
            current_time,
            alert_id,
        )
    )

    return True


def process_event(event_id):
    """
    Convert a stored detection event into an alert,
    or update an existing active alert representing
    the same condition.
    """
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                asset_id,
                observation_id,
                event_type,
                severity,
                port,
                protocol
            FROM events
            WHERE id = ?
            """,
            (event_id,)
        )

        event = cursor.fetchone()

        if event is None:
            raise ValueError(
                f"Event not found: {event_id}"
            )

        asset_id = event[0]
        observation_id = event[1]
        event_type = event[2]
        severity = event[3]
        port = event[4]
        protocol = event[5]

        active_alert = find_active_alert(
            connection=connection,
            asset_id=asset_id,
            event_type=event_type,
            port=port,
            protocol=protocol,
        )

        if active_alert is None:
            alert_id = create_alert(
                connection=connection,
                asset_id=asset_id,
                event_type=event_type,
                severity=severity,
                observation_id=observation_id,
                port=port,
                protocol=protocol,
            )

            action = "created"

        else:
            alert_id = active_alert[0]

            changed = update_alert(
                connection=connection,
                alert_id=alert_id,
                latest_observation_id=observation_id,
            )

            if changed:
                action = "updated"
            else:
                action = "unchanged"

        connection.commit()

        # Push only brand new alerts, so a persisting condition
        # does not notify the operator on every scan.
        if action == "created":
            notify_alert(alert_id)

        return {
            "event_id": event_id,
            "alert_id": alert_id,
            "action": action,
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def get_current_deviation_keys(comparison):
    """
    Build a set containing the deviation conditions
    currently present relative to the baseline.
    """
    deviation_keys = set()

    for service in comparison["added"]:
        deviation_keys.add(
            (
                "service_added",
                service[0],
                service[1],
            )
        )

    for service in comparison["removed"]:
        deviation_keys.add(
            (
                "service_removed",
                service[0],
                service[1],
            )
        )

    for previous, current in comparison["changed"]:
        deviation_keys.add(
            (
                "service_changed",
                current[0],
                current[1],
            )
        )

    return deviation_keys


def resolve_cleared_alerts(
    ip_address,
    observation_id,
    comparison,
):
    """
    Resolve active alerts whose conditions are no
    longer present in the current baseline comparison.
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

        asset = cursor.fetchone()

        if asset is None:
            raise ValueError(
                f"Asset not found: {ip_address}"
            )

        asset_id = asset[0]

        current_deviations = (
            get_current_deviation_keys(
                comparison
            )
        )

        cursor.execute(
            """
            SELECT
                id,
                event_type,
                port,
                protocol
            FROM alerts
            WHERE asset_id = ?
              AND status = 'active'
            """,
            (asset_id,)
        )

        active_alerts = cursor.fetchall()

        resolved_alerts = []

        current_time = datetime.now().isoformat(
            timespec="seconds"
        )

        for alert in active_alerts:
            alert_id = alert[0]

            alert_key = (
                alert[1],
                alert[2],
                alert[3],
            )

            if alert_key in current_deviations:
                continue

            cursor.execute(
                """
                UPDATE alerts
                SET status = 'resolved',
                    latest_observation_id = ?,
                    last_seen = ?,
                    resolved_at = ?
                WHERE id = ?
                """,
                (
                    observation_id,
                    current_time,
                    current_time,
                    alert_id,
                )
            )

            resolved_alerts.append(
                alert_id
            )

        connection.commit()

        return resolved_alerts

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# ======================================================================
# Investigation workflow
# ======================================================================


def get_investigation_status(event_id):
    """
    Return the current investigation status for an event.
    """
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT investigation_status
            FROM events
            WHERE id = ?
            """,
            (event_id,)
        )

        result = cursor.fetchone()

        if result is None:
            raise ValueError(
                f"Event not found: {event_id}"
            )

        return result[0]

    finally:
        connection.close()


def set_investigation_status(
    event_id,
    status,
):
    """
    Change the investigation state of an event.

    Valid states:
        new
        investigating
        resolved
    """
    normalized_status = (
        status.strip().lower()
    )

    if normalized_status not in INVESTIGATION_STATUSES:
        raise ValueError(
            "Invalid investigation status: "
            f"{status}. Expected one of: "
            f"{', '.join(sorted(INVESTIGATION_STATUSES))}"
        )

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id
            FROM events
            WHERE id = ?
            """,
            (event_id,)
        )

        event = cursor.fetchone()

        if event is None:
            raise ValueError(
                f"Event not found: {event_id}"
            )

        cursor.execute(
            """
            UPDATE events
            SET investigation_status = ?
            WHERE id = ?
            """,
            (
                normalized_status,
                event_id,
            )
        )

        connection.commit()

        return {
            "event_id": event_id,
            "investigation_status": normalized_status,
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def start_investigation(event_id):
    """
    Mark an event as actively being investigated.
    """
    return set_investigation_status(
        event_id,
        "investigating",
    )


def resolve_investigation(event_id):
    """
    Mark an event investigation as resolved.
    """
    return set_investigation_status(
        event_id,
        "resolved",
    )


def reopen_investigation(event_id):
    """
    Return a resolved investigation to the new state.
    """
    return set_investigation_status(
        event_id,
        "new",
    )
