from datetime import datetime

from core.database import get_connection
from core.baseline import compare_to_baseline
from core.alerts import (
    process_event,
    resolve_cleared_alerts,
)


def get_asset_id(connection, ip_address):
    """
    Return the database ID for an ARGUS asset.
    """
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM assets
        WHERE ip = ?
        """,
        (ip_address,)
    )

    result = cursor.fetchone()

    if result is None:
        raise ValueError(
            f"Asset not found: {ip_address}"
        )

    return result[0]


def find_existing_event(
    connection,
    asset_id,
    observation_id,
    event_type,
    port,
    protocol,
):
    """
    Check whether ARGUS has already recorded
    this event for this observation.
    """
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM events
        WHERE asset_id = ?
          AND observation_id = ?
          AND event_type = ?
          AND port IS ?
          AND protocol IS ?
        LIMIT 1
        """,
        (
            asset_id,
            observation_id,
            event_type,
            port,
            protocol,
        )
    )

    result = cursor.fetchone()

    if result is None:
        return None

    return result[0]


def create_event(
    connection,
    asset_id,
    observation_id,
    baseline_observation_id,
    event_type,
    severity,
    message,
    service=None,
):
    """
    Store one ARGUS detection event.

    If the same event already exists for this
    observation, do not create a duplicate.
    """
    port = None
    protocol = None
    service_name = None
    product = None
    version = None

    if service is not None:
        port = service[0]
        protocol = service[1]
        service_name = service[2]
        product = service[3]
        version = service[4]

    existing_event_id = find_existing_event(
        connection=connection,
        asset_id=asset_id,
        observation_id=observation_id,
        event_type=event_type,
        port=port,
        protocol=protocol,
    )

    if existing_event_id is not None:
        return {
            "id": existing_event_id,
            "created": False,
        }

    cursor = connection.cursor()

    created_at = datetime.now().isoformat(
        timespec="seconds"
    )

    cursor.execute(
        """
        INSERT INTO events (
            asset_id,
            observation_id,
            baseline_observation_id,
            event_type,
            severity,
            status,
            port,
            protocol,
            service_name,
            product,
            version,
            message,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            asset_id,
            observation_id,
            baseline_observation_id,
            event_type,
            severity,
            "new",
            port,
            protocol,
            service_name,
            product,
            version,
            message,
            created_at,
        )
    )

    return {
        "id": cursor.lastrowid,
        "created": True,
    }


def generate_detection_events(
    ip_address,
    observation_id=None,
):
    """
    Compare an observation against the configured
    reference baseline.

    Create detection events for differences,
    process active alerts, and resolve alerts whose
    conditions are no longer present.
    """
    comparison = compare_to_baseline(
        ip_address,
        current_observation_id=observation_id,
    )

    connection = get_connection()

    try:
        asset_id = get_asset_id(
            connection,
            ip_address
        )

        baseline_id = comparison[
            "reference_observation"
        ]

        current_id = comparison[
            "current_observation"
        ]

        created_events = []
        existing_events = []

        for service in comparison["added"]:
            port = service[0]
            protocol = service[1]
            name = service[2] or "Unknown"

            message = (
                f"Service {port}/{protocol} "
                f"({name}) was observed but is "
                f"not present in reference "
                f"baseline #{baseline_id}."
            )

            result = create_event(
                connection=connection,
                asset_id=asset_id,
                observation_id=current_id,
                baseline_observation_id=baseline_id,
                event_type="service_added",
                severity="informational",
                message=message,
                service=service,
            )

            if result["created"]:
                created_events.append(
                    result["id"]
                )
            else:
                existing_events.append(
                    result["id"]
                )

        for service in comparison["removed"]:
            port = service[0]
            protocol = service[1]
            name = service[2] or "Unknown"

            message = (
                f"Baseline service {port}/{protocol} "
                f"({name}) was not observed in "
                f"observation #{current_id}."
            )

            result = create_event(
                connection=connection,
                asset_id=asset_id,
                observation_id=current_id,
                baseline_observation_id=baseline_id,
                event_type="service_removed",
                severity="informational",
                message=message,
                service=service,
            )

            if result["created"]:
                created_events.append(
                    result["id"]
                )
            else:
                existing_events.append(
                    result["id"]
                )

        for previous, current in comparison["changed"]:
            port = current[0]
            protocol = current[1]

            message = (
                f"Service details for "
                f"{port}/{protocol} changed "
                f"relative to reference "
                f"baseline #{baseline_id}."
            )

            result = create_event(
                connection=connection,
                asset_id=asset_id,
                observation_id=current_id,
                baseline_observation_id=baseline_id,
                event_type="service_changed",
                severity="informational",
                message=message,
                service=current,
            )

            if result["created"]:
                created_events.append(
                    result["id"]
                )
            else:
                existing_events.append(
                    result["id"]
                )

        # Commit events before the alert manager
        # opens another database connection.
        connection.commit()

        alert_results = []

        for event_id in created_events:
            alert_result = process_event(
                event_id
            )

            alert_results.append(
                alert_result
            )

        resolved_alerts = resolve_cleared_alerts(
            ip_address=ip_address,
            observation_id=current_id,
            comparison=comparison,
        )

        return {
            "asset": ip_address,
            "baseline_observation": baseline_id,
            "current_observation": current_id,
            "events_created": created_events,
            "events_existing": existing_events,
            "alerts_processed": alert_results,
            "alerts_resolved": resolved_alerts,
        }

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()