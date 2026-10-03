from core.database import get_connection
from core.risk import (
    calculate_event_risk,
    calculate_alert_risk,
    risk_summary,
)


# ============================================================
# RISK ENRICHMENT
# ============================================================

def _add_event_risk(event):
    """
    Add explainable risk intelligence to a detection event.
    """

    baseline_deviation = (
        event.get("baseline_observation_id") is not None
    )

    service_exposed = (
        event.get("port") is not None
    )

    result = calculate_event_risk(
        event_type=event.get("event_type"),
        severity=event.get("severity"),
        baseline_deviation=baseline_deviation,
        alert_active=event.get("alert_active", False),
        service_exposed=service_exposed,
    )

    event["risk"] = risk_summary(result)

    return event


def _add_alert_risk(alert):
    """
    Add explainable risk intelligence to an alert.
    """

    baseline_deviation = (
        alert.get("baseline_deviation", False)
    )

    service_exposed = (
        alert.get("port") is not None
    )

    result = calculate_alert_risk(
        severity=alert.get("severity"),
        event_type=alert.get("event_type"),
        occurrence_count=alert.get("occurrence_count", 1),
        baseline_deviation=baseline_deviation,
        service_exposed=service_exposed,
    )

    alert["risk"] = risk_summary(result)

    return alert


# ============================================================
# PRIORITIZATION
# ============================================================

_PRIORITY_ORDER = {
    "critical": 4,
    "high": 3,
    "elevated": 2,
    "normal": 1,
}


def _priority_rank(priority):
    """
    Convert a priority label into a sortable rank.
    """

    return _PRIORITY_ORDER.get(
        (priority or "").lower(),
        0,
    )


def _prioritization_key(item):
    """
    Build a consistent sorting key for events and alerts.

    Priority comes first.
    Risk score comes second.
    Newer activity comes third.
    """

    risk = item.get("risk", {})

    priority = risk.get("priority", "normal")
    score = risk.get("score", 0)

    timestamp = (
        item.get("created_at")
        or item.get("last_seen")
        or ""
    )

    return (
        _priority_rank(priority),
        score,
        timestamp,
    )


def prioritize_events(events):
    """
    Sort detection events by operational priority.

    Highest priority and highest risk appear first.
    """

    return sorted(
        events,
        key=_prioritization_key,
        reverse=True,
    )


def prioritize_alerts(alerts):
    """
    Sort alerts by operational priority.

    Highest priority and highest risk appear first.
    """

    return sorted(
        alerts,
        key=_prioritization_key,
        reverse=True,
    )


# ============================================================
# OBSERVATION INTELLIGENCE
# ============================================================

def get_observation_detail(asset_id, observation_id):
    """
    Return one observation, its detected services,
    and detection events associated with it.
    """

    connection = get_connection()
    cursor = connection.cursor()

    try:
        # ----------------------------------------------------
        # Observation
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                o.id,
                o.asset_id,
                o.observed_at,
                o.status,
                a.ip
            FROM observations o
            JOIN assets a
                ON a.id = o.asset_id
            WHERE o.asset_id = ?
              AND o.id = ?
            """,
            (
                asset_id,
                observation_id,
            ),
        )

        observation = cursor.fetchone()

        if observation is None:
            return None

        result = dict(observation)

        # ----------------------------------------------------
        # Services
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                id,
                observation_id,
                port,
                protocol,
                name,
                product,
                version
            FROM services
            WHERE observation_id = ?
            ORDER BY port
            """,
            (observation_id,),
        )

        result["services"] = [
            dict(row)
            for row in cursor.fetchall()
        ]

        # ----------------------------------------------------
        # Detection Events
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                id,
                asset_id,
                observation_id,
                baseline_observation_id,
                event_type,
                severity,
                status,
                investigation_status,
                port,
                protocol,
                service_name,
                product,
                version,
                message,
                created_at
            FROM events
            WHERE asset_id = ?
              AND observation_id = ?
            ORDER BY created_at DESC
            """,
            (
                asset_id,
                observation_id,
            ),
        )

        events = [
            dict(row)
            for row in cursor.fetchall()
        ]

        # Determine whether each event has an active alert.
        for event in events:
            cursor.execute(
                """
                SELECT 1
                FROM alerts
                WHERE asset_id = ?
                  AND event_type = ?
                  AND status = 'active'
                  AND (
                        port = ?
                        OR (
                            port IS NULL
                            AND ? IS NULL
                        )
                      )
                LIMIT 1
                """,
                (
                    event["asset_id"],
                    event["event_type"],
                    event["port"],
                    event["port"],
                ),
            )

            event["alert_active"] = (
                cursor.fetchone() is not None
            )

            _add_event_risk(event)

        result["events"] = prioritize_events(events)

        # ----------------------------------------------------
        # Baseline State
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                1
            FROM baselines
            WHERE asset_id = ?
              AND observation_id = ?
            LIMIT 1
            """,
            (
                asset_id,
                observation_id,
            ),
        )

        result["is_baseline"] = (
            cursor.fetchone() is not None
        )

        return result

    finally:
        connection.close()


# ============================================================
# RECENT DETECTION EVENTS
# ============================================================

def get_recent_events(limit=20):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                e.id,
                e.asset_id,
                a.ip,
                e.observation_id,
                e.baseline_observation_id,
                e.event_type,
                e.severity,
                e.status,
                e.investigation_status,
                e.port,
                e.protocol,
                e.service_name,
                e.product,
                e.version,
                e.message,
                e.created_at
            FROM events e
            JOIN assets a
                ON a.id = e.asset_id
            ORDER BY e.created_at DESC
            LIMIT ?
            """,
            (limit,),
        )

        events = [
            dict(row)
            for row in cursor.fetchall()
        ]

        for event in events:
            cursor.execute(
                """
                SELECT 1
                FROM alerts
                WHERE asset_id = ?
                  AND event_type = ?
                  AND status = 'active'
                  AND (
                        port = ?
                        OR (
                            port IS NULL
                            AND ? IS NULL
                        )
                      )
                LIMIT 1
                """,
                (
                    event["asset_id"],
                    event["event_type"],
                    event["port"],
                    event["port"],
                ),
            )

            event["alert_active"] = (
                cursor.fetchone() is not None
            )

            _add_event_risk(event)

        return prioritize_events(events)

    finally:
        connection.close()


# ============================================================
# ACTIVE ALERTS
# ============================================================

def get_active_alerts(limit=20):
    """
    Return currently active alerts with related asset
    and risk information.
    """

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                alerts.id,
                alerts.asset_id,
                assets.ip,
                alerts.event_type,
                alerts.port,
                alerts.protocol,
                alerts.severity,
                alerts.status,
                alerts.first_observation_id,
                alerts.latest_observation_id,
                alerts.occurrence_count,
                alerts.first_seen,
                alerts.last_seen,
                alerts.resolved_at
            FROM alerts
            JOIN assets
                ON assets.id = alerts.asset_id
            WHERE alerts.status = 'active'
            ORDER BY alerts.last_seen DESC
            LIMIT ?
            """,
            (limit,),
        )

        alerts = [
            dict(row)
            for row in cursor.fetchall()
        ]

        for alert in alerts:
            cursor.execute(
                """
                SELECT
                    1
                FROM events
                WHERE asset_id = ?
                  AND observation_id = ?
                  AND baseline_observation_id IS NOT NULL
                  AND event_type = ?
                  AND (
                        port = ?
                        OR (
                            port IS NULL
                            AND ? IS NULL
                        )
                      )
                LIMIT 1
                """,
                (
                    alert["asset_id"],
                    alert["latest_observation_id"],
                    alert["event_type"],
                    alert["port"],
                    alert["port"],
                ),
            )

            alert["baseline_deviation"] = (
                cursor.fetchone() is not None
            )

            _add_alert_risk(alert)

        return prioritize_alerts(alerts)

    finally:
        connection.close()


# ============================================================
# ALERT DETAIL
# ============================================================

def get_alert_detail(alert_id):
    """
    Return complete intelligence for one alert,
    including related events and risk information.
    """

    connection = get_connection()
    cursor = connection.cursor()

    try:
        # ----------------------------------------------------
        # Alert
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                alerts.id,
                alerts.asset_id,
                assets.ip,
                alerts.event_type,
                alerts.port,
                alerts.protocol,
                alerts.severity,
                alerts.status,
                alerts.first_observation_id,
                alerts.latest_observation_id,
                alerts.occurrence_count,
                alerts.first_seen,
                alerts.last_seen,
                alerts.resolved_at
            FROM alerts
            JOIN assets
                ON assets.id = alerts.asset_id
            WHERE alerts.id = ?
            """,
            (alert_id,),
        )

        alert = cursor.fetchone()

        if alert is None:
            return None

        result = dict(alert)

        # ----------------------------------------------------
        # Baseline Deviation
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                1
            FROM events
            WHERE asset_id = ?
              AND observation_id = ?
              AND baseline_observation_id IS NOT NULL
              AND event_type = ?
              AND (
                    port = ?
                    OR (
                        port IS NULL
                        AND ? IS NULL
                    )
                  )
            LIMIT 1
            """,
            (
                result["asset_id"],
                result["latest_observation_id"],
                result["event_type"],
                result["port"],
                result["port"],
            ),
        )

        result["baseline_deviation"] = (
            cursor.fetchone() is not None
        )

        _add_alert_risk(result)

        # ----------------------------------------------------
        # Related Detection Events
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                id,
                asset_id,
                observation_id,
                baseline_observation_id,
                event_type,
                severity,
                status,
                investigation_status,
                port,
                protocol,
                service_name,
                product,
                version,
                message,
                created_at
            FROM events
            WHERE asset_id = ?
              AND event_type = ?
              AND (
                    port = ?
                    OR (
                        port IS NULL
                        AND ? IS NULL
                    )
                  )
            ORDER BY created_at DESC
            """,
            (
                result["asset_id"],
                result["event_type"],
                result["port"],
                result["port"],
            ),
        )

        events = [
            dict(row)
            for row in cursor.fetchall()
        ]

        for event in events:
            event["alert_active"] = (
                result["status"] == "active"
            )

            _add_event_risk(event)

        result["events"] = prioritize_events(events)

        return result

    finally:
        connection.close()


# ============================================================
# ASSET EVENTS
# ============================================================

def get_asset_events(asset_id, limit=20):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                e.id,
                e.asset_id,
                e.observation_id,
                e.baseline_observation_id,
                e.event_type,
                e.severity,
                e.status,
                e.port,
                e.protocol,
                e.service_name,
                e.product,
                e.version,
                e.message,
                e.created_at
            FROM events e
            WHERE e.asset_id = ?
            ORDER BY e.created_at DESC
            LIMIT ?
            """,
            (
                asset_id,
                limit,
            ),
        )

        events = [
            dict(row)
            for row in cursor.fetchall()
        ]

        for event in events:
            cursor.execute(
                """
                SELECT 1
                FROM alerts
                WHERE asset_id = ?
                  AND event_type = ?
                  AND status = 'active'
                  AND (
                        port = ?
                        OR (
                            port IS NULL
                            AND ? IS NULL
                        )
                      )
                LIMIT 1
                """,
                (
                    event["asset_id"],
                    event["event_type"],
                    event["port"],
                    event["port"],
                ),
            )

            event["alert_active"] = (
                cursor.fetchone() is not None
            )

            _add_event_risk(event)

        return prioritize_events(events)

    finally:
        connection.close()


# ============================================================
# ASSET ALERTS
# ============================================================

def get_asset_alerts(asset_id, limit=20):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
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
            FROM alerts
            WHERE asset_id = ?
            ORDER BY last_seen DESC
            LIMIT ?
            """,
            (
                asset_id,
                limit,
            ),
        )

        alerts = [
            dict(row)
            for row in cursor.fetchall()
        ]

        for alert in alerts:
            cursor.execute(
                """
                SELECT
                    1
                FROM events
                WHERE asset_id = ?
                  AND observation_id = ?
                  AND baseline_observation_id IS NOT NULL
                  AND event_type = ?
                  AND (
                        port = ?
                        OR (
                            port IS NULL
                            AND ? IS NULL
                        )
                      )
                LIMIT 1
                """,
                (
                    alert["asset_id"],
                    alert["latest_observation_id"],
                    alert["event_type"],
                    alert["port"],
                    alert["port"],
                ),
            )

            alert["baseline_deviation"] = (
                cursor.fetchone() is not None
            )

            _add_alert_risk(alert)

        return prioritize_alerts(alerts)

    finally:
        connection.close()


# ============================================================
# ASSET INVENTORY
# ============================================================

def get_asset_inventory():
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                a.id,
                a.ip,
                a.hostname,
                a.mac,
                a.first_seen,
                a.last_seen,

                (
                    SELECT o.id
                    FROM observations o
                    WHERE o.asset_id = a.id
                    ORDER BY o.observed_at DESC
                    LIMIT 1
                ) AS latest_observation_id,

                (
                    SELECT o.status
                    FROM observations o
                    WHERE o.asset_id = a.id
                    ORDER BY o.observed_at DESC
                    LIMIT 1
                ) AS status,

                (
                    SELECT COUNT(*)
                    FROM services s
                    JOIN observations o
                        ON o.id = s.observation_id
                    WHERE o.asset_id = a.id
                      AND o.id = (
                          SELECT o2.id
                          FROM observations o2
                          WHERE o2.asset_id = a.id
                          ORDER BY o2.observed_at DESC
                          LIMIT 1
                      )
                ) AS open_services,

                (
                    SELECT b.observation_id
                    FROM baselines b
                    WHERE b.asset_id = a.id
                    LIMIT 1
                ) AS baseline_observation_id

            FROM assets a
            ORDER BY a.last_seen DESC
            """
        )

        return [
            dict(row)
            for row in cursor.fetchall()
        ]

    finally:
        connection.close()


# ============================================================
# SINGLE ASSET
# ============================================================

def get_asset_by_id(asset_id):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                ip,
                hostname,
                mac,
                first_seen,
                last_seen
            FROM assets
            WHERE id = ?
            """,
            (asset_id,),
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        connection.close()


# ============================================================
# SERVICES FOR OBSERVATION
# ============================================================

def _get_services_for_observation(
    cursor,
    observation_id,
):
    cursor.execute(
        """
        SELECT
            id,
            observation_id,
            port,
            protocol,
            name,
            product,
            version
        FROM services
        WHERE observation_id = ?
        ORDER BY port
        """,
        (observation_id,),
    )

    return [
        dict(row)
        for row in cursor.fetchall()
    ]


# ============================================================
# ASSET STATE COMPARISON
# ============================================================

def get_asset_state_comparison(asset_id):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                observed_at,
                status
            FROM observations
            WHERE asset_id = ?
            ORDER BY observed_at DESC
            LIMIT 1
            """,
            (asset_id,),
        )

        latest = cursor.fetchone()

        cursor.execute(
            """
            SELECT
                o.id,
                o.observed_at,
                o.status
            FROM observations o
            JOIN baselines b
                ON b.observation_id = o.id
            WHERE b.asset_id = ?
            LIMIT 1
            """,
            (asset_id,),
        )

        baseline = cursor.fetchone()

        def enrich_observation(row):
            if row is None:
                return None

            observation = dict(row)

            cursor.execute(
                """
                SELECT COUNT(*)
                FROM services
                WHERE observation_id = ?
                """,
                (observation["id"],),
            )

            observation["service_count"] = cursor.fetchone()[0]

            return observation

        return {
            "baseline": enrich_observation(baseline),
            "latest": enrich_observation(latest),
        }

    finally:
        connection.close()