from core.database import get_connection


def get_asset_history(ip_address):
    """
    Retrieve the stored history of one ARGUS asset,
    including its configured reference baseline.
    """
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT
                id,
                ip,
                mac,
                hostname,
                first_seen,
                last_seen
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

        cursor.execute(
            """
            SELECT observation_id
            FROM baselines
            WHERE asset_id = ?
            """,
            (asset_id,)
        )

        baseline_result = cursor.fetchone()

        baseline_observation_id = None

        if baseline_result is not None:
            baseline_observation_id = (
                baseline_result[0]
            )

        cursor.execute(
            """
            SELECT
                id,
                status,
                observed_at
            FROM observations
            WHERE asset_id = ?
            ORDER BY id ASC
            """,
            (asset_id,)
        )

        observation_rows = cursor.fetchall()

        observations = []

        for observation in observation_rows:
            observation_id = observation[0]
            status = observation[1]
            observed_at = observation[2]

            cursor.execute(
                """
                SELECT
                    port,
                    protocol,
                    name,
                    product,
                    version
                FROM services
                WHERE observation_id = ?
                ORDER BY port ASC
                """,
                (observation_id,)
            )

            services = cursor.fetchall()

            is_baseline = (
                observation_id
                == baseline_observation_id
            )

            observations.append(
                {
                    "id": observation_id,
                    "status": status,
                    "observed_at": observed_at,
                    "services": services,
                    "is_baseline": is_baseline,
                }
            )

        return {
            "id": asset[0],
            "ip": asset[1],
            "mac": asset[2],
            "hostname": asset[3],
            "first_seen": asset[4],
            "last_seen": asset[5],
            "baseline_observation":
                baseline_observation_id,
            "observations": observations,
        }

    finally:
        connection.close()


def display_asset_history(ip_address):
    """
    Display the historical observations of one asset.
    """
    history = get_asset_history(ip_address)

    observations = history["observations"]

    print()
    print("=" * 50)
    print("ASSET HISTORY")
    print("=" * 50)

    print(f"IP Address   : {history['ip']}")
    print(
        f"MAC Address  : "
        f"{history['mac'] or 'Unknown'}"
    )
    print(
        f"Hostname     : "
        f"{history['hostname'] or 'Unknown'}"
    )
    print(f"First Seen   : {history['first_seen']}")
    print(f"Last Seen    : {history['last_seen']}")
    print(f"Observations : {len(observations)}")

    baseline_id = history[
        "baseline_observation"
    ]

    if baseline_id is None:
        print("Baseline     : Not configured")
    else:
        print(
            f"Baseline     : "
            f"Observation #{baseline_id}"
        )

    if not observations:
        print()
        print("No observations stored.")
        return

    print()
    print("HISTORY")
    print("-" * 50)

    for observation in observations:
        services = observation["services"]

        baseline_marker = ""

        if observation["is_baseline"]:
            baseline_marker = " [REFERENCE BASELINE]"

        print()
        print(
            f"Observation #{observation['id']}"
            f"{baseline_marker}"
        )

        print(
            f"Time     : "
            f"{observation['observed_at']}"
        )

        print(
            f"Status   : "
            f"{observation['status'].upper()}"
        )

        print(
            f"Services : "
            f"{len(services)}"
        )

        if not services:
            print("  No open services recorded.")
            continue

        for service in services:
            port = service[0]
            protocol = service[1]
            name = service[2] or "Unknown"
            product = service[3] or "Unknown"
            version = service[4] or "Unknown"

            print(
                f"  {port}/{protocol} "
                f"{name} | "
                f"{product} {version}"
            )