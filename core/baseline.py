from core.database import get_connection


def get_asset_id(connection, ip_address):
    """
    Find the database ID of an asset using its IP address.
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
        return None

    return result[0]


def get_observations(connection, asset_id):
    """
    Return observations for an asset from newest to oldest.
    """
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, observed_at
        FROM observations
        WHERE asset_id = ?
        ORDER BY id DESC
        """,
        (asset_id,)
    )

    return cursor.fetchall()


def observation_belongs_to_asset(
    connection,
    observation_id,
    asset_id,
):
    """
    Check whether an observation belongs to an asset.
    """
    cursor = connection.cursor()

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

    return cursor.fetchone() is not None


def get_services(connection, observation_id):
    """
    Return the services recorded for one observation.
    """
    cursor = connection.cursor()

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
        """,
        (observation_id,)
    )

    return cursor.fetchall()


def get_reference_baseline(
    connection,
    asset_id,
):
    """
    Return the reference baseline observation
    configured for an asset.
    """
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT observation_id
        FROM baselines
        WHERE asset_id = ?
        """,
        (asset_id,)
    )

    result = cursor.fetchone()

    if result is None:
        return None

    return result[0]


def service_key(service):
    """
    Create a simple identity for a network service.

    A service is identified by its port and protocol.
    """
    port = service[0]
    protocol = service[1]

    return port, protocol


def compare_service_sets(
    previous_services,
    current_services,
):
    """
    Compare two sets of observed services.

    Return services that were added, removed,
    or remained present but changed details.
    """
    previous_map = {
        service_key(service): service
        for service in previous_services
    }

    current_map = {
        service_key(service): service
        for service in current_services
    }

    previous_keys = set(previous_map)
    current_keys = set(current_map)

    added_keys = (
        current_keys - previous_keys
    )

    removed_keys = (
        previous_keys - current_keys
    )

    common_keys = (
        previous_keys & current_keys
    )

    added = [
        current_map[key]
        for key in sorted(added_keys)
    ]

    removed = [
        previous_map[key]
        for key in sorted(removed_keys)
    ]

    changed = []

    for key in sorted(common_keys):
        previous_service = previous_map[key]
        current_service = current_map[key]

        if previous_service != current_service:
            changed.append(
                (
                    previous_service,
                    current_service,
                )
            )

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def compare_observation_ids(
    connection,
    ip_address,
    asset_id,
    reference_observation_id,
    current_observation_id,
    comparison_type,
):
    """
    Compare two specific observations belonging
    to the same asset.
    """
    if not observation_belongs_to_asset(
        connection,
        reference_observation_id,
        asset_id,
    ):
        raise ValueError(
            "Reference observation does not "
            "belong to this asset."
        )

    if not observation_belongs_to_asset(
        connection,
        current_observation_id,
        asset_id,
    ):
        raise ValueError(
            "Current observation does not "
            "belong to this asset."
        )

    reference_services = get_services(
        connection,
        reference_observation_id
    )

    current_services = get_services(
        connection,
        current_observation_id
    )

    differences = compare_service_sets(
        reference_services,
        current_services
    )

    return {
        "ip": ip_address,
        "comparison_type": comparison_type,
        "reference_observation":
            reference_observation_id,
        "current_observation":
            current_observation_id,
        "added": differences["added"],
        "removed": differences["removed"],
        "changed": differences["changed"],
    }


def compare_observations(
    ip_address,
    previous_observation_id=None,
    current_observation_id=None,
):
    """
    Compare two chronological observations.

    If IDs are not supplied, compare the two
    most recent observations automatically.
    """
    connection = get_connection()

    try:
        asset_id = get_asset_id(
            connection,
            ip_address
        )

        if asset_id is None:
            raise ValueError(
                f"Asset not found: {ip_address}"
            )

        observations = get_observations(
            connection,
            asset_id
        )

        if len(observations) < 2:
            raise ValueError(
                "At least two observations are required "
                "for change detection."
            )

        if current_observation_id is None:
            current_observation_id = (
                observations[0][0]
            )

        if previous_observation_id is None:
            previous_candidates = [
                observation[0]
                for observation in observations
                if observation[0]
                < current_observation_id
            ]

            if not previous_candidates:
                raise ValueError(
                    "No previous observation exists "
                    "for the selected current observation."
                )

            previous_observation_id = (
                previous_candidates[0]
            )

        return compare_observation_ids(
            connection=connection,
            ip_address=ip_address,
            asset_id=asset_id,
            reference_observation_id=(
                previous_observation_id
            ),
            current_observation_id=(
                current_observation_id
            ),
            comparison_type="previous",
        )

    finally:
        connection.close()


def compare_to_baseline(
    ip_address,
    current_observation_id=None,
):
    """
    Compare an observation against the asset's
    explicit reference baseline.

    If no current observation ID is supplied,
    use the most recent observation.
    """
    connection = get_connection()

    try:
        asset_id = get_asset_id(
            connection,
            ip_address
        )

        if asset_id is None:
            raise ValueError(
                f"Asset not found: {ip_address}"
            )

        baseline_observation_id = (
            get_reference_baseline(
                connection,
                asset_id
            )
        )

        if baseline_observation_id is None:
            raise ValueError(
                "No reference baseline has been "
                "configured for this asset."
            )

        observations = get_observations(
            connection,
            asset_id
        )

        if not observations:
            raise ValueError(
                "No observations exist for this asset."
            )

        if current_observation_id is None:
            current_observation_id = (
                observations[0][0]
            )

        return compare_observation_ids(
            connection=connection,
            ip_address=ip_address,
            asset_id=asset_id,
            reference_observation_id=(
                baseline_observation_id
            ),
            current_observation_id=(
                current_observation_id
            ),
            comparison_type="baseline",
        )

    finally:
        connection.close()