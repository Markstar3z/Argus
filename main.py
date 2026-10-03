from core.scanner import discover_hosts, scan_services
from core.parser import parse_discovery_report
from core.database import (
    initialize_database,
    save_asset_observation,
)
from core.baseline import (
    compare_observations,
    compare_to_baseline,
)
from core.history import display_asset_history
from core.detection import generate_detection_events


def display_asset(asset, number):
    """
    Display information about one discovered asset.
    """
    hostname = asset.hostname or "Unknown"
    mac_address = asset.mac or "Unknown"

    print()
    print(f"Asset #{number}")
    print(f"IP Address : {asset.ip}")
    print(f"MAC Address: {mac_address}")
    print(f"Hostname   : {hostname}")
    print(f"Status     : {asset.status.upper()}")


def display_services(asset):
    """
    Display the open services stored on an asset.
    """
    print()
    print(f"Services for {asset.ip}")
    print("-" * 50)

    if not asset.services:
        print("No open services discovered.")
        return

    for service in asset.services:
        name = service.name or "Unknown"
        product = service.product or "Unknown"
        version = service.version or "Unknown"

        print()
        print(
            f"Port       : "
            f"{service.port}/{service.protocol}"
        )
        print(f"Service    : {name}")
        print(f"Product    : {product}")
        print(f"Version    : {version}")


def enrich_asset_services(asset):
    """
    Perform service analysis on an asset and attach
    discovered services to the original Asset object.
    """
    service_report = scan_services(
        f"{asset.ip}/32"
    )

    service_assets = parse_discovery_report(
        service_report
    )

    if not service_assets:
        return asset

    service_asset = service_assets[0]

    asset.services = service_asset.services

    return asset


def display_service_details(service):
    """
    Display one service tuple returned by the
    baseline comparison engine.
    """
    port, protocol, name, product, version = service

    name = name or "Unknown"
    product = product or "Unknown"
    version = version or "Unknown"

    print(f"    Port    : {port}/{protocol}")
    print(f"    Service : {name}")
    print(f"    Product : {product}")
    print(f"    Version : {version}")


def display_changes(result):
    """
    Display the result of either a previous-state
    comparison or a reference-baseline comparison.
    """
    print()
    print(f"Asset    : {result['ip']}")

    comparison_type = result.get(
        "comparison_type",
        "previous"
    )

    reference_observation = result[
        "reference_observation"
    ]

    current_observation = result[
        "current_observation"
    ]

    if comparison_type == "baseline":
        print(
            f"Baseline : "
            f"#{reference_observation}"
        )
    else:
        print(
            f"Previous : "
            f"#{reference_observation}"
        )

    print(
        f"Current  : "
        f"#{current_observation}"
    )

    added = result["added"]
    removed = result["removed"]
    changed = result["changed"]

    if not added and not removed and not changed:
        print()

        if comparison_type == "baseline":
            print(
                "No baseline deviations detected."
            )
        else:
            print(
                "No service changes detected."
            )

        return

    for service in added:
        print()

        if comparison_type == "baseline":
            print("[+] BASELINE DEVIATION")
        else:
            print("[+] NEW SERVICE")

        display_service_details(service)

    for service in removed:
        print()

        if comparison_type == "baseline":
            print("[-] MISSING BASELINE SERVICE")
        else:
            print("[-] REMOVED SERVICE")

        display_service_details(service)

    for previous_service, current_service in changed:
        print()

        if comparison_type == "baseline":
            print("[*] BASELINE SERVICE CHANGED")
        else:
            print("[*] SERVICE DETAILS CHANGED")

        print("    Reference:")
        display_service_details(
            previous_service
        )

        print("    Current:")
        display_service_details(
            current_service
        )


def display_detection_result(result):
    """
    Display events and alert actions produced by
    the ARGUS detection engine.
    """
    print()
    print(f"Asset       : {result['asset']}")

    print(
        f"Baseline    : "
        f"#{result['baseline_observation']}"
    )

    print(
        f"Observation : "
        f"#{result['current_observation']}"
    )

    created = result["events_created"]
    existing = result["events_existing"]
    processed = result["alerts_processed"]
    resolved = result["alerts_resolved"]

    print(
        f"New Events  : "
        f"{len(created)}"
    )

    print(
        f"Known Events: "
        f"{len(existing)}"
    )

    if created:
        print(
            "Event IDs   : "
            + ", ".join(
                f"#{event_id}"
                for event_id in created
            )
        )

    if processed:
        for alert in processed:
            print(
                f"Alert #{alert['alert_id']}: "
                f"{alert['action']}"
            )

    if resolved:
        print(
            "Resolved    : "
            + ", ".join(
                f"Alert #{alert_id}"
                for alert_id in resolved
            )
        )

    if not processed and not resolved:
        print(
            "Alert Action: "
            "No alert state changes."
        )


def main():
    print("=" * 50)
    print("ARGUS")
    print("Defensive Network Intelligence Platform")
    print("=" * 50)

    initialize_database()

    target = input(
        "\nEnter an authorized network "
        "(example 192.168.1.0/24): "
    ).strip()

    if not target:
        print("[!] No network supplied.")
        return

    try:
        discovery_report = discover_hosts(target)
        assets = parse_discovery_report(
            discovery_report
        )

        print()
        print("=" * 50)
        print("DISCOVERED ASSETS")
        print("=" * 50)

        if not assets:
            print("No active assets discovered.")
            return

        for number, asset in enumerate(
            assets,
            start=1
        ):
            display_asset(
                asset,
                number
            )

        print()
        print("-" * 50)
        print(
            f"Total assets discovered: "
            f"{len(assets)}"
        )

        print()
        print("=" * 50)
        print("SERVICE ANALYSIS")
        print("=" * 50)

        for asset in assets:
            enrich_asset_services(asset)
            display_services(asset)

        print()
        print("=" * 50)
        print("DATABASE STORAGE")
        print("=" * 50)

        observation_ids = {}

        for asset in assets:
            observation_id = (
                save_asset_observation(
                    asset
                )
            )

            observation_ids[
                asset.ip
            ] = observation_id

            print(
                f"[+] Saved {asset.ip} "
                f"as observation "
                f"#{observation_id}"
            )

        print()
        print("=" * 50)
        print("CHANGE DETECTION")
        print("=" * 50)

        for asset in assets:
            try:
                result = compare_observations(
                    asset.ip,
                    current_observation_id=(
                        observation_ids[
                            asset.ip
                        ]
                    ),
                )

                display_changes(result)

            except ValueError as error:
                print()
                print(
                    f"Asset    : "
                    f"{asset.ip}"
                )
                print(
                    f"Details  : "
                    f"{error}"
                )

        print()
        print("=" * 50)
        print("BASELINE ANALYSIS")
        print("=" * 50)

        for asset in assets:
            try:
                result = compare_to_baseline(
                    asset.ip,
                    current_observation_id=(
                        observation_ids[
                            asset.ip
                        ]
                    ),
                )

                display_changes(result)

            except ValueError as error:
                print()
                print(
                    f"Asset    : "
                    f"{asset.ip}"
                )
                print(
                    "Baseline : "
                    "Not configured or "
                    "unavailable."
                )
                print(
                    f"Details  : "
                    f"{error}"
                )

        print()
        print("=" * 50)
        print("DETECTION EVENTS & ALERTS")
        print("=" * 50)

        for asset in assets:
            try:
                result = (
                    generate_detection_events(
                        asset.ip,
                        observation_id=(
                            observation_ids[
                                asset.ip
                            ]
                        ),
                    )
                )

                display_detection_result(
                    result
                )

            except ValueError as error:
                print()
                print(
                    f"Asset     : "
                    f"{asset.ip}"
                )
                print(
                    "Detection : "
                    "Unable to analyze "
                    "against a reference "
                    "baseline."
                )
                print(
                    f"Details   : "
                    f"{error}"
                )

        for asset in assets:
            display_asset_history(
                asset.ip
            )

        print()
        print("=" * 50)
        print("CURRENT ASSET SUMMARY")
        print("=" * 50)

        for number, asset in enumerate(
            assets,
            start=1
        ):
            display_asset(
                asset,
                number
            )

            print(
                f"Open Services: "
                f"{len(asset.services)}"
            )

        print()
        print("=" * 50)
        print("ARGUS ANALYSIS COMPLETE")
        print("=" * 50)

    except (
        ValueError,
        RuntimeError,
    ) as error:
        print(
            f"\n[!] {error}"
        )


if __name__ == "__main__":
    main()