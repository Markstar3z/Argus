from core.scanner import discover_hosts, scan_services
from core.parser import parse_discovery_report


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
    Display the open services discovered for an asset.
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
        print(f"Port       : {service.port}/{service.protocol}")
        print(f"Service    : {name}")
        print(f"Product    : {product}")
        print(f"Version    : {version}")


def main():
    print("=" * 50)
    print("ARGUS")
    print("Defensive Network Intelligence Platform")
    print("=" * 50)

    target = input(
        "\nEnter an authorized network "
        "(example 192.168.1.0/24): "
    ).strip()

    if not target:
        print("[!] No network supplied.")
        return

    try:
        # Phase 1: Asset discovery
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
            display_asset(asset, number)

        print()
        print("-" * 50)
        print(
            f"Total assets discovered: "
            f"{len(assets)}"
        )

        # Phase 2: Service analysis
        print()
        print("=" * 50)
        print("SERVICE ANALYSIS")
        print("=" * 50)

        for asset in assets:
            service_report = scan_services(
                f"{asset.ip}/32"
            )

            service_assets = parse_discovery_report(
                service_report
            )

            if not service_assets:
                print()
                print(
                    f"No service information "
                    f"returned for {asset.ip}."
                )
                continue

            service_asset = service_assets[0]

            display_services(service_asset)

        print()
        print("=" * 50)
        print("ARGUS ANALYSIS COMPLETE")
        print("=" * 50)

    except (ValueError, RuntimeError) as error:
        print(f"\n[!] {error}")


if __name__ == "__main__":
    main()