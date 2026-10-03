import xml.etree.ElementTree as ET
from pathlib import Path

from core.models import Asset, Service


def get_host_status(host):
    """
    Extract the status of an Nmap host.
    """
    status_element = host.find("status")

    if status_element is not None:
        return status_element.get("state", "unknown")

    return "unknown"


def get_host_addresses(host):
    """
    Extract IPv4 and MAC addresses from an Nmap host.
    """
    ip_address = None
    mac_address = None

    for address in host.findall("address"):
        address_type = address.get("addrtype")

        if address_type == "ipv4":
            ip_address = address.get("addr")

        elif address_type == "mac":
            mac_address = address.get("addr")

    return ip_address, mac_address


def get_hostname(host):
    """
    Extract the first hostname discovered by Nmap.
    """
    hostname_element = host.find("hostnames/hostname")

    if hostname_element is not None:
        return hostname_element.get("name")

    return None


def get_services(host):
    """
    Extract open network services from an Nmap host.
    """
    services = []

    for port_element in host.findall("ports/port"):

        state_element = port_element.find("state")

        if state_element is None:
            continue

        port_state = state_element.get("state")

        if port_state != "open":
            continue

        port_number = int(
            port_element.get("portid")
        )

        protocol = port_element.get(
            "protocol",
            "unknown"
        )

        service_element = port_element.find("service")

        name = None
        product = None
        version = None

        if service_element is not None:
            name = service_element.get("name")
            product = service_element.get("product")
            version = service_element.get("version")

        service = Service(
            port=port_number,
            protocol=protocol,
            name=name,
            product=product,
            version=version,
        )

        services.append(service)

    return services


def parse_discovery_report(report_path: Path):
    """
    Parse an Nmap XML report and return Asset objects.
    """

    tree = ET.parse(report_path)
    root = tree.getroot()

    assets = []

    for host in root.findall("host"):

        status = get_host_status(host)

        ip_address, mac_address = (
            get_host_addresses(host)
        )

        hostname = get_hostname(host)

        services = get_services(host)

        if ip_address:
            asset = Asset(
                ip=ip_address,
                status=status,
                mac=mac_address,
                hostname=hostname,
                services=services,
            )

            assets.append(asset)

    return assets
