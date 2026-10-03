import subprocess
from datetime import datetime
from pathlib import Path
import ipaddress


REPORT_DIR = Path("reports")


def validate_target(target: str) -> str:
    """
    Validate that the supplied target is a valid
    IPv4 or IPv6 host/network.
    """
    try:
        network = ipaddress.ip_network(target, strict=False)
        return str(network)

    except ValueError as exc:
        raise ValueError(
            f"Invalid network target: {target}"
        ) from exc


def discover_hosts(target: str) -> Path:
    """
    Run Nmap host discovery and save the result as XML.
    No port scanning is performed.
    """
    target = validate_target(target)

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output_file = (
        REPORT_DIR /
        f"discovery_{timestamp}.xml"
    )

    command = [
        "nmap",
        "-sn",
        "-oX",
        str(output_file),
        target,
    ]

    print()
    print(f"[ARGUS] Target: {target}")
    print("[ARGUS] Starting asset discovery...")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap discovery failed:\n{result.stderr}"
        )

    print("[ARGUS] Discovery complete.")
    print(f"[ARGUS] Report: {output_file}")

    return output_file


def scan_services(target: str) -> Path:
    """
    Scan common TCP ports on an authorized target
    and attempt to identify running services.
    """
    target = validate_target(target)

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    output_file = (
        REPORT_DIR /
        f"services_{timestamp}.xml"
    )

    command = [
        "nmap",
        "-sT",
        "-sV",
        "--top-ports",
        "100",
        "-oX",
        str(output_file),
        target,
    ]

    print()
    print(f"[ARGUS] Service target: {target}")
    print("[ARGUS] Starting service analysis...")

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Nmap service scan failed:\n{result.stderr}"
        )

    print("[ARGUS] Service analysis complete.")
    print(f"[ARGUS] Report: {output_file}")

    return output_file