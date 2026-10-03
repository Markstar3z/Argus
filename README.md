# ARGUS: Network Intelligence and Policy Drift Detection System

ARGUS is an automated network security auditing platform built to establish trusted baseline profiles across subnets, detect unauthorized assets, and monitor policy drift. By contrasting real time scans against verified reference snapshots, the platform enables security teams to identify rogue devices, anomalous port states, and service modifications before they become attack vectors.

## System Architecture

The inspection pipeline operates through five coordinated stages:

* Subnet Sweeping: Active host discovery and port enumeration across target CIDR blocks.
* Telemetry Parsing: Structured normalization of raw scan outputs into strongly typed schema definitions.
* Baseline Profiling: Cryptographic and stateful recording of authorized assets, service banners, and port configurations.
* Drift Detection: Differential auditing that contrasts active scan observations with the baseline to flag unauthorized delta events.
* Risk Quantification: Algorithmic severity assessment calculating cumulative risk based on protocol criticality, exposure depth, and baseline divergence.

## Core Module Structure

* core/scanner.py: Orchestrates active target sweeping and port discovery.
* core/parser.py: Parses and extracts network telemetry from scan outputs into standardized models.
* core/baseline.py: Establishes, persists, and validates known good network state profiles.
* core/detection.py: Implements differential anomaly detection logic to catch state drift.
* core/risk.py: Computes asset and event risk weights based on service exposure severity.
* core/alerts.py: Formulates and routes alert telemetry when anomalies violate policy thresholds.
* core/history.py: Manages temporal audit logs to preserve historical posture changes over time.
* core/models.py and core/database.py: Defines SQLite schema structures and manages persistence.
* dashboard/app.py: Serves the analyst web interface built with Flask and Jinja templates.
* dashboard/templates/: Visual consoles for posture overview, drift alerts, asset profiles, and comparative audits.

## Technology Stack

* Core Language: Python 3
* Web Framework: Flask
* Templating Engine: Jinja2
* Persistence: SQLite
* Telemetry Ingestion: XML scan records
* User Interface: Custom HTML5 and CSS3

## Installation

Clone the repository to your local workstation:

git clone https://github.com/Markstar3z/argus.git
cd argus

Install application dependencies:

pip install flask

## Execution

Initialize the detection engine:

python main.py

Start the analyst management dashboard:

python dashboard/app.py

Access the monitoring portal at http://127.0.0.1:5000 in any web browser.

## Security and Defense Verification

1. Establishing the Baseline: Run an authorized scan across your subnet. ARGUS records the approved inventory of IPs, open ports, and validated service signatures.
2. Introducing Policy Drift: Simulate an internal anomaly by opening an unauthorized port or connecting an unmapped device.
3. Automated Alerting: ARGUS flags the anomaly, recalculates the asset risk score, and surfaces the event inside the analyst dashboard with historical differential analysis.