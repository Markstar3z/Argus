# ARGUS

## Defensive Network Intelligence Platform

ARGUS is a defensive network intelligence and monitoring platform designed to observe authorized network assets, establish behavioral baselines, detect changes, track alerts, notify the operator, and provide an investigation oriented dashboard.

The project focuses on turning repeated network observations into useful security intelligence rather than treating individual scans as isolated results.

## Core Capabilities

* Authorized network host discovery
* Asset inventory
* Service and port discovery
* Observation history
* Baseline establishment
* Baseline deviation detection
* Service change detection
* Detection event generation
* Alert lifecycle management
* Alert resolution tracking
* Instant alert notifications through Telegram, email, or webhook
* Risk scoring
* Historical observation comparison
* Investigation oriented dashboard

## Detection Lifecycle

ARGUS follows a simple defensive monitoring lifecycle:

```text
Discover
   ↓
Observe
   ↓
Establish Baseline
   ↓
Compare
   ↓
Detect
   ↓
Generate Event
   ↓
Create / Update Alert
   ↓
Notify
   ↓
Track
   ↓
Resolve When Cleared
```

ARGUS does not simply record what exists on a network. It tracks how the observed state changes over time and uses those changes to generate security intelligence.

A detected network change follows this path:

```text
Service Change
      ↓
New Observation
      ↓
Detection
      ↓
Security Event
      ↓
Alert Created  →  Operator Notified
      ↓
Alert Updated While Condition Persists
      ↓
Condition Clears
      ↓
Alert Resolved
```

This allows ARGUS to maintain a history of security relevant changes rather than treating every scan as an isolated event.

## Example Detection

A controlled test can demonstrate the complete detection lifecycle.

Initial state:

```text
Asset: 192.168.29.128
Services: 0
```

A temporary HTTP service is then introduced:

```text
Port: 8080/tcp
Service: HTTP
Product: SimpleHTTPServer
Version: 0.6
```

ARGUS detects the change:

```text
Observation
    ↓
Service Added
    ↓
Baseline Deviation
    ↓
Detection Event
    ↓
Alert Created
    ↓
Notification Sent
```

When the temporary service is removed:

```text
Service Removed
       ↓
New Observation
       ↓
Condition Cleared
       ↓
Alert Resolved
```

This demonstrates ARGUS's ability to track both the appearance and disappearance of a network condition.

## Alert Notifications

ARGUS pushes new alerts to you, so you do not have to sit at the terminal or keep the dashboard open.

Supported channels:

* Telegram
* Email (SMTP)
* Webhook (Discord bridges, Slack bridges, n8n, and similar tools)

How it behaves:

* A notification is sent once, when an alert is first created.
* If the same condition persists across later scans, no repeat notifications are sent.
* If a notification fails, the scan carries on. Notifications never break detection.
* If no channel is configured, nothing is sent and ARGUS works as before.
* The dashboard top bar shows whether notifications are on.

### Setup

Copy the example file and fill in only the channels you want:

```bash
cp .env.example .env
```

Telegram (recommended, no password needed):

1. Message @BotFather on Telegram and create a bot to get a token.
2. Send any message to your new bot, then find your chat ID.
3. Add both to `.env`:

```text
ARGUS_TELEGRAM_TOKEN=your_bot_token
ARGUS_TELEGRAM_CHAT_ID=your_chat_id
```

Email (optional):

```text
ARGUS_SMTP_HOST=smtp.gmail.com
ARGUS_SMTP_PORT=587
ARGUS_SMTP_USER=you@gmail.com
ARGUS_SMTP_PASSWORD=your_app_password
ARGUS_EMAIL_TO=you@gmail.com
```

For Gmail, use an app password, never your real account password. App passwords need 2 step verification turned on.

Webhook (optional):

```text
ARGUS_WEBHOOK_URL=https://your-webhook-url
```

Other settings:

```text
ARGUS_NOTIFY_MIN_SEVERITY=informational
ARGUS_DASHBOARD_URL=http://127.0.0.1:5000
```

`ARGUS_NOTIFY_MIN_SEVERITY` can be informational, low, medium, high, or critical. Only alerts at or above this level are sent. The default is informational, so every new alert notifies you.

`ARGUS_DASHBOARD_URL` is the address used for the alert link inside each message.

### Test it

```bash
python -m core.notifier
```

This sends a test message to every configured channel and prints whether each one worked.

### Keep your secrets safe

The `.env` file holds your tokens and passwords. It is already listed in `.gitignore`, so it should never be committed. Only `.env.example` belongs in the repository.

## Risk Assessment

ARGUS includes a lightweight risk scoring system.

Risk calculations can consider:

* Event severity
* Event type
* Baseline deviation
* Alert state
* Service exposure
* Repeated occurrences

Each risk result contains a score, a level, and the reasons behind it.

Risk scoring is intended to support investigation and prioritization. It is not intended to replace human analysis.

## Dashboard

ARGUS includes a Flask based investigation dashboard with a dark, minimal interface. Alerts and events carry a colored edge that reflects their severity, and a notification indicator in the top bar shows whether alerts are being pushed to you.

The dashboard provides visibility into:

* Network assets
* Current asset state
* Observation history
* Baselines
* Detection events
* Active alerts
* Alert details
* Observation comparisons
* Risk information

Start the dashboard with:

```bash
cd ~/argus
python dashboard/app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Project Structure

```text
argus/
│
├── core/
│   ├── alerts.py
│   ├── baseline.py
│   ├── database.py
│   ├── detection.py
│   ├── history.py
│   ├── models.py
│   ├── notifier.py
│   ├── parser.py
│   ├── risk.py
│   ├── scanner.py
│   └── main.py
│
├── dashboard/
│   ├── app.py
│   ├── data.py
│   │
│   ├── templates/
│   │   ├── base.html
│   │   ├── dashboard.html
│   │   ├── asset.html
│   │   ├── observation.html
│   │   ├── alert.html
│   │   └── compare.html
│   │
│   └── static/
│       └── css/
│           ├── style.css
│           └── theme.css
│
├── main.py
├── .env.example
├── README.md
└── .gitignore
```

## Core Components

**Scanner**
Responsible for network discovery and service scanning.

**Parser**
Processes scanner output into structured network information.

**Database**
Stores assets, observations, services, baselines, events, and alerts using SQLite.

**Baseline Engine**
Establishes a reference state and compares new observations against it.

**Detection Engine**
Identifies changes between observations and baseline states.

**Alert System**
Creates, updates, and resolves alerts based on detected conditions.

**Notifier**
Pushes newly created alerts to Telegram, email, or a webhook. It uses only the Python standard library.

**Risk Engine**
Calculates contextual risk scores for detection events and alerts.

**History**
Maintains the historical record of observations for each asset.

**Dashboard**
Provides the investigation and visualization layer through Flask. Styling lives in `style.css`, with the visual theme layered on top in `theme.css`.

## Database Model

ARGUS currently uses SQLite for persistent monitoring data.

The main entities are:

**Assets**
Represents discovered network hosts.

**Observations**
Represents the state of an asset at a specific point in time.

**Services**
Represents services discovered during an observation.

**Baselines**
Defines the established reference state for an asset.

**Events**
Represents changes detected between network states.

**Alerts**
Tracks detected conditions through their lifecycle.

## Alert Lifecycle

ARGUS maintains persistent alert state.

```text
Detection
    ↓
New Event
    ↓
Create Alert  →  Notify Operator
    ↓
Active
    ↓
Condition Continues
    ↓
Update Occurrence
    ↓
Condition Clears
    ↓
Resolved
```

This means an alert is not simply created and forgotten.

ARGUS tracks:

* First observation
* Latest observation
* Occurrence count
* First seen time
* Last seen time
* Resolution time
* Current status

## Observation History

Every scan produces an observation associated with an asset.

An observation can contain:

* Asset state
* Observation timestamp
* Service information
* Detection events
* Baseline relationship

This creates a historical record that can be used to investigate changes over time.

## Baseline Monitoring

ARGUS can establish a reference observation for an asset. Future observations can then be compared against that baseline.

The comparison identifies:

* Added services
* Removed services
* Changed services

For example:

```text
Baseline
    ↓
0 services

Current Observation
    ↓
1 service

Difference
    ↓
1 service added
```

A baseline deviation is a signal for investigation, not automatic proof of malicious activity.

## Observation Comparison

ARGUS can compare two specific observations.

```text
Observation #5
      ↓
Observation #14
```

The comparison can identify:

* Added services
* Removed services
* Changed service metadata

This makes it possible to investigate exactly what changed between two points in time.

## Technology Stack

ARGUS is currently built with:

* Python
* SQLite
* Flask
* HTML
* CSS
* Network scanning and parsing components

## Running ARGUS

1. Clone or enter the project

```bash
cd ~/argus
```

2. Optional: set up notifications (see Alert Notifications above)

```bash
cp .env.example .env
```

3. Run the main analysis pipeline

```bash
python main.py
```

4. Start the dashboard

```bash
python dashboard/app.py
```

5. Open the dashboard

```text
http://127.0.0.1:5000
```

## Development Checks

Before committing changes, Python files can be checked with:

```bash
python -m py_compile \
    dashboard/app.py \
    dashboard/data.py \
    core/alerts.py \
    core/notifier.py \
    core/risk.py
```

A successful compilation produces no output.

## Defensive Scope

ARGUS is designed for:

* Authorized network monitoring
* Defensive security research
* Network visibility
* Security learning
* Controlled laboratory environments

Only scan or monitor systems and networks for which you have explicit authorization.

## Current Project Status

ARGUS currently has a functioning:

* Network discovery pipeline
* Asset inventory
* Observation system
* Service tracking
* Baseline system
* Baseline comparison
* Change detection
* Detection event system
* Alert lifecycle management
* Alert resolution
* Alert notifications (Telegram, email, webhook)
* Risk assessment
* Observation comparison
* Flask investigation dashboard

The frontend can continue to be refined independently without changing the underlying detection architecture.

## Roadmap

Future improvements may include:

* Improved dashboard visualizations
* Better observation timeline presentation
* More advanced risk analysis
* Expanded detection rules
* Additional network intelligence
* Authentication and access control
* Scheduled automated monitoring
* Notification rules per asset or per event type
* Reporting and export capabilities
* Improved investigation workflows

## Project Philosophy

ARGUS is built around a simple idea:

A network is not just a collection of machines. It is a changing system.

Understanding those changes over time makes it possible to build better visibility, better detection, and better investigations.

## License

This project is currently under active development.

License information will be added as the project matures.
