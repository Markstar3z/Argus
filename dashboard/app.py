from datetime import datetime

from flask import (
    Flask,
    render_template,
    abort,
    request,
    redirect,
    url_for,
)

from core.database import get_connection
from core.history import get_asset_history
from core.baseline import compare_to_baseline, compare_observations
from core.notifier import configured_channels
from core.alerts import (
    start_investigation,
    resolve_investigation,
    reopen_investigation,
)
from dashboard.data import (
    get_asset_inventory,
    get_asset_by_id,
    get_asset_state_comparison,
    get_observation_detail,
    get_recent_events,
    get_active_alerts,
    get_alert_detail,
)


app = Flask(__name__)


@app.context_processor
def inject_notification_state():
    return {"notify_channels": configured_channels()}


@app.template_filter("date_only")
def format_date(value):
    if not value:
        return "Unknown"

    try:
        parsed = datetime.fromisoformat(str(value))
        return parsed.strftime("%d %b %Y")
    except (ValueError, TypeError):
        return str(value)


@app.template_filter("time_only")
def format_time(value):
    if not value:
        return ""

    try:
        parsed = datetime.fromisoformat(str(value))
        return parsed.strftime("%H:%M:%S")
    except (ValueError, TypeError):
        return ""


def get_dashboard_summary():
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("SELECT COUNT(*) FROM assets")
        total_assets = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM observations")
        total_observations = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM services")
        total_service_records = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(*) FROM baselines")
        total_baselines = cursor.fetchone()[0]

        return {
            "assets": total_assets,
            "observations": total_observations,
            "services": total_service_records,
            "baselines": total_baselines,
        }

    finally:
        connection.close()


def get_first_asset_id():
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id
            FROM assets
            ORDER BY id ASC
            LIMIT 1
            """
        )

        row = cursor.fetchone()

        if row is None:
            return None

        return row[0]

    finally:
        connection.close()


@app.route("/")
def dashboard():
    summary = get_dashboard_summary()

    assets = get_asset_inventory()

    investigation_queue = get_recent_events(limit=10)

    active_alerts = get_active_alerts(limit=10)

    return render_template(
        "dashboard.html",
        summary=summary,
        assets=assets,
        recent_events=investigation_queue,
        investigation_queue=investigation_queue,
        active_alerts=active_alerts,
    )


@app.route(
    "/event/<int:event_id>/investigate",
    methods=["POST"],
)
def investigate_event(event_id):
    """
    Control the investigation lifecycle for a detection event.

    Supported actions:
        start
        resolve
        reopen
    """
    action = request.form.get(
        "action",
        "start",
    ).strip().lower()

    try:
        if action == "start":
            start_investigation(event_id)

        elif action == "resolve":
            resolve_investigation(event_id)

        elif action == "reopen":
            reopen_investigation(event_id)

        else:
            abort(400)

    except ValueError:
        abort(404)

    return redirect(
        url_for("dashboard") + "#priority"
    )


@app.route("/observations")
def observations():
    asset_id = get_first_asset_id()

    if asset_id is None:
        return redirect(url_for("dashboard"))

    return redirect(
        url_for("asset_detail", asset_id=asset_id) + "#observations"
    )


@app.route("/baselines")
def baselines():
    asset_id = get_first_asset_id()

    if asset_id is None:
        return redirect(url_for("dashboard"))

    return redirect(
        url_for("asset_detail", asset_id=asset_id) + "#baseline"
    )


@app.route("/comparisons")
def comparisons():
    asset_id = get_first_asset_id()

    if asset_id is None:
        return redirect(url_for("dashboard"))

    return redirect(
        url_for("asset_detail", asset_id=asset_id) + "#comparison"
    )


@app.route("/asset/<int:asset_id>")
def asset_detail(asset_id):
    asset = get_asset_by_id(asset_id)

    if asset is None:
        abort(404)

    history = get_asset_history(asset["ip"])
    state = get_asset_state_comparison(asset_id)

    baseline_result = None
    baseline_error = None

    try:
        baseline_result = compare_to_baseline(asset["ip"])
    except ValueError as error:
        baseline_error = str(error)

    return render_template(
        "asset.html",
        asset=asset,
        history=history,
        state=state,
        baseline_result=baseline_result,
        baseline_error=baseline_error,
    )


@app.route(
    "/asset/<int:asset_id>/observation/<int:observation_id>"
)
def observation_detail(asset_id, observation_id):
    asset = get_asset_by_id(asset_id)

    if asset is None:
        abort(404)

    observation = get_observation_detail(
        asset_id,
        observation_id,
    )

    if observation is None:
        abort(404)

    state = get_asset_state_comparison(asset_id)

    return render_template(
        "observation.html",
        asset=asset,
        observation=observation,
        state=state,
    )


@app.route("/alert/<int:alert_id>")
def alert_detail(alert_id):
    alert = get_alert_detail(alert_id)

    if alert is None:
        abort(404)

    asset = get_asset_by_id(alert["asset_id"])

    if asset is None:
        abort(404)

    return render_template(
        "alert.html",
        alert=alert,
        asset=asset,
    )


@app.route("/asset/<int:asset_id>/compare")
def observation_compare(asset_id):
    asset = get_asset_by_id(asset_id)

    if asset is None:
        abort(404)

    try:
        from_id = int(request.args["from"])
        to_id = int(request.args["to"])
    except (KeyError, ValueError):
        abort(400)

    from_observation = get_observation_detail(
        asset_id,
        from_id,
    )

    to_observation = get_observation_detail(
        asset_id,
        to_id,
    )

    if from_observation is None or to_observation is None:
        abort(404)

    try:
        result = compare_observations(
            ip_address=asset["ip"],
            previous_observation_id=from_id,
            current_observation_id=to_id,
        )
    except ValueError:
        abort(400)

    return render_template(
        "compare.html",
        asset=asset,
        from_observation=from_observation,
        to_observation=to_observation,
        result=result,
    )


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True,
    )
