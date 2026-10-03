from dataclasses import dataclass


@dataclass
class RiskResult:
    score: int
    level: str
    priority: str
    reasons: list[str]


def _clamp_score(score: int) -> int:
    return max(0, min(100, score))


def _risk_level(score: int) -> str:
    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 30:
        return "medium"

    return "low"


def _priority_level(
    score: int,
    occurrence_count: int = 1,
) -> str:
    """
    Convert risk and recurrence into an investigation priority.

    Priority is intentionally separate from risk level.
    """

    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if occurrence_count >= 3:
        return "high"

    if score >= 40:
        return "elevated"

    return "normal"


def calculate_event_risk(
    event_type: str,
    severity: str,
    baseline_deviation: bool = False,
    alert_active: bool = False,
    service_exposed: bool = False,
) -> RiskResult:
    """
    Calculate explainable risk for a detection event.

    Risk is based only on observable ARGUS evidence.
    """

    score = 0
    reasons = []

    event_type = (event_type or "").lower()
    severity = (severity or "").lower()

    # --------------------------------------------------------
    # Event severity
    # --------------------------------------------------------

    severity_scores = {
        "informational": 5,
        "info": 5,
        "low": 15,
        "medium": 30,
        "high": 45,
        "critical": 60,
    }

    severity_score = severity_scores.get(
        severity,
        10,
    )

    score += severity_score

    reasons.append(
        f"Event severity: {severity or 'unknown'}"
    )

    # --------------------------------------------------------
    # Event type
    # --------------------------------------------------------

    if event_type == "service_added":
        score += 15

        reasons.append(
            "A previously unseen service was detected."
        )

    elif event_type == "service_removed":
        score += 5

        reasons.append(
            "A previously observed service disappeared."
        )

    elif event_type == "service_changed":
        score += 20

        reasons.append(
            "An existing service changed state or metadata."
        )

    else:
        score += 10

        reasons.append(
            f"Detection event type: {event_type or 'unknown'}"
        )

    # --------------------------------------------------------
    # Baseline deviation
    # --------------------------------------------------------

    if baseline_deviation:
        score += 15

        reasons.append(
            "The observed state differs from the established baseline."
        )

    # --------------------------------------------------------
    # Active alert
    # --------------------------------------------------------

    if alert_active:
        score += 10

        reasons.append(
            "An active alert is associated with this condition."
        )

    # --------------------------------------------------------
    # Exposed service
    # --------------------------------------------------------

    if service_exposed:
        score += 10

        reasons.append(
            "The detected condition involves an exposed service."
        )

    score = _clamp_score(score)

    return RiskResult(
        score=score,
        level=_risk_level(score),
        priority=_priority_level(score),
        reasons=reasons,
    )


def calculate_alert_risk(
    severity: str,
    event_type: str,
    occurrence_count: int = 1,
    baseline_deviation: bool = False,
    service_exposed: bool = False,
) -> RiskResult:
    """
    Calculate risk for an ARGUS alert.

    Repeated occurrences increase risk gradually
    and can increase investigation priority.
    """

    result = calculate_event_risk(
        event_type=event_type,
        severity=severity,
        baseline_deviation=baseline_deviation,
        alert_active=True,
        service_exposed=service_exposed,
    )

    score = result.score
    reasons = list(result.reasons)

    # --------------------------------------------------------
    # Repeated activity
    # --------------------------------------------------------

    if occurrence_count > 1:
        repetition_bonus = min(
            (occurrence_count - 1) * 5,
            20,
        )

        score += repetition_bonus

        reasons.append(
            f"Condition has occurred {occurrence_count} times."
        )

    score = _clamp_score(score)

    return RiskResult(
        score=score,
        level=_risk_level(score),
        priority=_priority_level(
            score,
            occurrence_count=occurrence_count,
        ),
        reasons=reasons,
    )


def risk_summary(result: RiskResult) -> dict:
    """
    Convert a RiskResult into a dashboard-friendly dictionary.
    """

    return {
        "score": result.score,
        "level": result.level,
        "priority": result.priority,
        "reasons": result.reasons,
    }