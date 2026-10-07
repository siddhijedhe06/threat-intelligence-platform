from fastapi import FastAPI
from pydantic import BaseModel

from database import get_db_connection


app = FastAPI(
    title="Threat Alert Service",
    description="Threat alert generation service",
    version="1.0.0"
)


class AlertRequest(BaseModel):
    threat_id: int
    risk_score: int
    severity: str
    category: str


@app.get("/")
def root():
    return {
        "message": "Threat Alert Service is running"
    }


@app.post("/alerts")
def create_alert(request: AlertRequest):

    # Only create an alert for high-risk threats
    if request.risk_score < 80:
        return {
            "message": "No alert required",
            "risk_score": request.risk_score
        }

    connection = get_db_connection()
    cursor = connection.cursor()

    alert_type = "High Risk Threat"

    message = (
        f"Critical threat detected. "
        f"Category: {request.category}, "
        f"Risk Score: {request.risk_score}"
    )

    sql = """
        INSERT INTO alerts
        (
            threat_id,
            alert_type,
            message,
            severity,
            status
        )
        VALUES (%s, %s, %s, %s, %s)
    """

    values = (
        request.threat_id,
        alert_type,
        message,
        request.severity,
        "Open"
    )

    cursor.execute(sql, values)
    connection.commit()

    alert_id = cursor.lastrowid

    cursor.close()
    connection.close()

    return {
        "message": "Alert created successfully",
        "alert_id": alert_id,
        "threat_id": request.threat_id,
        "severity": request.severity,
        "risk_score": request.risk_score
    }