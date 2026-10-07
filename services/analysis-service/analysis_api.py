import httpx

from fastapi import FastAPI
from pydantic import BaseModel

from analysis import (
    calculate_risk_score,
    get_severity,
    classify_threat
)

from database import get_db_connection


app = FastAPI(
    title="Threat Analysis Service",
    description="Threat classification and risk scoring service",
    version="1.0.0"
)


class AnalysisRequest(BaseModel):
    threat_id: int
    source_score: int
    severity_score: int
    frequency_score: int
    recency_score: int
    corroboration_score: int


@app.get("/")
def root():
    return {
        "message": "Threat Analysis Service is running"
    }


@app.post("/analyze/{threat_id}")
def analyze_threat(threat_id: int, request: AnalysisRequest):

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    # Get threat information
    cursor.execute(
        "SELECT * FROM threat_indicators WHERE id = %s",
        (threat_id,)
    )

    threat = cursor.fetchone()

    if threat is None:
        cursor.close()
        connection.close()

        return {
            "error": "Threat not found"
        }

    # Classify threat
    category = classify_threat(
        threat["indicator"],
        threat["description"] or ""
    )

    # Calculate risk score
    risk_score = calculate_risk_score(
        request.source_score,
        request.severity_score,
        request.frequency_score,
        request.recency_score,
        request.corroboration_score
    )

    # Determine severity
    severity = get_severity(risk_score)

    # Save analysis result
    insert_query = """
        INSERT INTO threat_analysis
        (
            threat_id,
            category,
            risk_score,
            severity,
            source_score,
            severity_score,
            frequency_score,
            recency_score,
            corroboration_score,
            analysis_details
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    values = (
        threat_id,
        category,
        risk_score,
        severity,
        request.source_score,
        request.severity_score,
        request.frequency_score,
        request.recency_score,
        request.corroboration_score,
        "Threat analyzed using rule-based classification and risk scoring."
    )

    cursor.execute(insert_query, values)
    connection.commit()

    analysis_id = cursor.lastrowid

    cursor.close()
    connection.close()

    alert_status = "No alert required"

    if risk_score >= 80:

        try:

            alert_response = httpx.post(
                "http://alert-service:8002/alerts",
                json={
                    "threat_id": threat_id,
                    "risk_score": risk_score,
                    "severity": severity,
                    "category": category
                }
            )

            if alert_response.status_code == 200:
                alert_status = "Alert service notified"

            else:
                alert_status = "Alert service returned an error"

        except Exception as e:

            alert_status = f"Alert service unavailable: {str(e)}"


    return {
        "message": "Threat analyzed successfully",
        "analysis_id": analysis_id,
        "threat_id": threat_id,
        "category": category,
        "risk_score": risk_score,
        "severity": severity,
        "alert_status": alert_status
    }