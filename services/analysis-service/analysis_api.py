import os
import httpx

from fastapi import FastAPI
from pydantic import BaseModel

from analysis import (
    calculate_risk_score,
    get_severity,
    classify_threat,
    analyze_threat_indicator
)

from database import get_db_connection


app = FastAPI(
    title="Threat Analysis Service",
    description="Threat classification and risk scoring service",
    version="1.0.0"
)


class AnalysisRequest(BaseModel):
    threat_id: int
    source_score: int | None = 15
    severity_score: int | None = 15
    frequency_score: int | None = 10
    recency_score: int | None = 10
    corroboration_score: int | None = 5


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

    # Check if request has customized non-default scores
    is_default_scores = (
        request.source_score == 15
        and request.severity_score == 15
        and request.frequency_score == 10
        and request.recency_score == 10
        and request.corroboration_score == 5
    )

    override_scores = None if is_default_scores else {
        "source_score": request.source_score,
        "severity_score": request.severity_score,
        "frequency_score": request.frequency_score,
        "recency_score": request.recency_score,
        "corroboration_score": request.corroboration_score
    }

    # Execute deep intelligence analysis
    analysis_res = analyze_threat_indicator(
        indicator=threat["indicator"],
        indicator_type=threat.get("indicator_type", ""),
        source=threat.get("source", ""),
        description=threat.get("description", "") or "",
        override_scores=override_scores
    )

    category = analysis_res["category"]
    risk_score = analysis_res["risk_score"]
    severity = analysis_res["severity"]
    source_score = analysis_res["source_score"]
    severity_score = analysis_res["severity_score"]
    frequency_score = analysis_res["frequency_score"]
    recency_score = analysis_res["recency_score"]
    corroboration_score = analysis_res["corroboration_score"]
    analysis_details = analysis_res["analysis_details"]

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
        source_score,
        severity_score,
        frequency_score,
        recency_score,
        corroboration_score,
        analysis_details
    )

    cursor.execute(insert_query, values)
    connection.commit()

    analysis_id = cursor.lastrowid

    cursor.close()
    connection.close()

    alert_status = "No alert required"

    if risk_score >= 80:

        try:

            alert_service_url = os.getenv(
                "ALERT_SERVICE_URL",
                "http://127.0.0.1:8002"
            )
                
            alert_response = httpx.post(
            f"{alert_service_url}/alerts",
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
        "source_score": source_score,
        "severity_score": severity_score,
        "frequency_score": frequency_score,
        "recency_score": recency_score,
        "corroboration_score": corroboration_score,
        "analysis_details": analysis_details,
        "alert_status": alert_status
    }