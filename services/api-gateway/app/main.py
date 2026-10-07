from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import httpx

from database import get_db_connection
from auth import (
    verify_password,
    create_access_token,
    get_current_user,
    require_role
)

app = FastAPI(
    title="Cybersecurity Threat Intelligence Platform",
    description="Threat Intelligence and Risk Analysis API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class Threat(BaseModel):
    indicator: str
    indicator_type: str
    source: str | None = None
    description: str | None = None

    # Optional risk scoring factors
    source_score: int = 15
    severity_score: int = 15
    frequency_score: int = 10
    recency_score: int = 10
    corroboration_score: int = 5

class LoginRequest(BaseModel):
    username: str
    password: str

@app.get("/")
def root():
    return {
        "message": "Cybersecurity Threat Intelligence Platform API is running"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy"
    }


@app.get("/threats")
def get_threats(current_user: dict = Depends(get_current_user)):

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT
            ti.id,
            ti.indicator,
            ti.indicator_type,
            ti.source,
            ti.description,
            ti.first_seen,
            ti.last_seen,
            ti.status,
            ti.created_at,
            ta.category,
            ta.risk_score,
            ta.severity
        FROM threat_indicators ti
        LEFT JOIN threat_analysis ta
            ON ti.id = ta.threat_id
        ORDER BY ti.created_at DESC
    """

    cursor.execute(query)

    threats = cursor.fetchall()

    cursor.close()
    connection.close()

    return {
        "count": len(threats),
        "threats": threats
    }

@app.get("/threats/critical")
def get_critical_threats(
    current_user: dict = Depends(get_current_user)
):

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT
            ti.id,
            ti.indicator,
            ti.indicator_type,
            ti.source,
            ti.description,
            ta.category,
            ta.risk_score,
            ta.severity,
            ti.created_at
        FROM threat_indicators ti
        INNER JOIN threat_analysis ta
            ON ti.id = ta.threat_id
        WHERE ta.risk_score >= 80
        ORDER BY ta.risk_score DESC
    """

    cursor.execute(query)

    threats = cursor.fetchall()

    cursor.close()
    connection.close()

    return {
        "count": len(threats),
        "critical_threats": threats
    }

@app.get("/threats/{threat_id}")
def get_threat(
    threat_id: int,
    current_user: dict = Depends(get_current_user)
):

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT
            ti.id,
            ti.indicator,
            ti.indicator_type,
            ti.source,
            ti.description,
            ti.first_seen,
            ti.last_seen,
            ti.status,
            ti.created_at,
            ta.category,
            ta.risk_score,
            ta.severity,
            ta.source_score,
            ta.severity_score,
            ta.frequency_score,
            ta.recency_score,
            ta.corroboration_score,
            ta.analysis_details
        FROM threat_indicators ti
        LEFT JOIN threat_analysis ta
            ON ti.id = ta.threat_id
        WHERE ti.id = %s
    """

    cursor.execute(query, (threat_id,))

    threat = cursor.fetchone()

    cursor.close()
    connection.close()

    if threat is None:
        return {
            "message": "Threat not found"
        }

    return threat



@app.get("/statistics")
def get_statistics(
    current_user: dict = Depends(get_current_user)
):

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("""
        SELECT COUNT(*) AS total_threats
        FROM threat_indicators
    """)

    total_threats = cursor.fetchone()["total_threats"]

    cursor.execute("""
        SELECT COUNT(*) AS critical_threats
        FROM threat_analysis
        WHERE risk_score >= 80
    """)

    critical_threats = cursor.fetchone()["critical_threats"]

    cursor.execute("""
        SELECT COUNT(*) AS high_threats
        FROM threat_analysis
        WHERE risk_score BETWEEN 61 AND 80
    """)

    high_threats = cursor.fetchone()["high_threats"]

    cursor.execute("""
        SELECT COUNT(*) AS medium_threats
        FROM threat_analysis
        WHERE risk_score BETWEEN 31 AND 60
    """)

    medium_threats = cursor.fetchone()["medium_threats"]

    cursor.execute("""
        SELECT COUNT(*) AS low_threats
        FROM threat_analysis
        WHERE risk_score <= 30
    """)

    low_threats = cursor.fetchone()["low_threats"]

    cursor.execute("""
        SELECT COUNT(*) AS open_alerts
        FROM alerts
        WHERE status = 'Open'
    """)

    open_alerts = cursor.fetchone()["open_alerts"]

    cursor.close()
    connection.close()

    return {
        "total_threats": total_threats,
        "critical_threats": critical_threats,
        "high_threats": high_threats,
        "medium_threats": medium_threats,
        "low_threats": low_threats,
        "open_alerts": open_alerts
    }

@app.get("/alerts")
def get_alerts(current_user: dict = Depends(get_current_user)):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = """
        SELECT
            a.id,
            a.threat_id,
            a.alert_type,
            a.message,
            a.severity,
            a.status,
            a.created_at,
            a.acknowledged_at,
            a.resolved_at,
            ti.indicator,
            ti.indicator_type,
            ta.category,
            ta.risk_score
        FROM alerts a
        INNER JOIN threat_indicators ti
            ON a.threat_id = ti.id
        LEFT JOIN threat_analysis ta
            ON a.threat_id = ta.threat_id
        ORDER BY a.created_at DESC
    """

    cursor.execute(query)
    alerts = cursor.fetchall()

    cursor.close()
    connection.close()

    return {
        "count": len(alerts),
        "alerts": alerts
    }

@app.put("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    current_user: dict = Depends(
        require_role(["Admin", "Analyst"])
    )
):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM alerts
        WHERE id = %s
        """,
        (alert_id,)
    )

    alert = cursor.fetchone()

    if alert is None:
        cursor.close()
        connection.close()
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    cursor.execute(
        """
        UPDATE alerts
        SET status = 'Acknowledged',
            acknowledged_at = NOW()
        WHERE id = %s
        """,
        (alert_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return {
        "message": "Alert acknowledged successfully",
        "alert_id": alert_id,
        "status": "Acknowledged"
    }

@app.put("/alerts/{alert_id}/resolve")
def resolve_alert(
    alert_id: int,
    current_user: dict = Depends(
        require_role(["Admin", "Analyst"])
    )
):
    connection = get_db_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id
        FROM alerts
        WHERE id = %s
        """,
        (alert_id,)
    )

    alert = cursor.fetchone()

    if alert is None:
        cursor.close()
        connection.close()
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    cursor.execute(
        """
        UPDATE alerts
        SET status = 'Resolved',
            resolved_at = NOW()
        WHERE id = %s
        """,
        (alert_id,)
    )

    connection.commit()

    cursor.close()
    connection.close()

    return {
        "message": "Alert resolved successfully",
        "alert_id": alert_id,
        "status": "Resolved"
    }

@app.post("/threats")
def create_threat(
    threat: Threat,
    current_user: dict = Depends(
        require_role(["Admin", "Analyst"])
    )
):

    # ------------------------------------------------
    # STEP 1: Save threat into MySQL
    # ------------------------------------------------

    connection = get_db_connection()

    cursor = connection.cursor()

    sql = """
        INSERT INTO threat_indicators
        (indicator, indicator_type, source, description)
        VALUES (%s, %s, %s, %s)
    """

    values = (
        threat.indicator,
        threat.indicator_type,
        threat.source,
        threat.description
    )

    cursor.execute(sql, values)

    connection.commit()

    threat_id = cursor.lastrowid

    cursor.close()
    connection.close()


    # ------------------------------------------------
    # STEP 2: Send threat to Analysis Service
    # ------------------------------------------------

    analysis_status = "Analysis service not contacted"
    analysis_result = None

    try:

        response = httpx.post(
            f"http://analysis-service:8001/analyze/{threat_id}",
            json={
                "threat_id": threat_id,
                "source_score": threat.source_score,
                "severity_score": threat.severity_score,
                "frequency_score": threat.frequency_score,
                "recency_score": threat.recency_score,
                "corroboration_score": threat.corroboration_score
            },
            timeout=10.0
        )

        if response.status_code == 200:

            analysis_status = "Analysis completed"

            analysis_result = response.json()

        else:

            analysis_status = "Analysis service returned an error"

    except Exception as e:

        analysis_status = f"Analysis service unavailable: {str(e)}"


    # ------------------------------------------------
    # STEP 3: Return complete result
    # ------------------------------------------------

    return {
        "message": "Threat added successfully",
        "threat_id": threat_id,
        "analysis_status": analysis_status,
        "analysis": analysis_result
    }

@app.post("/login")
def login(request: LoginRequest):

    connection = get_db_connection()

    cursor = connection.cursor(dictionary=True)

    cursor.execute(
        """
        SELECT id, username, password_hash, role
        FROM users
        WHERE username = %s
        """,
        (request.username,)
    )

    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if user is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if not verify_password(
        request.password,
        user["password_hash"]
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    token = create_access_token({
        "user_id": user["id"],
        "username": user["username"],
        "role": user["role"]
    })

    return {
        "message": "Login successful",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "username": user["username"],
            "role": user["role"]
        }
    }