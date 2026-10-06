from fastapi import FastAPI
from database import get_db_connection

app = FastAPI(
    title="Cybersecurity Threat Intelligence Platform",
    description="Threat Intelligence and Risk Analysis API",
    version="1.0.0"
)


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
def get_threats():

    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    cursor.execute("SELECT * FROM threat_indicators")

    threats = cursor.fetchall()

    cursor.close()
    connection.close()

    return {
        "count": len(threats),
        "threats": threats
    }