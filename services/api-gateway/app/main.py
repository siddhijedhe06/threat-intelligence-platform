from fastapi import FastAPI

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