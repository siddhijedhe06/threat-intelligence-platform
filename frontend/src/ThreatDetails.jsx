import { useEffect, useState } from "react";
import "./ThreatDetails.css";

function ThreatDetails({ threatId, onBack, onLogout }) {
  const [threat, setThreat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    fetchThreat();
  }, [threatId]);

  async function fetchThreat() {
    const token = sessionStorage.getItem("access_token");

    try {
      const response = await fetch(
        `http://127.0.0.1:8000/threats/${threatId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      const data = await response.json();

      if (!response.ok) {
        setError(data.detail || "Failed to load threat.");
        return;
      }

      setThreat(data);
    } catch {
      setError("Cannot connect to the API.");
    } finally {
      setLoading(false);
    }
  }

  if (loading) {
    return (
      <div className="threat-details-page">
        <div className="details-message">
          Loading threat details...
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="threat-details-page">
        <div className="details-error">{error}</div>
        <button onClick={onBack}>← Back</button>
      </div>
    );
  }

  if (!threat) {
    return null;
  }

  return (
    <div className="threat-details-page">

      <header className="details-header">
        <div>
             <div className="details-actions">
          <button onClick={onBack}>← Threat Intelligence</button>
          <p></p>
          <button onClick={onLogout}>Logout</button>
        </div>
          <h1>Threat Details</h1>
          <p>Detailed threat intelligence and risk analysis</p>
        </div>

       
      </header>

      <main className="details-content">

        <section className="threat-overview">

          <div>
            <span className="details-label">Indicator</span>
            <h2>{threat.indicator}</h2>
          </div>

          <div
            className={`details-severity ${
              (threat.severity || "").toLowerCase()
            }`}
          >
            {threat.severity || "UNKNOWN"}
          </div>

        </section>

        <section className="details-grid">

          <div className="details-card">
            <h3>Basic Information</h3>

            <div className="detail-row">
              <span>Threat ID</span>
              <strong>#{threat.id}</strong>
            </div>

            <div className="detail-row">
              <span>Indicator Type</span>
              <strong>{threat.indicator_type}</strong>
            </div>

            <div className="detail-row">
              <span>Source</span>
              <strong>{threat.source || "Unknown"}</strong>
            </div>

            <div className="detail-row">
              <span>Status</span>
              <strong>{threat.status}</strong>
            </div>

            <div className="detail-row">
              <span>Category</span>
              <strong>{threat.category || "Unknown"}</strong>
            </div>
          </div>

          <div className="details-card risk-card">
            <h3>Risk Assessment</h3>

            <div className="risk-score-large">
              {threat.risk_score ?? 0}
              <span>/100</span>
            </div>

            <p>
              Risk Score
            </p>

            <div className="risk-factors">

              <div>
                <span>Source Reliability</span>
                <strong>{threat.source_score ?? 0}</strong>
              </div>

              <div>
                <span>Threat Severity</span>
                <strong>{threat.severity_score ?? 0}</strong>
              </div>

              <div>
                <span>Frequency</span>
                <strong>{threat.frequency_score ?? 0}</strong>
              </div>

              <div>
                <span>Recency</span>
                <strong>{threat.recency_score ?? 0}</strong>
              </div>

              <div>
                <span>Corroboration</span>
                <strong>{threat.corroboration_score ?? 0}</strong>
              </div>

            </div>
          </div>

        </section>

        <section className="details-card">

          <h3>Description</h3>

          <p className="description-text">
            {threat.description || "No description available."}
          </p>

        </section>

        <section className="details-grid">

          <div className="details-card">

            <h3>Timeline</h3>

            <div className="detail-row">
              <span>First Seen</span>
              <strong>
                {threat.first_seen
                  ? new Date(threat.first_seen).toLocaleString()
                  : "Not available"}
              </strong>
            </div>

            <div className="detail-row">
              <span>Last Seen</span>
              <strong>
                {threat.last_seen
                  ? new Date(threat.last_seen).toLocaleString()
                  : "Not available"}
              </strong>
            </div>

            <div className="detail-row">
              <span>Created</span>
              <strong>
                {threat.created_at
                  ? new Date(threat.created_at).toLocaleString()
                  : "Not available"}
              </strong>
            </div>

          </div>

          <div className="details-card">

            <h3>Analysis Details</h3>

            <p className="description-text">
              {threat.analysis_details ||
                "No additional analysis details available."}
            </p>

          </div>

        </section>

      </main>
    </div>
  );
}

export default ThreatDetails;