import { useEffect, useState } from "react";
import "./ThreatDetails.css";

function ThreatDetails({ threatId, onBack, onLogout, onNavigate }) {
  const [threat, setThreat] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [copied, setCopied] = useState(false);

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
        setError(data.detail || "Failed to load threat intelligence details.");
        return;
      }

      setThreat(data);
    } catch {
      setError("Cannot connect to the backend API.");
    } finally {
      setLoading(false);
    }
  }

  function handleCopyReport() {
    if (threat?.analysis_details) {
      navigator.clipboard.writeText(threat.analysis_details);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }

  if (loading) {
    return (
      <div className="threat-details-page">
        <div className="details-message">Loading threat intelligence analysis...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="threat-details-page">
        <div className="details-error">{error}</div>
        <button className="details-back-btn" onClick={onBack}>
          ← Back to Intelligence List
        </button>
      </div>
    );
  }

  if (!threat) {
    return null;
  }

  const severityClass = (threat.severity || "unknown").toLowerCase();
  const isCritical = (threat.risk_score ?? 0) >= 80;

  return (
    <div className="threat-details-page">
      <header className="details-header">
        <div className="details-top-nav">
          <button className="details-back-btn" onClick={onBack}>
            ← Back to Threat Intelligence
          </button>
          <div className="details-user-meta">
            <span>{sessionStorage.getItem("username") || "Analyst"}</span>
            <span className="role-tag">{sessionStorage.getItem("role") || "Viewer"}</span>
            <button className="details-logout-btn" onClick={onLogout}>
              Logout
            </button>
          </div>
        </div>

        <div className="details-title-row">
          <div>
            <p className="eyebrow">INDICATOR DOSSIER #{threat.id}</p>
            <h1>Intelligence & Risk Report</h1>
          </div>
          <button className="copy-report-btn" onClick={handleCopyReport}>
            {copied ? "✓ Report Copied" : "📋 Copy Full Report"}
          </button>
        </div>
      </header>

      <main className="details-content">
        {/* Critical Alert Condition Banner */}
        {isCritical && (
          <div className="critical-alert-banner">
            <div className="alert-banner-icon">⚠</div>
            <div className="alert-banner-text">
              <strong>CRITICAL THREAT CONDITION DETECTED</strong>
              <p>
                Calculated Risk Score ({threat.risk_score}/100) exceeds critical security threshold (80+).
                An automated security alert has been dispatched for SOC priority triage.
              </p>
            </div>
            {onNavigate && (
              <button
                className="view-alerts-banner-btn"
                onClick={() => onNavigate("alerts")}
              >
                View Alerts →
              </button>
            )}
          </div>
        )}

        {/* Primary Overview Hero */}
        <section className="threat-overview">
          <div className="threat-indicator-info">
            <span className="details-label">Analyzed Indicator Target</span>
            <h2>{threat.indicator}</h2>
            <div className="indicator-tags">
              <span className="tag-pill type-pill">{threat.indicator_type || "Unknown Type"}</span>
              <span className="tag-pill cat-pill">{threat.category || "Unknown Category"}</span>
              <span className="tag-pill source-pill">Source: {threat.source || "Manual Entry"}</span>
            </div>
          </div>

          <div className="threat-severity-badge-container">
            <span className="details-label">Risk Severity</span>
            <div className={`details-severity ${severityClass}`}>
              {threat.severity || "UNKNOWN"}
            </div>
          </div>
        </section>

        {/* Grid: Basic Info and Risk Assessment */}
        <section className="details-grid">
          <div className="details-card">
            <h3>Technical Metadata</h3>

            <div className="detail-row">
              <span>Threat ID</span>
              <strong>#{threat.id}</strong>
            </div>

            <div className="detail-row">
              <span>Indicator Type</span>
              <strong>{threat.indicator_type}</strong>
            </div>

            <div className="detail-row">
              <span>Source Feed</span>
              <strong>{threat.source || "Manual Entry"}</strong>
            </div>

            <div className="detail-row">
              <span>Status</span>
              <strong className="status-highlight">{threat.status || "Active"}</strong>
            </div>

            <div className="detail-row">
              <span>Threat Category</span>
              <strong>{threat.category || "Unknown"}</strong>
            </div>

            <div className="detail-row">
              <span>First Ingested</span>
              <strong>
                {threat.created_at
                  ? new Date(threat.created_at).toLocaleString()
                  : "Not recorded"}
              </strong>
            </div>
          </div>

          <div className="details-card risk-card">
            <h3>Risk Assessment Scoring</h3>

            <div className="risk-score-display">
              <div className={`risk-score-large ${severityClass}`}>
                {threat.risk_score ?? 0}
                <span>/100</span>
              </div>
              <p className="score-caption">Composite Heuristic Risk Score</p>
            </div>

            <div className="risk-factors">
              <div className="factor-box">
                <span>Source Reliability</span>
                <strong>{threat.source_score ?? 0} <small>/20</small></strong>
              </div>

              <div className="factor-box">
                <span>Threat Severity</span>
                <strong>{threat.severity_score ?? 0} <small>/30</small></strong>
              </div>

              <div className="factor-box">
                <span>Frequency / Pattern</span>
                <strong>{threat.frequency_score ?? 0} <small>/20</small></strong>
              </div>

              <div className="factor-box">
                <span>Recency Factor</span>
                <strong>{threat.recency_score ?? 0} <small>/15</small></strong>
              </div>

              <div className="factor-box">
                <span>Corroboration</span>
                <strong>{threat.corroboration_score ?? 0} <small>/15</small></strong>
              </div>
            </div>
          </div>
        </section>

        {/* Comprehensive Analysis Report */}
        <section className="details-card report-card">
          <div className="report-card-header">
            <div>
              <h3>Automated Security Intelligence Report</h3>
              <p>Generated by rule-based heuristic and structural IOC inspection</p>
            </div>
            <button className="copy-small-btn" onClick={handleCopyReport}>
              {copied ? "✓ Copied" : "Copy"}
            </button>
          </div>

          <div className="report-body">
            <pre className="full-report-pre">
              {threat.analysis_details || "No detailed report recorded for this indicator."}
            </pre>
          </div>
        </section>

        {/* Description Context */}
        {threat.description && (
          <section className="details-card">
            <h3>Analyst Description & Context</h3>
            <p className="description-text">{threat.description}</p>
          </section>
        )}
      </main>
    </div>
  );
}

export default ThreatDetails;