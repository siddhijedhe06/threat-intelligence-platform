
import { useState } from "react";
import "./AddThreat.css";

function AddThreat({ onBack, onLogout }) {
  const [indicator, setIndicator] = useState("");
  const [indicatorType, setIndicatorType] = useState("IP Address");
  const [source, setSource] = useState("Manual Entry");
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function handleSubmit(event) {
    event.preventDefault();
    setLoading(true);
    setResult(null);

    const token = sessionStorage.getItem("access_token");

    if (!token) {
      onLogout();
      return;
    }

    try {
      const response = await fetch("http://127.0.0.1:8000/threats", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          indicator: indicator.trim(),
          indicator_type: indicatorType,
          source: source.trim() || "Manual Entry",
          description: description.trim() || null,
        }),
      });

      const data = await response.json();

      if (response.status === 401) {
        onLogout();
        return;
      }

      if (!response.ok) {
        throw new Error(data.detail || "Could not submit the threat.");
      }

      setResult({
        success: true,
        message: `Threat submitted successfully. ID: ${data.threat_id}`,
        analysis: data.analysis,
        analysisStatus: data.analysis_status,
      });

      setIndicator("");
      setDescription("");
    } catch (error) {
      setResult({
        success: false,
        message: error.message || "Unable to connect to the API.",
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="add-threat-page">
      <header className="add-threat-header">
        <button className="add-back-button" onClick={onBack}>
          ← Back to Dashboard
        </button>

        <div className="add-user">
          {sessionStorage.getItem("username") || "Analyst"}
          <button className="add-logout-button" onClick={onLogout}>
            Logout
          </button>
        </div>
      </header>

      <main className="add-threat-content">
        <p className="add-eyebrow">SECURITY OPERATIONS / INGESTION</p>
        <h1>Add New Threat</h1>
        <p className="add-subtitle">
          Submit a suspicious indicator for automated analysis and risk scoring.
        </p>

        <section className="add-threat-card">
          <div className="add-card-heading">
            <div className="add-shield">🛡️</div>
            <div>
              <h2>Threat Indicator Details</h2>
              <p>Enter the indicator and any useful context.</p>
            </div>
          </div>

          <form onSubmit={handleSubmit}>
            <label htmlFor="indicator">Indicator *</label>
            <input
              id="indicator"
              value={indicator}
              onChange={(event) => setIndicator(event.target.value)}
              placeholder="e.g. 192.0.2.10 or suspicious.example"
              maxLength={500}
              required
            />

            <label htmlFor="indicatorType">Indicator Type *</label>
            <select
              id="indicatorType"
              value={indicatorType}
              onChange={(event) => setIndicatorType(event.target.value)}
              required
            >
              <option value="IP Address">IP Address</option>
              <option value="Domain">Domain</option>
              <option value="URL">URL</option>
              <option value="File Hash">File Hash</option>
            </select>

            <label htmlFor="source">Source</label>
            <input
              id="source"
              value={source}
              onChange={(event) => setSource(event.target.value)}
              placeholder="e.g. Manual Entry or Threat Feed"
              maxLength={255}
            />

            <label htmlFor="description">Description</label>
            <textarea
              id="description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Describe the suspicious activity or why it needs investigation..."
              rows={4}
              maxLength={5000}
            />

            <div className="add-form-note">
              <span>ⓘ</span>
              <p>
                Your backend assigns default risk-scoring factors and attempts
                automated analysis after the indicator is saved.
              </p>
            </div>

            <div className="add-form-actions">
              <button
                type="button"
                className="add-cancel-button"
                onClick={onBack}
              >
                Cancel
              </button>
              <button type="submit" disabled={loading}>
                {loading ? "Analyzing..." : "Submit for Analysis →"}
              </button>
            </div>
          </form>

          {result && (
            <div
              className={`add-result ${result.success ? "success" : "failure"}`}
              role="status"
            >
              <strong>
                {result.success ? "✓ Threat saved" : "Submission failed"}
              </strong>
              <p>{result.message}</p>

              {result.success && (
                <>
                  <p>
                    Analysis: {result.analysisStatus || "Status unavailable"}
                  </p>

                  {result.analysis && (
                    <div className="add-analysis-result">
                      <span>
                        Category: {result.analysis.category || "Unknown"}
                      </span>
                      <span>
                        Risk score: {result.analysis.risk_score ?? "—"}
                      </span>
                      <span>
                        Severity: {result.analysis.severity || "Unknown"}
                      </span>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default AddThreat;