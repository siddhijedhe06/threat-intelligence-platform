import { useState } from "react";
import "./AddThreat.css";

function AddThreat({ onBack, onLogout, onViewThreat }) {
  const [indicator, setIndicator] = useState("");
  const [indicatorType, setIndicatorType] = useState("IP Address");
  const [source, setSource] = useState("Manual Entry");
  const [description, setDescription] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  // Auto-detect indicator type when text changes
  function handleIndicatorChange(value) {
    setIndicator(value);
    const trimmed = value.trim();

    if (!trimmed) return;

    // Detect IP address
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?$/;
    if (ipv4Regex.test(trimmed)) {
      setIndicatorType("IP Address");
      return;
    }

    // Detect URL
    if (
      trimmed.startsWith("http://") ||
      trimmed.startsWith("https://") ||
      trimmed.startsWith("ftp://") ||
      (trimmed.includes("/") && trimmed.includes("."))
    ) {
      setIndicatorType("URL");
      return;
    }

    // Detect Hash
    if (/^[a-fA-F0-9]{32,64}$/.test(trimmed)) {
      setIndicatorType("File Hash");
      return;
    }

    // Detect Domain
    if (trimmed.includes(".") && !trimmed.includes(" ") && !trimmed.includes("/")) {
      setIndicatorType("Domain");
      return;
    }
  }

  function loadSample(sampleIndicator, sampleType, sampleSource, sampleDesc) {
    setIndicator(sampleIndicator);
    setIndicatorType(sampleType);
    setSource(sampleSource);
    setDescription(sampleDesc);
    setResult(null);
  }

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
        throw new Error(data.detail || "Could not submit the threat indicator.");
      }

      const analysisObj = data.analysis_result || data.analysis;

      setResult({
        success: true,
        threatId: data.threat_id,
        message: `Threat indicator added and analyzed successfully (ID: #${data.threat_id}).`,
        analysis: analysisObj,
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
          <span>{sessionStorage.getItem("username") || "Analyst"}</span>
          <span className="role-tag">{sessionStorage.getItem("role") || "Viewer"}</span>
          <button className="add-logout-button" onClick={onLogout}>
            Logout
          </button>
        </div>
      </header>

      <main className="add-threat-content">
        <p className="add-eyebrow">SECURITY OPERATIONS / INGESTION & ANALYSIS</p>
        <h1>Analyze Threat Indicator</h1>
        <p className="add-subtitle">
          Submit an IP address or website link/URL for comprehensive risk scoring,
          automated classification, and incident report generation.
        </p>

        {/* Quick test sample buttons */}
        <section className="sample-chips-container">
          <span className="sample-label">Quick Test Scenarios:</span>
          <div className="sample-chips">
            <button
              type="button"
              className="chip-btn chip-critical"
              onClick={() =>
                loadSample(
                  "http://paypal-security-update.com/login.php",
                  "URL",
                  "Phishing Feed",
                  "Credential harvesting website mimicking PayPal login portal"
                )
              }
            >
              ⚠ Phishing URL
            </button>
            <button
              type="button"
              className="chip-btn chip-critical"
              onClick={() =>
                loadSample(
                  "http://185.220.101.5:4444/payload.exe",
                  "URL",
                  "SOC Alert",
                  "Direct IP host with Metasploit listener port serving executable dropper"
                )
              }
            >
              ☣ Malware C2 URL
            </button>
            <button
              type="button"
              className="chip-btn chip-critical"
              onClick={() =>
                loadSample(
                  "185.220.101.5",
                  "IP Address",
                  "AlienVault OTX",
                  "Tor exit node observed executing high-volume brute force scanning"
                )
              }
            >
              🌐 Malicious IP
            </button>
            <button
              type="button"
              className="chip-btn chip-low"
              onClick={() =>
                loadSample(
                  "https://google.com",
                  "URL",
                  "Manual Entry",
                  "Legitimate global search engine homepage"
                )
              }
            >
              ✓ Safe Domain
            </button>
            <button
              type="button"
              className="chip-btn chip-low"
              onClick={() =>
                loadSample(
                  "192.168.1.1",
                  "IP Address",
                  "Manual Entry",
                  "Internal standard gateway address"
                )
              }
            >
              🏠 Private IP
            </button>
          </div>
        </section>

        <section className="add-threat-card">
          <div className="add-card-heading">
            <div className="add-shield">🛡️</div>
            <div>
              <h2>Indicator Intelligence Input</h2>
              <p>Enter the target IP or link to trigger automated heuristic evaluation.</p>
            </div>
          </div>

          <form onSubmit={handleSubmit}>
            <label htmlFor="indicator">Target Indicator (IP Address or Website Link/URL) *</label>
            <input
              id="indicator"
              value={indicator}
              onChange={(event) => handleIndicatorChange(event.target.value)}
              placeholder="e.g. 185.220.101.5 or http://paypal-security-update.com/login.php"
              maxLength={500}
              required
            />

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
              <div>
                <label htmlFor="indicatorType">Detected Indicator Type *</label>
                <select
                  id="indicatorType"
                  value={indicatorType}
                  onChange={(event) => setIndicatorType(event.target.value)}
                  required
                >
                  <option value="IP Address">IP Address</option>
                  <option value="URL">URL / Website Link</option>
                  <option value="Domain">Domain / Hostname</option>
                  <option value="File Hash">File Hash</option>
                </select>
              </div>

              <div>
                <label htmlFor="source">Intelligence Source</label>
                <input
                  id="source"
                  value={source}
                  onChange={(event) => setSource(event.target.value)}
                  placeholder="e.g. AbuseIPDB, ThreatFeed, SOC Alert, Manual Entry"
                  maxLength={255}
                />
              </div>
            </div>

            <label htmlFor="description">Threat Description / Context</label>
            <textarea
              id="description"
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Provide suspicious observations, attack patterns, detected ports, or threat actor context..."
              rows={4}
              maxLength={5000}
            />

            <div className="add-form-note">
              <span>ⓘ</span>
              <p>
                <strong>Automated Multi-Factor Analysis:</strong> Evaluates source reliability,
                threat category (Phishing, Malware, Botnet, Brute Force), structural IOC flags,
                and calculates a calibrated risk score (0-100). Scores &ge; 80 automatically trigger critical alerts.
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
                {loading ? "Analyzing Indicator..." : "Submit for Intelligence Analysis →"}
              </button>
            </div>
          </form>

          {result && (
            <div
              className={`add-result ${result.success ? "success" : "failure"}`}
              role="status"
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <strong>
                  {result.success ? "✓ Intelligence Analysis Completed" : "Submission Failed"}
                </strong>
                {result.threatId && onViewThreat && (
                  <button
                    type="button"
                    className="view-full-report-btn"
                    onClick={() => onViewThreat(result.threatId)}
                  >
                    View Full Report →
                  </button>
                )}
              </div>
              <p>{result.message}</p>

              {result.success && result.analysis && (
                <div className="add-analysis-card">
                  <div className="analysis-metrics-row">
                    <div>
                      <span>Category</span>
                      <strong>{result.analysis.category || "Unknown"}</strong>
                    </div>
                    <div>
                      <span>Risk Score</span>
                      <strong className={`score-badge ${(result.analysis.severity || "").toLowerCase()}`}>
                        {result.analysis.risk_score ?? "—"} / 100
                      </strong>
                    </div>
                    <div>
                      <span>Risk Level</span>
                      <strong className={`severity-tag ${(result.analysis.severity || "").toLowerCase()}`}>
                        {result.analysis.severity || "UNKNOWN"}
                      </strong>
                    </div>
                    <div>
                      <span>Alert Condition</span>
                      <strong>
                        {result.analysis.risk_score >= 80 ? (
                          <span style={{ color: "#ff7688" }}>⚠ Critical Alert Triggered</span>
                        ) : (
                          <span style={{ color: "#53d4ac" }}>✓ Standard Monitoring</span>
                        )}
                      </strong>
                    </div>
                  </div>

                  {result.analysis.analysis_details && (
                    <div className="quick-report-preview">
                      <div className="preview-label">Analysis Report Excerpt:</div>
                      <pre className="report-pre">{result.analysis.analysis_details}</pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default AddThreat;