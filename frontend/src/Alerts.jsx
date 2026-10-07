import { useEffect, useState } from "react";
import "./Alerts.css";

function Alerts({ onBack, onLogout }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const role = sessionStorage.getItem("role");

  useEffect(() => {
    fetchAlerts();
  }, []);

  async function fetchAlerts() {
    const token = sessionStorage.getItem("access_token");

    try {
      const response = await fetch("http://127.0.0.1:8000/alerts", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      const data = await response.json();

      if (!response.ok) {
        setError(data.detail || "Failed to load alerts.");
        return;
      }

      setAlerts(data.alerts || []);
    } catch {
      setError("Cannot connect to the API.");
    } finally {
      setLoading(false);
    }
  }

  function handleLogout() {
    onLogout();
  }
  
  async function updateAlert(alertId, action) {
  const token = sessionStorage.getItem("access_token");

  try {
    const response = await fetch(
      `http://127.0.0.1:8000/alerts/${alertId}/${action}`,
      {
        method: "PUT",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      }
    );

    const data = await response.json();

    if (!response.ok) {
      setError(data.detail || "Failed to update alert.");
      return;
    }

    fetchAlerts();
  } catch {
    setError("Cannot connect to the API.");
  }
}

  return (
    <div className="alerts-page">

      <header className="alerts-header">
        <div>
          <h1>Security Alerts</h1>
          <p>Monitor critical cybersecurity threats</p>
        </div>

        <div className="alerts-actions">
          <button onClick={onBack}>← Dashboard</button>
          <button onClick={handleLogout}>Logout</button>
        </div>
      </header>

      <main className="alerts-content">

        <div className="alerts-summary">
          <div className="alert-summary-card">
            <span>Total Alerts</span>
            <strong>{alerts.length}</strong>
          </div>

          <div className="alert-summary-card critical-card">
            <span>Critical</span>
            <strong>
              {alerts.filter((alert) => alert.severity === "CRITICAL").length}
            </strong>
          </div>

          <div className="alert-summary-card high-card">
            <span>High</span>
            <strong>
              {alerts.filter((alert) => alert.severity === "HIGH").length}
            </strong>
          </div>

          <div className="alert-summary-card open-card">
            <span>Open</span>
            <strong>
              {alerts.filter((alert) => alert.status === "Open").length}
            </strong>
          </div>
        </div>

        {loading && (
          <div className="alerts-message">
            Loading alerts...
          </div>
        )}

        {error && (
          <div className="alerts-error">
            {error}
          </div>
        )}

        {!loading && !error && alerts.length === 0 && (
          <div className="alerts-message">
            No security alerts found.
          </div>
        )}

        {!loading && alerts.length > 0 && (
          <div className="alerts-table-container">

            <table className="alerts-table">

              <thead>
                <tr>
                  <th>ID</th>
                  <th>Indicator</th>
                  <th>Type</th>
                  <th>Category</th>
                  <th>Risk Score</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Alert Type</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>

                    <td>#{alert.id}</td>

                    <td className="indicator-cell">
                      {alert.indicator}
                    </td>

                    <td>{alert.indicator_type}</td>

                    <td>{alert.category || "Unknown"}</td>

                    <td>
                      <span className="risk-score">
                        {alert.risk_score ?? "-"}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`severity-badge ${(
                          alert.severity || ""
                        ).toLowerCase()}`}
                      >
                        {alert.severity || "UNKNOWN"}
                      </span>
                    </td>

                    <td>
                      <span
                        className={`status-badge ${(
                          alert.status || ""
                        ).toLowerCase()}`}
                      >
                        {alert.status}
                      </span>
                    </td>

                    <td>{alert.alert_type}</td>

                    <td>
                      {alert.created_at
                        ? new Date(alert.created_at).toLocaleString()
                        : "-"}
                    </td>
                    
                    <td className="alert-actions-cell">
  {role !== "Viewer" && alert.status === "Open" && (
    <button
      className="acknowledge-btn"
      onClick={() =>
        updateAlert(alert.id, "acknowledge")
      }
    >
      Acknowledge
    </button>
  )}

  {role !== "Viewer" && alert.status === "Acknowledged" && (
    <button
      className="resolve-btn"
      onClick={() =>
        updateAlert(alert.id, "resolve")
      }
    >
      Resolve
    </button>
  )}

  {alert.status === "Resolved" && (
    <span className="resolved-label">
      ✓ Resolved
    </span>
  )}
</td>
                  </tr>
                ))}
              </tbody>

            </table>

          </div>
        )}

      </main>
    </div>
  );
}

export default Alerts;