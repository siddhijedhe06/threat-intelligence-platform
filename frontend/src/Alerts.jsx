import { useEffect, useMemo, useState } from "react";
import "./Alerts.css";

function Alerts({ onBack, onLogout, onSelectThreat }) {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [search, setSearch] = useState("");

  const role = sessionStorage.getItem("role") || "Viewer";
  const username = sessionStorage.getItem("username") || "Analyst";

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

  const filteredAlerts = useMemo(() => {
    const q = search.trim().toLowerCase();

    return alerts.filter((alert) => {
      const matchesSearch = [
        alert.indicator,
        alert.alert_type,
        alert.message,
        alert.category,
      ]
        .filter(Boolean)
        .some((val) => String(val).toLowerCase().includes(q));

      const matchesStatus =
        statusFilter === "All" ||
        String(alert.status || "").toLowerCase() === statusFilter.toLowerCase();

      const matchesSeverity =
        severityFilter === "All" ||
        String(alert.severity || "").toLowerCase() === severityFilter.toLowerCase();

      return matchesSearch && matchesStatus && matchesSeverity;
    });
  }, [alerts, search, statusFilter, severityFilter]);

  return (
    <div className="alerts-page">
      <header className="alerts-header">
        <div>
          <p className="eyebrow">SECURITY OPERATIONS CENTER / INCIDENT RESPONSE</p>
          <h1>Security Alerts & Incidents</h1>
          <p className="alerts-sub">
            Prioritized critical threat alerts automatically triggered when indicator risk scores reach &ge; 80.
          </p>
        </div>

        <div className="alerts-actions">
          <button className="alerts-nav-btn" onClick={onBack}>
            ← Dashboard
          </button>
          <div className="alerts-user-pill">
            <span>{username}</span>
            <span className="role-tag">{role}</span>
          </div>
          <button className="alerts-nav-btn" onClick={onLogout}>
            Logout
          </button>
        </div>
      </header>

      <main className="alerts-content">
        <div className="alerts-summary">
          <div className="alert-summary-card">
            <span>Total Alerts</span>
            <strong>{alerts.length}</strong>
          </div>

          <div className="alert-summary-card critical-card">
            <span>Critical Severity</span>
            <strong>
              {alerts.filter((a) => (a.severity || "").toUpperCase() === "CRITICAL").length}
            </strong>
          </div>

          <div className="alert-summary-card high-card">
            <span>High Severity</span>
            <strong>
              {alerts.filter((a) => (a.severity || "").toUpperCase() === "HIGH").length}
            </strong>
          </div>

          <div className="alert-summary-card open-card">
            <span>Open (Pending Triage)</span>
            <strong>
              {alerts.filter((a) => a.status === "Open").length}
            </strong>
          </div>
        </div>

        <section className="alerts-table-panel">
          <div className="alerts-table-header-row">
            <div>
              <h2>Incident & Alert Registry</h2>
              <p>Real-time threat notifications with triage acknowledgement workflows</p>
            </div>
            <button className="alerts-refresh-btn" onClick={fetchAlerts}>
              ↻ Refresh
            </button>
          </div>

          {/* Filters Bar */}
          <div className="alerts-filter-bar">
            <input
              placeholder="Search by indicator, category, or alert message..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="alerts-search-input"
            />

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="alerts-select"
            >
              <option value="All">All Statuses</option>
              <option value="Open">Open</option>
              <option value="Acknowledged">Acknowledged</option>
              <option value="Resolved">Resolved</option>
            </select>

            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="alerts-select"
            >
              <option value="All">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {loading && <div className="alerts-message">Loading active security alerts...</div>}
          {error && <div className="alerts-error">{error}</div>}

          {!loading && !error && filteredAlerts.length === 0 && (
            <div className="alerts-message">
              No matching alerts found. Adjust filters or search criteria.
            </div>
          )}

          {!loading && filteredAlerts.length > 0 && (
            <div className="alerts-table-container">
              <table className="alerts-table">
                <thead>
                  <tr>
                    <th>Alert ID</th>
                    <th>Indicator Target</th>
                    <th>Type</th>
                    <th>Category</th>
                    <th>Risk Score</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Alert Type</th>
                    <th>Triggered At</th>
                    <th>Triage Actions</th>
                  </tr>
                </thead>

                <tbody>
                  {filteredAlerts.map((alert) => (
                    <tr
                      key={alert.id}
                      className="alert-table-row"
                    >
                      <td>#{alert.id}</td>

                      <td
                        className="indicator-cell alert-indicator-clickable"
                        onClick={() => onSelectThreat && onSelectThreat(alert.threat_id)}
                        title="Click to view indicator dossier"
                      >
                        <strong>{alert.indicator}</strong>
                      </td>

                      <td>{alert.indicator_type || "—"}</td>

                      <td>{alert.category || "Unknown"}</td>

                      <td>
                        <span className="risk-score-badge">
                          {alert.risk_score ?? "—"}
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
                          : "—"}
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
                            onClick={() => updateAlert(alert.id, "resolve")}
                          >
                            Resolve
                          </button>
                        )}

                        {alert.status === "Resolved" && (
                          <span className="resolved-label">
                            ✓ Resolved
                          </span>
                        )}

                        {onSelectThreat && (
                          <button
                            className="details-mini-btn"
                            onClick={() => onSelectThreat(alert.threat_id)}
                            title="View full threat intelligence report"
                          >
                            Report &rarr;
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}

export default Alerts;