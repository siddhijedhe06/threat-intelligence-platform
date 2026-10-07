import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { useEffect, useState } from "react";
import "./Dashboard.css";

function Dashboard({ onLogout, onNavigate }) {
  const [stats, setStats] = useState(null);
  const [threats, setThreats] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const severityData = [
  {
    name: "Critical",
    value: stats?.critical || 0,
  },
  {
    name: "High",
    value: stats?.high || 0,
  },
  {
    name: "Medium",
    value: stats?.medium || 0,
  },
  {
    name: "Low",
    value: stats?.low || 0,
  },
];

  const username = sessionStorage.getItem("username") || "Analyst";
  const role = sessionStorage.getItem("role") || "Viewer";

  useEffect(() => {
    async function loadDashboard() {
      const token = sessionStorage.getItem("access_token");

      try {
        const headers = {
          Authorization: `Bearer ${token}`,
        };

        const [statsResponse, threatsResponse] = await Promise.all([
          fetch("http://127.0.0.1:8000/statistics", { headers }),
          fetch("http://127.0.0.1:8000/threats/critical", { headers }),
        ]);

        if (
          statsResponse.status === 401 ||
          threatsResponse.status === 401
        ) {
          sessionStorage.clear();
          onLogout();
          return;
        }

        if (!statsResponse.ok || !threatsResponse.ok) {
          throw new Error("Unable to load dashboard data.");
        }

        const statsData = await statsResponse.json();
        const threatsData = await threatsResponse.json();

        setStats(statsData);
        setThreats(threatsData.threats || []);
      } catch (err) {
        setError(err.message || "Could not connect to the API.");
      } finally {
        setLoading(false);
      }
    }

    loadDashboard();
  }, [onLogout]);

  function formatDate(value) {
    if (!value) return "—";

    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? String(value)
      : date.toLocaleDateString();
  }

  if (loading) {
    return <div className="dashboard-loading">Loading dashboard...</div>;
  }

  return (
    <div className="dashboard">
      <aside className="sidebar">
        <div className="brand">🛡 ThreatGuard</div>

        <p className="nav-heading">WORKSPACE</p>
        <div className="nav-item active">▦ Overview</div>
        <button
  className="nav-item"
  onClick={() => onNavigate("threats")}
>
  ⌕ Threat Intelligence
</button>

{sessionStorage.getItem("role") !== "Viewer" && (
  <button
    className="nav-item"
    onClick={() => onNavigate("add-threat")}
  >
    + Add New Threat
  </button>
)}

<button
  className="nav-item"
  onClick={() => onNavigate("alerts")}
>
  ⚠ Security Alerts
</button>

        <div className="nav-item">⚠ Critical Alerts</div>
        <div className="nav-item">▤ Analytics</div>

        <div className="sidebar-bottom">
          <div className="user-avatar">
            {username.charAt(0).toUpperCase()}
          </div>
          <div className="user-info">
            <strong>{username}</strong>
            <span>{role}</span>
          </div>
          <button className="logout-button" onClick={onLogout}>
            Logout
          </button>
        </div>
      </aside>

      <main className="dashboard-main">
        <header className="topbar">
          <span className="user-role">
  {sessionStorage.getItem("role")}
</span>
          <div>
            <p className="eyebrow">SECURITY OPERATIONS</p>
            <h1>Threat Overview</h1>
          </div>
          <span className="system-status">
            <span className="status-dot" />
            Dashboard
          </span>
        </header>

        <section className="welcome-section">
          <h2>Welcome back, {username}</h2>
          <p>Here's what's happening across your threat environment.</p>
        </section>

        {error && <div className="error-message">{error}</div>}

        {stats && (
          <>
            <section className="stats-grid">
              <StatCard
                title="Total Threats"
                value={stats.total_threats}
                icon="◈"
                color="blue"
              />
              <StatCard
                title="Critical Threats"
                value={stats.critical_threats}
                icon="⚠"
                color="red"
              />
              <StatCard
                title="High Risk"
                value={stats.high_threats}
                icon="↗"
                color="orange"
              />
              <StatCard
                title="Open Alerts"
                value={stats.open_alerts}
                icon="♢"
                color="purple"
              />
            </section>

            <section className="content-grid">
              <div className="panel severity-panel">
                <div className="panel-heading">
                  <div>
                    <h3>Threat Severity</h3>
                    <p>Distribution of analyzed threats</p>
                    
                  </div>
                </div>

                {[
                  ["Critical", stats.critical_threats, "critical"],
                  ["High", stats.high_threats, "high"],
                  ["Medium", stats.medium_threats, "medium"],
                  ["Low", stats.low_threats, "low"],
                ].map(([label, value, className]) => {
                  const total = Number(stats.total_threats) || 0;
                  const percentage = total
                    ? Math.min((Number(value) / total) * 100, 100)
                    : 0;

                  return (
                    <div className="severity-row" key={label}>
                      <div className="severity-label">
                        <span>{label}</span>
                        <strong>{value ?? 0}</strong>
                      </div>
                      <div className="progress-track">
                        <div
                          className={`progress-fill ${className}`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="panel insight-panel">
                <div className="insight-icon">⌁</div>
                <h3>Risk Monitoring</h3>
                <p>
                  Threats are automatically analyzed and assigned risk
                  scores. Scores of 81–100 are classified as critical.
                </p>
                <div className="risk-rule">
                  <span>Critical threshold</span>
                  <strong>80+</strong>
                </div>
                <div className="risk-rule">
                  <span>Active user</span>
                  <strong>{role}</strong>
                </div>
              </div>
            </section>

            <section className="panel threats-panel">
              <div className="panel-heading">
                <div>
                  <h3>Critical Threats</h3>
                  <p>Threats requiring priority investigation</p>
                </div>
                <span className="count-badge">{threats.length} found</span>
              </div>

              {threats.length === 0 ? (
                <div className="empty-state">
                  <span>✓</span>
                  <p>No critical threats found in the current results.</p>
                </div>
              ) : (
                <div className="table-wrapper">
                  <table>
                    <thead>
                      <tr>
                        <th>Indicator</th>
                        <th>Type</th>
                        <th>Category</th>
                        <th>Risk Score</th>
                        <th>Severity</th>
                        <th>First Seen</th>
                      </tr>
                    </thead>
                    <tbody>
                      {threats.map((threat) => (
                        <tr key={threat.id}>
                          <td className="indicator-cell">
                            {threat.indicator}
                          </td>
                          <td>{threat.indicator_type}</td>
                          <td>{threat.category || "Unknown"}</td>
                          <td>
                            <strong>{threat.risk_score}</strong>
                          </td>
                          <td>
                            <span className="severity-badge critical-badge">
                              {threat.severity || "CRITICAL"}
                            </span>
                          </td>
                          <td>{formatDate(threat.first_seen)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </>
        )}
      </main>
    </div>
  );
}

function StatCard({ title, value, icon, color }) {
  return (
    <article className="stat-card">
      <div className={`stat-icon ${color}`}>{icon}</div>
      <p>{title}</p>
      <h2>{value ?? 0}</h2>
    </article>
  );
}

export default Dashboard;