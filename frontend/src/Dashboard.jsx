import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { useEffect, useState } from "react";
import "./Dashboard.css";

function Dashboard({ onLogout, onNavigate }) {
  const [stats, setStats] = useState(null);
  const [threats, setThreats] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const username = sessionStorage.getItem("username") || "Analyst";
  const role = sessionStorage.getItem("role") || "Viewer";

  const severityData = [
    {
      name: "Critical",
      value: Number(stats?.critical_threats) || 0,
      color: "#ff657b",
    },
    {
      name: "High",
      value: Number(stats?.high_threats) || 0,
      color: "#ffa75e",
    },
    {
      name: "Medium",
      value: Number(stats?.medium_threats) || 0,
      color: "#e8cf65",
    },
    {
      name: "Low",
      value: Number(stats?.low_threats) || 0,
      color: "#53d4ac",
    },
  ];

  const totalAnalyzed = severityData.reduce((acc, curr) => acc + curr.value, 0);

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
        // Correctly handle both critical_threats and threats array keys
        setThreats(threatsData.critical_threats || threatsData.threats || []);
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
    return <div className="dashboard-loading">Loading security intelligence dashboard...</div>;
  }

  return (
    <div className="dashboard">
      <aside className="sidebar">
        <div className="brand">🛡 ThreatGuard</div>

        <p className="nav-heading">WORKSPACE</p>
        <button className="nav-item active" onClick={() => onNavigate("dashboard")}>
          ▦ Overview
        </button>
        <button
          className="nav-item"
          onClick={() => onNavigate("threats")}
        >
          ⌕ Threat Intelligence
        </button>

        {role !== "Viewer" && (
          <button
            className="nav-item"
            onClick={() => onNavigate("add-threat")}
          >
            + Add & Analyze Threat
          </button>
        )}

        <button
          className="nav-item"
          onClick={() => onNavigate("alerts")}
        >
          ⚠ Security Alerts {stats?.open_alerts ? `(${stats.open_alerts})` : ""}
        </button>

        <button
          className="nav-item"
          onClick={() => onNavigate("threats")}
        >
          ▤ Incident Log
        </button>

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
          <div>
            <p className="eyebrow">SECURITY OPERATIONS CENTER (SOC)</p>
            <h1>Threat Overview & Intelligence</h1>
          </div>
          <div style={{ display: "flex", gap: "10px", alignItems: "center" }}>
            <span className="user-role-badge">
              Role: {role}
            </span>
            <span className="system-status">
              <span className="status-dot" />
              Live Monitoring
            </span>
          </div>
        </header>

        <section className="welcome-section">
          <h2>Welcome back, {username}</h2>
          <p>
            Automated intelligence engine is actively scoring IP addresses, URLs, and domains for cyber risk.
          </p>
        </section>

        {error && <div className="error-message">{error}</div>}

        {stats && (
          <>
            <section className="stats-grid">
              <div onClick={() => onNavigate("threats")} style={{ cursor: "pointer" }}>
                <StatCard
                  title="Total Threats"
                  value={stats.total_threats}
                  icon="◈"
                  color="blue"
                />
              </div>
              <div onClick={() => onNavigate("threats")} style={{ cursor: "pointer" }}>
                <StatCard
                  title="Critical Threats"
                  value={stats.critical_threats}
                  icon="⚠"
                  color="red"
                />
              </div>
              <div onClick={() => onNavigate("threats")} style={{ cursor: "pointer" }}>
                <StatCard
                  title="High Risk Assets"
                  value={stats.high_threats}
                  icon="↗"
                  color="orange"
                />
              </div>
              <div onClick={() => onNavigate("alerts")} style={{ cursor: "pointer" }}>
                <StatCard
                  title="Open Alerts"
                  value={stats.open_alerts}
                  icon="♢"
                  color="purple"
                />
              </div>
            </section>

            <section className="content-grid">
              <div className="panel severity-panel">
                <div className="panel-heading">
                  <div>
                    <h3>Threat Severity Distribution</h3>
                    <p>Dynamic classification across indicators</p>
                  </div>
                  <span className="count-badge" style={{ background: "#172d42", color: "#6fe3d4" }}>
                    {totalAnalyzed} Evaluated
                  </span>
                </div>

                <div className="severity-chart-row" style={{ display: "flex", gap: "20px", alignItems: "center" }}>
                  {totalAnalyzed > 0 && (
                    <div style={{ width: 140, height: 140, flexShrink: 0 }}>
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={severityData}
                            cx="50%"
                            cy="50%"
                            innerRadius={38}
                            outerRadius={60}
                            paddingAngle={3}
                            dataKey="value"
                          >
                            {severityData.map((entry, index) => (
                              <Cell key={`cell-${index}`} fill={entry.color} />
                            ))}
                          </Pie>
                          <Tooltip
                            contentStyle={{
                              backgroundColor: "#0c1423",
                              border: "1px solid #26344a",
                              borderRadius: 8,
                              fontSize: 12,
                              color: "#f1f5fc",
                            }}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                  )}

                  <div style={{ flex: 1, minWidth: 0 }}>
                    {[
                      ["Critical (81-100)", stats.critical_threats, "critical"],
                      ["High (61-80)", stats.high_threats, "high"],
                      ["Medium (31-60)", stats.medium_threats, "medium"],
                      ["Low (0-30)", stats.low_threats, "low"],
                    ].map(([label, value, className]) => {
                      const total = Number(stats.total_threats) || 1;
                      const percentage = Math.min((Number(value) / total) * 100, 100);

                      return (
                        <div className="severity-row" key={label} style={{ margin: "10px 0" }}>
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
                </div>
              </div>

              <div className="panel insight-panel">
                <div className="insight-icon">⌁</div>
                <h3>Automated Risk Engine</h3>
                <p>
                  IP addresses and website links are deeply analyzed for brand impersonation,
                  phishing vectors, malicious payload downloads, Tor exit nodes, and exploit indicators.
                </p>
                <div className="risk-rule">
                  <span>Critical Alert Threshold</span>
                  <strong>Score &ge; 80</strong>
                </div>
                <div className="risk-rule">
                  <span>Active Role</span>
                  <strong>{role}</strong>
                </div>
                <div className="risk-rule">
                  <span>Security Alerts</span>
                  <strong style={{ color: stats.open_alerts > 0 ? "#ff7e8c" : "#53d4ac" }}>
                    {stats.open_alerts} Open
                  </strong>
                </div>
                {role !== "Viewer" && (
                  <button
                    onClick={() => onNavigate("add-threat")}
                    style={{
                      width: "100%",
                      marginTop: "16px",
                      padding: "10px",
                      borderRadius: "8px",
                      border: "none",
                      background: "#38cbbb",
                      color: "#07131c",
                      fontWeight: 700,
                      cursor: "pointer",
                      fontSize: "13px"
                    }}
                  >
                    + Analyze New Indicator
                  </button>
                )}
              </div>
            </section>

            <section className="panel threats-panel">
              <div className="panel-heading">
                <div>
                  <h3>Critical Threats & Alerts</h3>
                  <p>Highest severity indicators requiring urgent review (click any row for full report)</p>
                </div>
                <span className="count-badge">{threats.length} Critical Found</span>
              </div>

              {threats.length === 0 ? (
                <div className="empty-state">
                  <span>✓</span>
                  <p>No critical threats currently detected. Security perimeter normal.</p>
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
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {threats.map((threat) => (
                        <tr
                          key={threat.id}
                          className="clickable-threat-row"
                          onClick={() => onNavigate("threat-details", threat.id)}
                          style={{ cursor: "pointer" }}
                        >
                          <td className="indicator-cell">
                            <strong>{threat.indicator}</strong>
                          </td>
                          <td>{threat.indicator_type}</td>
                          <td>{threat.category || "Unknown"}</td>
                          <td>
                            <span className="score-pill-critical">
                              {threat.risk_score} / 100
                            </span>
                          </td>
                          <td>
                            <span className="severity-badge critical-badge">
                              {threat.severity || "CRITICAL"}
                            </span>
                          </td>
                          <td>{formatDate(threat.first_seen || threat.created_at)}</td>
                          <td>
                            <button
                              className="view-report-link"
                              onClick={(e) => {
                                e.stopPropagation();
                                onNavigate("threat-details", threat.id);
                              }}
                            >
                              Report &rarr;
                            </button>
                          </td>
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