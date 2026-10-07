
import { useEffect, useMemo, useState } from "react";
import "./Threats.css";

function Threats({ onBack, onLogout, onSelectThreat }) {
  const [threats, setThreats] = useState([]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [typeFilter, setTypeFilter] = useState("All");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const username = sessionStorage.getItem("username") || "Analyst";
  const role = sessionStorage.getItem("role") || "Viewer";

  useEffect(() => {
    async function fetchThreats() {
      const token = sessionStorage.getItem("access_token");

      if (!token) {
        onLogout();
        return;
      }

      try {
        const response = await fetch("http://127.0.0.1:8000/threats", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (response.status === 401) {
          onLogout();
          return;
        }

        const data = await response.json();

        if (!response.ok) {
          throw new Error(data.detail || "Failed to load threats.");
        }

        setThreats(data.threats || []);
      } catch (err) {
        setError(err.message || "Could not connect to the backend.");
      } finally {
        setLoading(false);
      }
    }

    fetchThreats();
  }, [onLogout]);

  const types = useMemo(
    () => [
      "All",
      ...new Set(
        threats
          .map((threat) => threat.indicator_type)
          .filter(Boolean)
      ),
    ],
    [threats]
  );

  const filteredThreats = useMemo(() => {
    const query = search.trim().toLowerCase();

    return threats.filter((threat) => {
      const matchesSearch = [
        threat.indicator,
        threat.source,
        threat.category,
        threat.description,
      ]
        .filter(Boolean)
        .some((value) => String(value).toLowerCase().includes(query));

      const severity = String(threat.severity || "Unknown").toUpperCase();

      const matchesSeverity =
        severityFilter === "All" ||
        severity === severityFilter.toUpperCase();

      const matchesType =
        typeFilter === "All" || threat.indicator_type === typeFilter;

      return matchesSearch && matchesSeverity && matchesType;
    });
  }, [threats, search, severityFilter, typeFilter]);

  function getSeverity(threat) {
    if (threat.severity) return String(threat.severity).toUpperCase();

    if (threat.risk_score == null) return "UNANALYZED";

    const score = Number(threat.risk_score);

    if (score <= 30) return "LOW";
    if (score <= 60) return "MEDIUM";
    if (score <= 80) return "HIGH";
    return "CRITICAL";
  }

  function formatDate(value) {
    if (!value) return "—";

    const date = new Date(value);
    return Number.isNaN(date.getTime())
      ? String(value)
      : date.toLocaleDateString();
  }

  return (
    <div className="threats-page">
      <header className="threats-topbar">
        <button className="back-button" onClick={onBack}>
          ← Dashboard
        </button>

        <div className="threats-user">
          <span>{username}</span>
          <span className="role-tag">{role}</span>
          <button className="logout-small" onClick={onLogout}>
            Logout
          </button>
        </div>
      </header>

      <main className="threats-content">
        <p className="threats-eyebrow">SECURITY OPERATIONS / INTELLIGENCE</p>
        <h1>Threat Intelligence</h1>
        <p className="threats-subtitle">
          Search, review, and filter indicators collected by your platform.
        </p>

        <section className="threats-summary">
          <div>
            <span>Total indicators</span>
            <strong>{threats.length}</strong>
          </div>
          <div>
            <span>Critical</span>
            <strong>
              {threats.filter((t) => getSeverity(t) === "CRITICAL").length}
            </strong>
          </div>
          <div>
            <span>High risk</span>
            <strong>
              {threats.filter((t) => getSeverity(t) === "HIGH").length}
            </strong>
          </div>
          <div>
            <span>Showing results</span>
            <strong>{filteredThreats.length}</strong>
          </div>
        </section>

        <section className="threats-table-card">
          <div className="threats-table-heading">
            <div>
              <h2>All Indicators</h2>
              <p>Data loaded from your authenticated FastAPI endpoint.</p>
            </div>
            <button
              className="refresh-button"
              onClick={() => window.location.reload()}
            >
              ↻ Refresh
            </button>
          </div>

          <div className="threat-filters">
            <input
              aria-label="Search threats"
              placeholder="Search indicator, source, category..."
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />

            <select
              aria-label="Filter by severity"
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value)}
            >
              <option value="All">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="UNANALYZED">Unanalyzed</option>
            </select>

            <select
              aria-label="Filter by indicator type"
              value={typeFilter}
              onChange={(event) => setTypeFilter(event.target.value)}
            >
              {types.map((type) => (
                <option value={type} key={type}>
                  {type === "All" ? "All indicator types" : type}
                </option>
              ))}
            </select>
          </div>

          {error && <div className="threats-error">{error}</div>}

          {loading ? (
            <div className="threats-empty">Loading threat indicators...</div>
          ) : !error && filteredThreats.length === 0 ? (
            <div className="threats-empty">
              No matching indicators found. Try changing your search or filters.
            </div>
          ) : !error ? (
            <div className="threats-table-scroll">
              <table className="threats-table">
                <thead>
                  <tr>
                    <th>Indicator</th>
                    <th>Type</th>
                    <th>Category</th>
                    <th>Risk score</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>First seen</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredThreats.map((threat) => {
                    const severity = getSeverity(threat);

                    return (
                      <tr
  key={threat.id}
  onClick={() => onSelectThreat(threat.id)}
  className="threat-row"
>
                        <td className="threat-indicator">
                          {threat.indicator}
                        </td>
                        <td>{threat.indicator_type || "—"}</td>
                        <td>{threat.category || "Unknown"}</td>
                        <td>
                          {threat.risk_score == null
                            ? "—"
                            : threat.risk_score}
                        </td>
                        <td>
                          <span
                            className={`threat-severity severity-${severity.toLowerCase()}`}
                          >
                            {severity}
                          </span>
                        </td>
                        <td>{threat.source || "—"}</td>
                        <td>{formatDate(threat.first_seen)}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>
      </main>
    </div>
  );
}

export default Threats;