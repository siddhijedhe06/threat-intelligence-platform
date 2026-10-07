
import { useCallback, useState } from "react";
import Dashboard from "./Dashboard";
import "./App.css";
import Threats from "./Threats";
import AddThreat from "./AddThreat";
import Alerts from "./Alerts";
import ThreatDetails from "./ThreatDetails";

function App() {
  const [token, setToken] = useState(
    () => sessionStorage.getItem("access_token")
  );
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [currentPage, setCurrentPage] = useState("dashboard");
const [selectedThreatId, setSelectedThreatId] = useState(null);
  const logout = useCallback(() => {
    sessionStorage.clear();
    setToken(null);
    setUsername("");
    setPassword("");
    setCurrentPage("dashboard");
    setMessage("");
  }, []);

  async function handleLogin(event) {
    event.preventDefault();
    setMessage("");
    setLoading(true);

    try {
      const response = await fetch("http://127.0.0.1:8000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        setMessage(data.detail || "Login failed.");
        return;
      }

      sessionStorage.setItem("access_token", data.access_token);
      sessionStorage.setItem("username", data.user.username);
      sessionStorage.setItem("role", data.user.role);
      setToken(data.access_token);
    } catch {
      setMessage("Cannot connect to the API. Check your backend.");
    } finally {
      setLoading(false);
    }
  }

  if (token) {
    if (currentPage === "alerts") {
  return (
    <Alerts
      onBack={() => setCurrentPage("dashboard")}
      onLogout={logout}
    />
  );
}

if (currentPage === "threat-details") {
  return (
    <ThreatDetails
      threatId={selectedThreatId}
      onBack={() => setCurrentPage("threats")}
      onLogout={logout}
    />
  );
}

  if (currentPage === "threats") {
  return (
    <Threats
      onBack={() => setCurrentPage("dashboard")}
      onLogout={logout}
      onSelectThreat={(id) => {
        setSelectedThreatId(id);
        setCurrentPage("threat-details");
      }}
    />
  );
}

if (currentPage === "add-threat") {
  return (
    <AddThreat
      onBack={() => setCurrentPage("dashboard")}
      onLogout={logout}
    />
  );
}
  return (
    <Dashboard
      onLogout={logout}
      onNavigate={setCurrentPage}
    />
  );
}

  return (
    <main className="login-page">
      <section className="login-card">
        <div className="shield-icon">🛡️</div>
        <p className="eyebrow">CYBERSECURITY PLATFORM</p>
        <h1>Threat Intelligence</h1>
        <p className="subtitle">
          Monitor threats. Analyze risks. Stay protected.
        </p>

        <form onSubmit={handleLogin}>
          <label htmlFor="username">Username</label>
          <input
            id="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="Enter your username"
            autoComplete="username"
            required
          />

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Enter your password"
            autoComplete="current-password"
            required
          />

          <button type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign in"}
          </button>
        </form>

        {message && (
          <p className="login-message" role="status">
            {message}
          </p>
        )}

        <p className="footer-text">
          Secure access · Role-based authentication
        </p>
      </section>
    </main>
  );
}

export default App;