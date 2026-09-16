import { useEffect, useState } from "react";
import "./styles.css";

const API_URL = "/api";

function App() {
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadData() {
    try {
      setLoading(true);
      setError("");

      const [alertsResponse, incidentsResponse] = await Promise.all([
        fetch(`${API_URL}/alerts`),
        fetch(`${API_URL}/incidents`),
      ]);

      if (!alertsResponse.ok) {
        throw new Error("Failed to load alerts");
      }

      if (!incidentsResponse.ok) {
        throw new Error("Failed to load incidents");
      }

      const alertsData = await alertsResponse.json();
      const incidentsData = await incidentsResponse.json();

      setAlerts(alertsData.items || []);
      setIncidents(incidentsData.items || []);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadData();

    const interval = setInterval(() => {
      loadData();
    }, 10000);

    return () => clearInterval(interval);
  }, []);

  const criticalAlerts = alerts.filter(
    (alert) => alert.severity === "CRITICAL"
  ).length;

  const highAlerts = alerts.filter(
    (alert) => alert.severity === "HIGH"
  ).length;

  const escalatedAlerts = alerts.filter(
    (alert) => alert.status === "OPEN"
  ).length;

  return (
    <div className="app">
      <header className="header">
        <div>
          <h1>Enterprise IDS/IPS</h1>
          <p>Security Operations Dashboard</p>
        </div>

        <button onClick={loadData} className="refresh-button">
          Refresh
        </button>
      </header>

      {error && (
        <div className="error">
          Backend connection error: {error}
        </div>
      )}

      <section className="stats">
        <div className="stat-card">
          <span>Total Alerts</span>
          <strong>{alerts.length}</strong>
        </div>

        <div className="stat-card">
          <span>Critical Alerts</span>
          <strong>{criticalAlerts}</strong>
        </div>

        <div className="stat-card">
          <span>High Alerts</span>
          <strong>{highAlerts}</strong>
        </div>

        <div className="stat-card">
          <span>Open Alerts</span>
          <strong>{escalatedAlerts}</strong>
        </div>

        <div className="stat-card">
          <span>Incidents</span>
          <strong>{incidents.length}</strong>
        </div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Recent Alerts</h2>
          <span>{alerts.length} alerts</span>
        </div>

        {loading ? (
          <p className="message">Loading alerts...</p>
        ) : alerts.length === 0 ? (
          <p className="message">No alerts found.</p>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Signature</th>
                  <th>Category</th>
                  <th>Source IP</th>
                  <th>Destination</th>
                  <th>Risk</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {alerts.map((alert) => (
                  <tr key={alert.id}>
                    <td>
                      <span
                        className={`severity ${String(
                          alert.severity
                        ).toLowerCase()}`}
                      >
                        {alert.severity}
                      </span>
                    </td>

                    <td>{alert.signature}</td>

                    <td>{alert.category}</td>

                    <td>{alert.src_ip || "-"}</td>

                    <td>
                      {alert.dst_ip || "-"}
                      {alert.dst_port
                        ? `:${alert.dst_port}`
                        : ""}
                    </td>

                    <td>
                      <strong>{alert.risk_score}</strong>
                    </td>

                    <td>
                      <span
                        className={`status ${String(
                          alert.status
                        ).toLowerCase()}`}
                      >
                        {alert.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
        <div className="panel-header">
          <h2>Recent Incidents</h2>
          <span>{incidents.length} incidents</span>
        </div>

        {loading ? (
          <p className="message">Loading incidents...</p>
        ) : incidents.length === 0 ? (
          <p className="message">No incidents found.</p>
        ) : (
          <div className="table-container">
            <table>
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Risk</th>
                  <th>Status</th>
                  <th>Created</th>
                </tr>
              </thead>

              <tbody>
                {incidents.map((incident) => (
                  <tr key={incident.id}>
                    <td>{incident.title}</td>

                    <td>
                      <span
                        className={`severity ${String(
                          incident.severity
                        ).toLowerCase()}`}
                      >
                        {incident.severity}
                      </span>
                    </td>

                    <td>{incident.risk_score}</td>

                    <td>{incident.status}</td>

                    <td>
                      {incident.created_at
                        ? new Date(
                            incident.created_at
                          ).toLocaleString()
                        : "-"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

export default App;

