import React, { useEffect, useState } from "react";
import { AuditAPI } from "../api/client.js";

export default function AdminAudit() {
  const [logs, setLogs] = useState([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    AuditAPI.all()
      .then(({ data }) => {
        setLogs(data.logs);
        setTotal(data.total);
      })
      .catch((err) => setError(err.response?.data?.detail || "Failed to load audit log."));
  }, []);

  return (
    <div className="card">
      <h3>System audit log ({total} events)</h3>
      {error && <p className="error">{error}</p>}
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Image</th>
            <th>Detail</th>
            <th>IP</th>
          </tr>
        </thead>
        <tbody>
          {logs.map((l) => (
            <tr key={l.id}>
              <td>{new Date(l.timestamp).toLocaleString()}</td>
              <td>{l.actor_email || "system"}</td>
              <td>
                <span className={`badge ${l.action.includes("TAMPER") || l.action.includes("DENIED") ? "danger" : ""}`}>
                  {l.action}
                </span>
              </td>
              <td className="mono small">{l.image_id ? l.image_id.slice(0, 8) : "—"}</td>
              <td className="small">{l.detail || ""}</td>
              <td className="small">{l.ip_address || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
