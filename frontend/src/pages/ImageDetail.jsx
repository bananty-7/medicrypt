import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { ImageAPI, AuditAPI } from "../api/client.js";
import { useAuth } from "../api/AuthContext.jsx";

export default function ImageDetail() {
  const { id } = useParams();
  const { user } = useAuth();
  const [meta, setMeta] = useState(null);
  const [logs, setLogs] = useState([]);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [error, setError] = useState("");
  const [shareEmail, setShareEmail] = useState("");
  const [shareMsg, setShareMsg] = useState("");
  const [tamperMsg, setTamperMsg] = useState("");

  const loadMeta = async () => {
    try {
      const { data } = await ImageAPI.metadata(id);
      setMeta(data);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load image metadata.");
    }
  };

  const loadLogs = async () => {
    try {
      const { data } = await AuditAPI.forImage(id);
      setLogs(data.logs);
    } catch {
      /* non-fatal */
    }
  };

  useEffect(() => {
    loadMeta();
    loadLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const handleDecrypt = async () => {
    setError("");
    setPreviewUrl(null);
    try {
      const res = await ImageAPI.download(id);
      const blob = new Blob([res.data], { type: meta?.content_type || "image/png" });
      setPreviewUrl(URL.createObjectURL(blob));
      loadLogs();
    } catch (err) {
      if (err.response?.status === 409) {
        setError("⚠️ TAMPERING DETECTED — " + (err.response.data?.detail || ""));
      } else {
        setError(err.response?.data?.detail || "Decryption failed.");
      }
      loadLogs();
    }
  };

  const handleShare = async (e) => {
    e.preventDefault();
    setShareMsg("");
    try {
      const { data } = await ImageAPI.share(id, shareEmail);
      setShareMsg(data.message);
      setShareEmail("");
    } catch (err) {
      setShareMsg(err.response?.data?.detail || "Share failed.");
    }
  };

  const handleTamper = async () => {
    setTamperMsg("");
    try {
      const { data } = await ImageAPI.simulateTamper(id);
      setTamperMsg(data.message);
    } catch (err) {
      setTamperMsg(err.response?.data?.detail || "Failed.");
    }
  };

  if (!meta) return <div className="card">{error || "Loading…"}</div>;

  return (
    <div className="dashboard">
      <div className="card">
        <h3>{meta.filename}</h3>
        <p>
          <b>Modality:</b> {meta.modality || "—"} &nbsp; <b>Uploaded:</b>{" "}
          {new Date(meta.created_at).toLocaleString()}
        </p>
        <p className="muted">Notes: {meta.notes || "none"}</p>
        <p className="mono small">SHA-256 (plaintext): {meta.sha256_hash}</p>

        {error && <p className="error">{error}</p>}

        <button onClick={handleDecrypt}>🔓 Decrypt &amp; View</button>

        {previewUrl && (
          <div className="preview">
            <img src={previewUrl} alt="decrypted medical scan" />
            <p className="success">✅ Integrity verified (AES-GCM) &amp; signature valid (RSA-PSS)</p>
          </div>
        )}
      </div>

      <div className="card">
        <h3>Share access</h3>
        <form onSubmit={handleShare}>
          <input
            type="email"
            placeholder="grant access to email..."
            value={shareEmail}
            onChange={(e) => setShareEmail(e.target.value)}
            required
          />
          <button type="submit">Grant decryption access</button>
        </form>
        {shareMsg && <p className="muted">{shareMsg}</p>}
      </div>

      {user.role === "admin" && (
        <div className="card">
          <h3>⚠️ Demo: simulate tampering</h3>
          <p className="muted">
            Flips a byte in the stored ciphertext to demonstrate that the system detects
            tampering on the next decrypt attempt.
          </p>
          <button className="danger" onClick={handleTamper}>
            Corrupt stored ciphertext
          </button>
          {tamperMsg && <p className="muted">{tamperMsg}</p>}
        </div>
      )}

      <div className="card">
        <h3>Access history</h3>
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Actor</th>
              <th>Action</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((l) => (
              <tr key={l.id}>
                <td>{new Date(l.timestamp).toLocaleString()}</td>
                <td>{l.actor_email || "—"}</td>
                <td>
                  <span className={`badge ${l.action.includes("TAMPER") ? "danger" : ""}`}>
                    {l.action}
                  </span>
                </td>
                <td className="small">{l.detail || ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
