import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ImageAPI } from "../api/client.js";
import { useAuth } from "../api/AuthContext.jsx";

function UploadForm({ onUploaded }) {
  const [patientEmail, setPatientEmail] = useState("");
  const [modality, setModality] = useState("X-ray");
  const [notes, setNotes] = useState("");
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [ok, setOk] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setOk("");
    if (!file) return setError("Choose an image file first.");
    const fd = new FormData();
    fd.append("patient_email", patientEmail);
    fd.append("modality", modality);
    fd.append("notes", notes);
    fd.append("file", file);
    setBusy(true);
    try {
      await ImageAPI.upload(fd);
      setOk("Image encrypted, signed, and uploaded successfully.");
      setPatientEmail("");
      setNotes("");
      setFile(null);
      onUploaded();
    } catch (err) {
      setError(err.response?.data?.detail || "Upload failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="card" onSubmit={handleSubmit}>
      <h3>Upload a medical image</h3>
      <label>Patient email</label>
      <input
        type="email"
        value={patientEmail}
        onChange={(e) => setPatientEmail(e.target.value)}
        placeholder="patient@example.com"
        required
      />
      <label>Modality</label>
      <select value={modality} onChange={(e) => setModality(e.target.value)}>
        <option>X-ray</option>
        <option>CT</option>
        <option>MRI</option>
        <option>Other</option>
      </select>
      <label>Notes</label>
      <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={2} />
      <label>Image file (PNG / JPEG / TIFF / DICOM)</label>
      <input type="file" onChange={(e) => setFile(e.target.files[0])} required />
      {error && <p className="error">{error}</p>}
      {ok && <p className="success">{ok}</p>}
      <button type="submit" disabled={busy}>
        {busy ? "Encrypting & uploading..." : "Encrypt & Upload"}
      </button>
    </form>
  );
}

export default function Dashboard() {
  const { user } = useAuth();
  const [images, setImages] = useState([]);
  const [error, setError] = useState("");

  const fetchImages = async () => {
    try {
      const { data } = await ImageAPI.list();
      setImages(data);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load images.");
    }
  };

  useEffect(() => {
    fetchImages();
  }, []);

  const canUpload = user.role === "doctor" || user.role === "admin";

  return (
    <div className="dashboard">
      {canUpload && <UploadForm onUploaded={fetchImages} />}

      <div className="card">
        <h3>Accessible images ({images.length})</h3>
        {error && <p className="error">{error}</p>}
        {images.length === 0 && <p className="muted">No images yet.</p>}
        <table>
          <thead>
            <tr>
              <th>Filename</th>
              <th>Modality</th>
              <th>Uploaded</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {images.map((img) => (
              <tr key={img.id}>
                <td>{img.filename}</td>
                <td>{img.modality || "—"}</td>
                <td>{new Date(img.created_at).toLocaleString()}</td>
                <td>
                  <Link to={`/images/${img.id}`}>View →</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
