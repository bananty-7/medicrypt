import React, { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { AuthAPI } from "../api/client.js";

export default function Register() {
  const [form, setForm] = useState({
    full_name: "",
    email: "",
    password: "",
    role: "patient",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState(false);
  const navigate = useNavigate();

  const update = (field) => (e) => setForm({ ...form, [field]: e.target.value });

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      await AuthAPI.register(form);
      setSuccess(true);
      setTimeout(() => navigate("/login"), 1200);
    } catch (err) {
      setError(err.response?.data?.detail || "Registration failed.");
    }
  };

  return (
    <div className="card auth-card">
      <h2>Create account</h2>
      <form onSubmit={handleSubmit}>
        <label>Full name</label>
        <input value={form.full_name} onChange={update("full_name")} required />
        <label>Email</label>
        <input type="email" value={form.email} onChange={update("email")} required />
        <label>Password (min 8 characters)</label>
        <input
          type="password"
          value={form.password}
          onChange={update("password")}
          minLength={8}
          required
        />
        <label>Role</label>
        <select value={form.role} onChange={update("role")}>
          <option value="patient">Patient</option>
          <option value="doctor">Doctor</option>
          <option value="admin">Admin</option>
        </select>
        {error && <p className="error">{error}</p>}
        {success && <p className="success">Account created! Redirecting to login…</p>}
        <button type="submit">Register</button>
      </form>
      <p>
        Already have an account? <Link to="/login">Sign in</Link>
      </p>
    </div>
  );
}
