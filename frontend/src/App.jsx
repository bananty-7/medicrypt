import React from "react";
import { Routes, Route, Navigate, Link } from "react-router-dom";
import { AuthProvider, useAuth } from "./api/AuthContext.jsx";
import Login from "./pages/Login.jsx";
import Register from "./pages/Register.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import ImageDetail from "./pages/ImageDetail.jsx";
import AdminAudit from "./pages/AdminAudit.jsx";

function ProtectedRoute({ children }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return children;
}

function Shell({ children }) {
  const { user, logout } = useAuth();
  return (
    <div className="app-shell">
      <header className="topbar">
        <Link to="/" className="brand">
          🛡️ MediCrypt
        </Link>
        {user && (
          <nav>
            <span className="user-chip">
              {user.full_name} · <b>{user.role}</b>
            </span>
            {user.role === "admin" && <Link to="/admin/audit">Audit Log</Link>}
            <button className="link-btn" onClick={logout}>
              Log out
            </button>
          </nav>
        )}
      </header>
      <main>{children}</main>
      <footer>
        MediCrypt — AES-256-GCM · RSA-OAEP key exchange · RSA-PSS signatures · role-based access control
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <Shell>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/images/:id"
            element={
              <ProtectedRoute>
                <ImageDetail />
              </ProtectedRoute>
            }
          />
          <Route
            path="/admin/audit"
            element={
              <ProtectedRoute>
                <AdminAudit />
              </ProtectedRoute>
            }
          />
        </Routes>
      </Shell>
    </AuthProvider>
  );
}
