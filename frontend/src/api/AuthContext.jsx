import React, { createContext, useContext, useState } from "react";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const raw = localStorage.getItem("medicrypt_user");
    return raw ? JSON.parse(raw) : null;
  });

  const login = (token, userObj) => {
    localStorage.setItem("medicrypt_token", token);
    localStorage.setItem("medicrypt_user", JSON.stringify(userObj));
    setUser(userObj);
  };

  const logout = () => {
    localStorage.removeItem("medicrypt_token");
    localStorage.removeItem("medicrypt_user");
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
