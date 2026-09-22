import axios from "axios";

const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const client = axios.create({ baseURL: BASE_URL });

client.interceptors.request.use((config) => {
  const token = localStorage.getItem("medicrypt_token");
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

export const AuthAPI = {
  register: (payload) => client.post("/auth/register", payload),
  login: (payload) => client.post("/auth/login", payload),
};

export const ImageAPI = {
  list: () => client.get("/images/"),
  metadata: (id) => client.get(`/images/${id}`),
  upload: (formData) =>
    client.post("/images/upload", formData, {
      headers: { "Content-Type": "multipart/form-data" },
    }),
    download: (id) =>
    client.get(`/images/${id}/download`, {
      responseType: "blob",
      params: { _ts: Date.now() },
      headers: { "Cache-Control": "no-cache" },
    }),
  share: (id, email) => client.post(`/images/${id}/share`, { grant_to_email: email }),
  simulateTamper: (id) => client.post(`/images/${id}/simulate-tamper`),
};

export const AuditAPI = {
  all: (limit = 100, offset = 0) => client.get(`/audit/?limit=${limit}&offset=${offset}`),
  forImage: (id) => client.get(`/audit/image/${id}`),
};

export default client;
