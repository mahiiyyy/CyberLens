const API = import.meta.env.VITE_API_URL || "http://localhost:4000/api";

function getToken() {
  return localStorage.getItem("cyberlens_token") || sessionStorage.getItem("cyberlens_token");
}

export async function api(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${API}${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    localStorage.removeItem("cyberlens_token");
    sessionStorage.removeItem("cyberlens_token");
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "API request failed");
  return data;
}

export function clearAuth() {
  localStorage.removeItem("cyberlens_token");
  sessionStorage.removeItem("cyberlens_token");
  localStorage.removeItem("cyberlens_user");
  sessionStorage.removeItem("cyberlens_user");
}
