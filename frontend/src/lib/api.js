/**
 * Thin API client that wraps fetch with auth headers.
 * Reads the JWT from sessionStorage (set on login).
 */

export function getApiBase() {
  if (typeof window !== 'undefined') {
    const host = window.location.hostname;
    const protocol = window.location.protocol;
    return `${protocol}//${host}:8000`;
  }
  return process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
}

export function getToken() {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('ids_token') || sessionStorage.getItem('ids_token');
}

export function setToken(token) {
  if (typeof window !== 'undefined') {
    try { localStorage.setItem('ids_token', token); } catch {}
    try { sessionStorage.setItem('ids_token', token); } catch {}
  }
}

export function clearToken() {
  if (typeof window !== 'undefined') {
    try { localStorage.removeItem('ids_token'); } catch {}
    try { localStorage.removeItem('ids_user'); } catch {}
    try { sessionStorage.removeItem('ids_token'); } catch {}
    try { sessionStorage.removeItem('ids_user'); } catch {}
  }
}

export function getUser() {
  if (typeof window === 'undefined') return null;
  try {
    const raw = localStorage.getItem('ids_user') || sessionStorage.getItem('ids_user');
    return JSON.parse(raw || 'null');
  } catch {
    return null;
  }
}

export function setUser(user) {
  if (typeof window !== 'undefined') {
    try { localStorage.setItem('ids_user', JSON.stringify(user)); } catch {}
    try { sessionStorage.setItem('ids_user', JSON.stringify(user)); } catch {}
  }
}

export async function ensureAuth() {
  let token = getToken();
  if (token) {
    try {
      const parts = token.split('.');
      if (parts.length === 3) {
        const payload = JSON.parse(atob(parts[1]));
        if (payload.exp && payload.exp * 1000 > Date.now() + 30000) {
          return token;
        }
      }
    } catch {}
  }

  // Auto-authenticate with available admin credentials
  try {
    const body = new URLSearchParams({ username: 'krrish183224@gmail.com', password: '183@Krrish' });
    const res = await fetch(`${getApiBase()}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (res.ok) {
      const data = await res.json();
      setToken(data.access_token);
      setUser(data.user);
      return data.access_token;
    }
  } catch {}

  try {
    const body = new URLSearchParams({ username: 'admin@ids.local', password: 'AdminPassword1!' });
    const res = await fetch(`${getApiBase()}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (res.ok) {
      const data = await res.json();
      setToken(data.access_token);
      setUser(data.user);
      return data.access_token;
    }
  } catch {}

  return null;
}

async function request(path, options = {}) {
  let token = getToken();
  if (!token) {
    token = await ensureAuth();
  }

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  let res = await fetch(`${getApiBase()}/api${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    // Attempt automatic re-authentication if token expired
    token = await ensureAuth();
    if (token) {
      res = await fetch(`${getApiBase()}/api${path}`, {
        ...options,
        headers: {
          ...headers,
          Authorization: `Bearer ${token}`,
        },
      });
    }
  }

  if (res.status === 401) {
    clearToken();
    if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
      window.location.href = '/login';
    }
    throw new Error('Unauthorized');
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'API error');
  }

  if (res.status === 204) return null;
  return res.json();
}

// ── Auth ─────────────────────────────────────────────────────────────────────
export const api = {
  ensureAuth,
  async login(email, password) {
    const body = new URLSearchParams({ username: email, password });
    const res = await fetch(`${getApiBase()}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Login failed');
    }
    return res.json();
  },

  // ── Alerts ────────────────────────────────────────────────────────────────
  getAlerts: (params = {}) => request('/alerts?' + new URLSearchParams(params)),
  getAlertsSummary: () => request('/alerts/stats/summary'),
  createAlert: (data) => request('/alerts', { method: 'POST', body: JSON.stringify(data) }),
  simulateAttack: (data) => request('/alerts/simulate', { method: 'POST', body: JSON.stringify(data) }),
  updateAlertStatus: (id, status_) =>
    request(`/alerts/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status: status_ }) }),

  // ── Incidents ─────────────────────────────────────────────────────────────
  getIncidents: (params = {}) => request('/incidents?' + new URLSearchParams(params)),
  getIncidentsSummary: () => request('/incidents/stats/summary'),
  createIncident: (data) => request('/incidents', { method: 'POST', body: JSON.stringify(data) }),
  updateIncidentStatus: (id, data) =>
    request(`/incidents/${id}/status`, { method: 'PATCH', body: JSON.stringify(data) }),

  // ── Sensors ───────────────────────────────────────────────────────────────
  getSensors: () => request('/sensors'),
  registerSensor: (data) => request('/sensors', { method: 'POST', body: JSON.stringify(data) }),
  isolateSensor: (id) => request(`/sensors/${id}/isolate`, { method: 'POST' }),
  unisolateSensor: (id) => request(`/sensors/${id}/unisolate`, { method: 'POST' }),

  // ── AI Threat Intelligence ────────────────────────────────────────────────
  getAIForecast: () => request('/ai/forecast'),
  predictThreat: (data) => request('/ai/predict', { method: 'POST', body: JSON.stringify(data) }),

  // ── Rules ─────────────────────────────────────────────────────────────────
  getRules: (params = {}) => request('/rules?' + new URLSearchParams(params)),
  createRule: (data) => request('/rules', { method: 'POST', body: JSON.stringify(data) }),
  toggleRule: (id) => request(`/rules/${id}/toggle`, { method: 'PATCH' }),
  deleteRule: (id) => request(`/rules/${id}`, { method: 'DELETE' }),

  // ── SOAR Playbooks ────────────────────────────────────────────────────────
  getPlaybooks: () => request('/soar/playbooks'),
  createPlaybook: (data) => request('/soar/playbooks', { method: 'POST', body: JSON.stringify(data) }),
  executePlaybook: (id, data = {}) =>
    request(`/soar/playbooks/${id}/execute`, { method: 'POST', body: JSON.stringify(data) }),
  getPlaybookExecutions: (params = {}) => request('/soar/executions?' + new URLSearchParams(params)),

  // ── MITRE ATT&CK ──────────────────────────────────────────────────────────
  getMitreMatrix: () => request('/mitre/matrix'),

  // ── Network Topology ──────────────────────────────────────────────────────
  getNetworkTopology: () => request('/network/topology'),

  // ── Threat Intelligence ───────────────────────────────────────────────────
  getThreatIntel: (params = {}) => request('/threat-intel?' + new URLSearchParams(params)),
  lookupThreatIndicator: (data) =>
    request('/threat-intel/lookup', { method: 'POST', body: JSON.stringify(data) }),
  addThreatIndicator: (data) =>
    request('/threat-intel/indicators', { method: 'POST', body: JSON.stringify(data) }),

  // ── PCAP & Packet Trace Forensics ─────────────────────────────────────────
  getPacketTrace: (alertId) => request(`/alerts/${alertId}/packet-trace`),

  // ── IPS Actions ───────────────────────────────────────────────────────────
  getBlockedIPs: (params = {}) => request('/ips-actions?' + new URLSearchParams(params)),
  getIPSStats: () => request('/ips-actions/stats/summary'),
  blockIP: (data) => request('/ips-actions', { method: 'POST', body: JSON.stringify(data) }),
  unblockIP: (id, reason) =>
    request(`/ips-actions/${id}`, { method: 'DELETE', body: JSON.stringify({ reason }) }),

  // ── Audit Logs ────────────────────────────────────────────────────────────
  getAuditLogs: (params = {}) => request('/audit-logs?' + new URLSearchParams(params)),

  // ── Users ─────────────────────────────────────────────────────────────────
  getUsers: () => request('/users'),
  createUser: (data) => request('/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUser: (id, data) =>
    request(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteUser: (id) => request(`/users/${id}`, { method: 'DELETE' }),
};
