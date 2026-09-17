/**
 * Thin API client that wraps fetch with auth headers.
 * Reads the JWT from sessionStorage (set on login).
 */

export function getApiBase() {
  if (typeof window !== 'undefined') {
    const host = window.location.hostname;
    return process.env.NEXT_PUBLIC_API_URL || `http://${host}:8000`;
  }
  return process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
}

export function getToken() {
  if (typeof window === 'undefined') return null;
  return sessionStorage.getItem('ids_token');
}

export function setToken(token) {
  sessionStorage.setItem('ids_token', token);
}

export function clearToken() {
  sessionStorage.removeItem('ids_token');
  sessionStorage.removeItem('ids_user');
}

export function getUser() {
  if (typeof window === 'undefined') return null;
  try {
    return JSON.parse(sessionStorage.getItem('ids_user') || 'null');
  } catch {
    return null;
  }
}

export function setUser(user) {
  sessionStorage.setItem('ids_user', JSON.stringify(user));
}

async function request(path, options = {}) {
  const token = getToken();
  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const res = await fetch(`${getApiBase()}/api${path}`, {
    ...options,
    headers,
  });

  if (res.status === 401) {
    clearToken();
    if (typeof window !== 'undefined') window.location.href = '/login';
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
