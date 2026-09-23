/**
 * Thin API client that wraps fetch with auth headers.
 * Reads the JWT from sessionStorage (set on login).
 */

export function getApiBase() {
  if (typeof window !== 'undefined') {
    return '';
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
    try {
      const isHttps = window.location.protocol === 'https:';
      document.cookie = `ids_token=${token}; path=/; max-age=604800; SameSite=Lax${isHttps ? '; Secure' : ''}`;
    } catch {}
  }
}

export function clearToken() {
  if (typeof window !== 'undefined') {
    try { localStorage.removeItem('ids_token'); } catch {}
    try { localStorage.removeItem('ids_user'); } catch {}
    try { sessionStorage.removeItem('ids_token'); } catch {}
    try { sessionStorage.removeItem('ids_user'); } catch {}
    try {
      document.cookie = 'ids_token=; path=/; max-age=0; SameSite=Lax';
    } catch {}
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

function parseJwt(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const pad = base64.length % 4;
    const padded = pad ? base64 + '='.repeat(4 - pad) : base64;
    return JSON.parse(atob(padded));
  } catch {
    return null;
  }
}

export async function ensureAuth() {
  let token = getToken();
  if (token) {
    const payload = parseJwt(token);
    if (payload && payload.exp && payload.exp * 1000 > Date.now() + 10000) {
      return token;
    }
  }
  // Clear any expired or invalid token
  clearToken();
  return null;
}

async function request(path, options = {}) {
  let token = getToken();
  if (!token) {
    token = await ensureAuth();
  }

  const isPublicAuth = path.startsWith('/auth/login') || path.startsWith('/auth/refresh');

  if (!token && !isPublicAuth && typeof window !== 'undefined') {
    const p = window.location.pathname;
    if (p !== '/login' && p !== '/demo' && p !== '/landing') {
      window.location.href = '/login';
      throw new Error('Authentication required');
    }
  }

  const headers = {
    'Content-Type': 'application/json',
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };

  const primaryUrl = `/api${path}`;
  const fallbackUrl = (typeof window !== 'undefined' && window.location.hostname)
    ? `${window.location.protocol}//${window.location.hostname}:8000/api${path}`
    : `/api${path}`;

  let res;
  try {
    res = await fetch(primaryUrl, {
      ...options,
      headers,
    });
  } catch (primaryErr) {
    try {
      res = await fetch(fallbackUrl, {
        ...options,
        headers,
      });
    } catch {
      throw primaryErr;
    }
  }

  if (res.status === 401) {
    // Attempt automatic re-authentication if token expired
    token = await ensureAuth();
    if (token) {
      const retryHeaders = {
        ...headers,
        Authorization: `Bearer ${token}`,
      };
      try {
        res = await fetch(primaryUrl, { ...options, headers: retryHeaders });
      } catch {
        res = await fetch(fallbackUrl, { ...options, headers: retryHeaders });
      }
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
    let msg = 'API error';
    if (typeof err.detail === 'string') {
      msg = err.detail;
    } else if (Array.isArray(err.detail)) {
      msg = err.detail.map(d => (d.loc ? `${d.loc.join('.')}: ` : '') + (d.msg || JSON.stringify(d))).join(', ');
    } else if (err.detail) {
      msg = JSON.stringify(err.detail);
    }
    throw new Error(msg);
  }

  if (res.status === 204) return null;
  return res.json();
}

// ── Auth ─────────────────────────────────────────────────────────────────────
export const api = {
  ensureAuth,
  async login(email, password) {
    const body = new URLSearchParams({ username: email, password });
    let res;
    try {
      res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
    } catch (e) {
      const fallback = (typeof window !== 'undefined' && window.location.hostname)
        ? `${window.location.protocol}//${window.location.hostname}:8000/api/auth/login`
        : '/api/auth/login';
      res = await fetch(fallback, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      });
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || 'Login failed: Invalid email or password');
    }
    return res.json();
  },

  // ── Alerts ────────────────────────────────────────────────────────────────
  getAlerts: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    return request('/alerts?' + new URLSearchParams(cleanParams));
  },
  getAlertsSummary: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    const qs = new URLSearchParams(cleanParams).toString();
    return request('/alerts/stats/summary' + (qs ? '?' + qs : ''));
  },
  getAlertsTimeline: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    const qs = new URLSearchParams(cleanParams).toString();
    return request('/alerts/stats/timeline' + (qs ? '?' + qs : ''));
  },
  getKillChainStats: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    const qs = new URLSearchParams(cleanParams).toString();
    return request('/alerts/stats/kill-chain' + (qs ? '?' + qs : ''));
  },
  getGeoRadarStats: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    const qs = new URLSearchParams(cleanParams).toString();
    return request('/alerts/stats/geo-radar' + (qs ? '?' + qs : ''));
  },
  createAlert: (data) => request('/alerts', { method: 'POST', body: JSON.stringify(data) }),
  simulateAttack: (data) => request('/alerts/simulate', { method: 'POST', body: JSON.stringify(data) }),
  updateAlertStatus: (id, status_) =>
    request(`/alerts/${id}/status`, { method: 'PATCH', body: JSON.stringify({ status: status_ }) }),
  batchResolveAlerts: (data) => request('/alerts/batch-resolve', { method: 'POST', body: JSON.stringify(data) }),

  // ── Incidents ─────────────────────────────────────────────────────────────
  getIncidents: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    return request('/incidents?' + new URLSearchParams(cleanParams));
  },
  getIncidentsSummary: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    const qs = new URLSearchParams(cleanParams).toString();
    return request('/incidents/stats/summary' + (qs ? '?' + qs : ''));
  },
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
  runBasAudit: () => request('/run-bas-audit', { method: 'POST' }),
  investigateIncident: (data = {}) => request('/investigate-incident', { method: 'POST', body: JSON.stringify(data) }),

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
  getPlaybookExecutions: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    return request('/soar/executions?' + new URLSearchParams(cleanParams));
  },

  // ── MITRE ATT&CK ──────────────────────────────────────────────────────────
  getMitreMatrix: () => request('/mitre/matrix'),
  getMitreTechnique: (id) => request(`/mitre/techniques/${id}`),

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
  getBlockedIPs: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    return request('/ips-actions?' + new URLSearchParams(cleanParams));
  },
  getIPSStats: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    const qs = new URLSearchParams(cleanParams).toString();
    return request('/ips-actions/stats/summary' + (qs ? '?' + qs : ''));
  },
  getIPSTimeline: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    const qs = new URLSearchParams(cleanParams).toString();
    return request('/ips-actions/stats/timeline' + (qs ? '?' + qs : ''));
  },
  blockIP: (data) => request('/ips-actions', { method: 'POST', body: JSON.stringify(data) }),
  unblockIP: (id, reason) =>
    request(`/ips-actions/${id}`, { method: 'DELETE', body: JSON.stringify({ reason }) }),

  // ── Audit Logs ────────────────────────────────────────────────────────────
  getAuditLogs: (params = {}) => {
    const cleanParams = Object.fromEntries(Object.entries(params).filter(([_, v]) => v !== undefined && v !== null));
    return request('/audit-logs?' + new URLSearchParams(cleanParams));
  },

  // ── Users ─────────────────────────────────────────────────────────────────
  getUsers: () => request('/users'),
  createUser: (data) => request('/users', { method: 'POST', body: JSON.stringify(data) }),
  updateUser: (id, data) =>
    request(`/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) }),
  deleteUser: (id) => request(`/users/${id}`, { method: 'DELETE' }),
  resetUserPassword: (id, data = {}) =>
    request(`/users/${id}/reset-password`, { method: 'POST', body: JSON.stringify(data) }),

  // ── System Settings ───────────────────────────────────────────────────────
  getSettings: () => request('/settings'),
  updateSettings: (data) => request('/settings', { method: 'POST', body: JSON.stringify(data) }),
};
