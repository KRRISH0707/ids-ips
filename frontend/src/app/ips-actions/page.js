'use client';

import { useState, useEffect, useCallback, useRef, useMemo } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner, EmptyState, Pagination } from '@/components/ui';
import { api, getUser } from '@/lib/api';
import { useLiveFeed } from '@/lib/useLiveFeed';
import {
  ResponsiveContainer, AreaChart, Area, PieChart, Pie, Cell, Tooltip, Legend, XAxis, YAxis, CartesianGrid
} from 'recharts';

const TRIGGER_COLORS = {
  'Autonomous DPI Trigger': '#ef4444',
  'C2 Beaconing Pattern': '#f59e0b',
  'SSH / Credential Abuse': '#00d4ff',
  'Port Scanning / Recon': '#8b5cf6',
  'Manual Analyst Rule': '#10b981',
};

const TIMELINE_DATA = [
  { time: '00:00', activeDrops: 14, autoEnforced: 12 },
  { time: '04:00', activeDrops: 19, autoEnforced: 18 },
  { time: '08:00', activeDrops: 32, autoEnforced: 30 },
  { time: '12:00', activeDrops: 45, autoEnforced: 43 },
  { time: '16:00', activeDrops: 38, autoEnforced: 35 },
  { time: '20:00', activeDrops: 28, autoEnforced: 27 },
  { time: '24:00', activeDrops: 22, autoEnforced: 20 },
];

import { useTimeRange } from '@/context/TimeRangeContext';

function CustomPieTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    const color = data.payload?.color || data.color || '#00d4ff';
    const name = data.name || data.payload?.name || 'Trigger Category';
    const value = data.value ?? data.payload?.value ?? 0;
    return (
      <div style={{
        background: 'rgba(6, 13, 24, 0.96)',
        border: `1px solid ${color}`,
        borderRadius: 8,
        padding: '8px 12px',
        boxShadow: `0 8px 24px rgba(0, 0, 0, 0.8), 0 0 12px ${color}44`,
        pointerEvents: 'none',
        zIndex: 9999,
        minWidth: 150
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
          <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc' }}>{name}</span>
        </div>
        <div style={{ fontSize: '1rem', fontWeight: 900, color, fontFamily: 'monospace' }}>
          {value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>quarantines</span>
        </div>
      </div>
    );
  }
  return null;
}

function CustomAreaTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div style={{
        background: 'rgba(6, 13, 24, 0.96)',
        border: '1px solid rgba(239, 68, 68, 0.4)',
        borderRadius: 8,
        padding: '8px 12px',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.8)',
        pointerEvents: 'none',
        zIndex: 9999
      }}>
        <div style={{ fontSize: '0.76rem', fontWeight: 700, color: '#94a3b8', marginBottom: 4 }}>
          {label}
        </div>
        {payload.map((item, idx) => (
          <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: '0.8rem', color: item.color || '#fff', marginTop: 2 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: item.color }} />
            <span>{item.name}: <strong style={{ color: '#fff' }}>{item.value}</strong></span>
          </div>
        ))}
      </div>
    );
  }
  return null;
}

export default function IPSActionsPage() {
  const { days, dateSpanText } = useTimeRange();
  const currentUser = getUser();
  const isViewer = currentUser?.role === 'VIEWER';

  const [blockedIPs, setBlockedIPs] = useState([]);
  const [velocityData, setVelocityData] = useState([]);
  const [loading, setLoading] = useState(!isViewer);
  const [error, setError] = useState(null);
  const [showModal, setShowModal] = useState(false);
  const [formData, setFormData] = useState({ target: '', reason: '', duration_minutes: 60 });
  const [lastSyncTime, setLastSyncTime] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedIp, setCopiedIp] = useState(null);
  const [showAnalytics, setShowAnalytics] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const { messages: liveMessages } = useLiveFeed(20);
  const isFirstLoad = useRef(true);

  // Reset pagination on filter or timeframe change
  useEffect(() => {
    setCurrentPage(1);
  }, [statusFilter, searchQuery, days, pageSize]);

  const fetchBlockedIPs = useCallback(async (isSilent = false) => {
    if (isViewer) return;
    try {
      if (!isSilent && isFirstLoad.current) {
        setLoading(true);
      }
      const [res, tl] = await Promise.allSettled([
        api.getBlockedIPs({ days: days || undefined, limit: 500 }),
        api.getIPSTimeline({ days: days || 45 }),
      ]);
      if (res.status === 'fulfilled') {
        const items = res.value?.items || res.value?.data || (Array.isArray(res.value) ? res.value : []);
        setBlockedIPs(items);
      }
      if (tl.status === 'fulfilled' && tl.value?.items?.length > 0) {
        setVelocityData(tl.value.items);
      }
      setLastSyncTime(new Date());
      setError(null);
    } catch (err) {
      setError(err.message || 'Failed to fetch blocked IPs');
    } finally {
      if (!isSilent && isFirstLoad.current) {
        setLoading(false);
        isFirstLoad.current = false;
      }
    }
  }, [isViewer, days]);

  // Initial load
  useEffect(() => {
    if (!isViewer) {
      fetchBlockedIPs(false);
    }
  }, [fetchBlockedIPs, isViewer]);

  // Real-time WebSocket Auto-Update Handler
  useEffect(() => {
    if (!liveMessages || liveMessages.length === 0 || isViewer) return;
    fetchBlockedIPs(true);
  }, [liveMessages, fetchBlockedIPs, isViewer]);

  // Background auto-sync every 3 seconds
  useEffect(() => {
    if (isViewer) return;
    const timer = setInterval(() => {
      fetchBlockedIPs(true);
    }, 3000);
    return () => clearInterval(timer);
  }, [fetchBlockedIPs, isViewer]);

  const handleCopyIp = (ip) => {
    if (!ip) return;
    navigator.clipboard.writeText(ip);
    setCopiedIp(ip);
    setTimeout(() => setCopiedIp(null), 1800);
  };

  const handleBlock = async (e) => {
    e.preventDefault();
    try {
      await api.blockIP(formData);
      setShowModal(false);
      setFormData({ target: '', reason: '', duration_minutes: 60 });
      fetchBlockedIPs(false);
    } catch (err) {
      alert(`Block operation failed: ${err.message}`);
    }
  };

  const handleUnblock = async (id) => {
    if (!confirm(`Are you sure you want to unblock this item?`)) return;
    try {
      await api.unblockIP(id, 'Manual Analyst Unblock');
      fetchBlockedIPs(true);
    } catch (err) {
      alert(`Unblock operation failed: ${err.message}`);
    }
  };

  // Metrics calculations
  const totalBlocks = blockedIPs.length;
  const activeBlocks = blockedIPs.filter(b => b.is_active !== false && b.status !== 'LIFTED').length;
  const liftedBlocks = totalBlocks - activeBlocks;
  const autoDrops = blockedIPs.filter(b => (b.reason || '').toLowerCase().includes('autonomous') || (b.reason || '').toLowerCase().includes('threat')).length;

  // Chart Data: Trigger Reason Categories
  const triggerChartData = useMemo(() => {
    const categories = {
      'Autonomous DPI Trigger': 0,
      'C2 Beaconing Pattern': 0,
      'SSH / Credential Abuse': 0,
      'Port Scanning / Recon': 0,
      'Manual Analyst Rule': 0,
    };

    blockedIPs.forEach(item => {
      const r = (item.reason || '').toLowerCase();
      if (r.includes('c2') || r.includes('beacon') || r.includes('trojan')) categories['C2 Beaconing Pattern']++;
      else if (r.includes('ssh') || r.includes('brute') || r.includes('auth')) categories['SSH / Credential Abuse']++;
      else if (r.includes('scan') || r.includes('recon') || r.includes('probe')) categories['Port Scanning / Recon']++;
      else if (r.includes('manual') || r.includes('analyst')) categories['Manual Analyst Rule']++;
      else categories['Autonomous DPI Trigger']++;
    });

    return Object.entries(categories)
      .filter(([_, count]) => count > 0)
      .map(([name, value]) => ({
        name,
        value,
        color: TRIGGER_COLORS[name] || '#00d4ff'
      }));
  }, [blockedIPs]);

  // Filtered entries
  const filteredList = useMemo(() => {
    return blockedIPs.filter((entry) => {
      const isActive = entry.is_active !== false && entry.status !== 'LIFTED';
      if (statusFilter === 'ACTIVE' && !isActive) return false;
      if (statusFilter === 'LIFTED' && isActive) return false;

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const target = (entry.target || entry.ip_address || '').toLowerCase();
        const reason = (entry.reason || '').toLowerCase();
        if (!target.includes(q) && !reason.includes(q)) return false;
      }
      return true;
    });
  }, [blockedIPs, statusFilter, searchQuery]);

  // Paginated slice
  const paginatedList = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredList.slice(start, start + pageSize);
  }, [filteredList, currentPage, pageSize]);

  return (
    <PageLayout sidebar={<Sidebar />}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <h1 className="page-title glow-text" style={{ margin: 0 }}>IPS Active Mitigation</h1>
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                fontSize: '0.72rem',
                fontWeight: 700,
                color: '#10b981',
                background: 'rgba(16,185,129,0.12)',
                padding: '4px 10px',
                borderRadius: 20,
                border: '1px solid rgba(16,185,129,0.3)',
                letterSpacing: '0.04em'
              }}
            >
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#10b981', boxShadow: '0 0 8px #10b981' }} />
              KERNEL ENFORCEMENT LIVE
            </span>
          </div>
          <p className="page-subtitle" style={{ margin: '4px 0 0' }}>
            Autonomous eBPF packet-filtering engine & dynamic firewall blocklist registry ({activeBlocks} active drops)
          </p>
        </div>

        {!isViewer && (
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <button
              className="btn btn-ghost btn-sm"
              onClick={() => setShowAnalytics(!showAnalytics)}
              style={{ display: 'flex', alignItems: 'center', gap: 6 }}
              title="Toggle quarantine analytics graphs"
            >
              <span>📊</span>
              <span>{showAnalytics ? 'Hide Analytics' : 'Show Analytics'}</span>
            </button>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => fetchBlockedIPs(false)}
              title="Manual Sync"
              style={{ fontSize: '0.78rem' }}
            >
              🔄 Refresh
            </button>
            <button className="btn btn-danger btn-sm" onClick={() => setShowModal(true)} style={{ fontSize: '0.78rem' }}>
              🛡️ Block IP Address
            </button>
          </div>
        )}
      </div>

      {/* Enterprise Operations Metric Ribbon */}
      <div className="enterprise-soc-ribbon">
        <div
          className="metric-card-enterprise"
          onClick={() => setStatusFilter(statusFilter === 'ACTIVE' ? 'ALL' : 'ACTIVE')}
          style={{ cursor: 'pointer' }}
          title="Click to filter by active quarantine drops"
        >
          <div className="metric-label">Active Quarantine Drops</div>
          <div className="metric-value" style={{ color: activeBlocks > 0 ? '#ef4444' : 'var(--text-primary)' }}>
            {activeBlocks}
          </div>
          <div className="metric-subtext">Actively dropped at network edge (click to filter)</div>
        </div>

        <div className="metric-card-enterprise">
          <div className="metric-label">Autonomous Heuristic Drops</div>
          <div className="metric-value" style={{ color: '#00d4ff' }}>
            {autoDrops}
          </div>
          <div className="metric-subtext">Triggered automatically by DPI signature correlation</div>
        </div>

        <div className="metric-card-enterprise">
          <div className="metric-label">Enforcement Latency</div>
          <div className="metric-value" style={{ color: '#10b981' }}>
            &lt; 1.2ms
          </div>
          <div className="metric-subtext">Kernel-level eBPF mitigation overhead</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => setStatusFilter(statusFilter === 'LIFTED' ? 'ALL' : 'LIFTED')}
          style={{ cursor: 'pointer' }}
          title="Click to filter by lifted rules"
        >
          <div className="metric-label">Decommissioned / Lifted</div>
          <div className="metric-value" style={{ color: 'var(--text-secondary)' }}>
            {liftedBlocks}
          </div>
          <div className="metric-subtext">Expired TTL or analyst-approved unblocks (click to filter)</div>
        </div>
      </div>

      {/* Visual Analytics Graphs Section */}
      {!isViewer && showAnalytics && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20, marginBottom: 20 }}>
          {/* Mitigation Velocity AreaChart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Mitigation Velocity & Ingress Drops
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Autonomous edge drop volume ({dateSpanText})
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#ef4444', fontWeight: 700, background: 'rgba(239,68,68,0.12)', padding: '2px 8px', borderRadius: 10 }}>
                eBPF RATE
              </span>
            </div>

            <div style={{ width: '100%', height: 210 }}>
              <ResponsiveContainer width="100%" height={210}>
                <AreaChart data={velocityData} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
                  <defs>
                    <linearGradient id="dropsGradient" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                  <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                  <Tooltip content={<CustomAreaTooltip />} />
                  <Area type="monotone" dataKey="activeDrops" stroke="#ef4444" strokeWidth={2} fillOpacity={1} fill="url(#dropsGradient)" name="Active Drop Rules" />
                  <Area type="monotone" dataKey="autoEnforced" stroke="#10b981" strokeWidth={2} fillOpacity={0} name="Auto Enforced" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Trigger Category Donut Chart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Quarantine Trigger Classification
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Distribution of attack vectors mitigated ({dateSpanText})
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#00d4ff', fontWeight: 700, background: 'rgba(0,212,255,0.12)', padding: '2px 8px', borderRadius: 10 }}>
                VECTOR BREAKDOWN
              </span>
            </div>

            {triggerChartData.length > 0 ? (
              <div style={{ width: '100%', height: 210 }}>
                <ResponsiveContainer width="100%" height={210}>
                  <PieChart>
                    <Pie
                      data={triggerChartData}
                      nameKey="name"
                      dataKey="value"
                      cx="50%"
                      cy="48%"
                      innerRadius={46}
                      outerRadius={72}
                      paddingAngle={4}
                      isAnimationActive={false}
                      onClick={(entry) => setSearchQuery(entry.name.split(' ')[0])}
                      cursor="pointer"
                    >
                      {triggerChartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} stroke="transparent" />
                      ))}
                    </Pie>
                    <Tooltip
                      content={<CustomPieTooltip />}
                      wrapperStyle={{ zIndex: 9999, pointerEvents: 'none' }}
                    />
                    <Legend
                      iconType="circle"
                      iconSize={8}
                      wrapperStyle={{ fontSize: '0.74rem', color: 'var(--text-secondary)', paddingTop: 4 }}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <EmptyState message="No active quarantine trigger records" />
            )}
          </div>
        </div>
      )}

      <div className="page-body">
        {isViewer ? (
          <div className="glass-card" style={{ padding: 40, textAlign: 'center', border: '1px solid rgba(239, 68, 68, 0.3)' }}>
            <div style={{ width: 56, height: 56, borderRadius: '50%', background: 'rgba(239, 68, 68, 0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px', color: '#ef4444' }}>
              <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
              IPS Controls Restricted
            </h3>
            <p style={{ fontSize: '0.9rem', color: 'var(--text-secondary)', maxWidth: 480, margin: '0 auto 16px', lineHeight: 1.6 }}>
              Your active role is <span style={{ color: '#94a3b8', fontWeight: 600 }}>VIEWER</span>. In accordance with the SOC Two-Layer Defense Matrix, active IPS firewall mitigation and IP blocklist controls require <span style={{ color: '#00d4ff', fontWeight: 600 }}>ANALYST</span> or <span style={{ color: '#a855f7', fontWeight: 600 }}>ADMIN</span> privileges.
            </p>
            <div style={{ display: 'inline-flex', gap: 12, fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              <span>👁️ Viewers have read-only telemetry privileges on Alerts and Incidents.</span>
            </div>
          </div>
        ) : loading ? (
          <Spinner />
        ) : error ? (
          <div className="glass-card" style={{ color: 'var(--sev-critical)', padding: 20 }}>
            {error}
          </div>
        ) : (
          <>
            {/* Filter Toolbar */}
            <div className="glass-card" style={{ padding: '14px 20px', marginBottom: 20, display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
              <div className="workspace-nav-bar" style={{ margin: 0, padding: 3 }}>
                {[
                  { key: 'ALL', label: `All Rules (${totalBlocks})` },
                  { key: 'ACTIVE', label: `Active (${activeBlocks})` },
                  { key: 'LIFTED', label: `Lifted (${liftedBlocks})` },
                ].map((tab) => (
                  <button
                    key={tab.key}
                    className={`workspace-tab-btn ${statusFilter === tab.key ? 'active' : ''}`}
                    onClick={() => setStatusFilter(tab.key)}
                    style={{ padding: '5px 12px', fontSize: '0.78rem' }}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              <div style={{ flex: 1, minWidth: 220 }}>
                <input
                  type="text"
                  className="input"
                  placeholder="Filter by target IP or trigger reason..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{ width: '100%', fontSize: '0.82rem', padding: '6px 12px' }}
                />
              </div>

              {(statusFilter !== 'ALL' || searchQuery) && (
                <button
                  className="btn btn-ghost btn-sm"
                  onClick={() => { setStatusFilter('ALL'); setSearchQuery(''); }}
                  style={{ fontSize: '0.75rem' }}
                >
                  Clear Filters
                </button>
              )}

              <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginLeft: 'auto', whiteSpace: 'nowrap' }}>
                Showing {filteredList.length} of {totalBlocks} rules
              </span>
            </div>

            {/* Table */}
            {filteredList.length === 0 ? (
              <EmptyState message={searchQuery || statusFilter !== 'ALL' ? 'No blocklist entries match your filter criteria' : 'No active IP blocks in firewall registry'} />
            ) : (
              <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
                <div className="table-wrapper">
                  <table className="data-table" style={{ tableLayout: 'fixed', width: '100%', minWidth: 1060 }}>
                    <colgroup>
                      <col style={{ width: '20%' }} />
                      <col style={{ width: '12%' }} />
                      <col style={{ width: '32%' }} />
                      <col style={{ width: '12%' }} />
                      <col style={{ width: '12%' }} />
                      <col style={{ width: '12%' }} />
                    </colgroup>
                    <thead>
                      <tr>
                        <th>Target IP / Subnet</th>
                        <th>Kernel Verdict</th>
                        <th>Mitigation Reason & Rule</th>
                        <th>Enforcement</th>
                        <th>Timestamp</th>
                        <th className="sticky-col-right" style={{ textAlign: 'right', paddingRight: 16 }}>Controls</th>
                      </tr>
                    </thead>
                    <tbody>
                      {paginatedList.map((entry) => {
                        const isActive = entry.is_active !== false && entry.status !== 'LIFTED';
                        const displayStatus = entry.status || (isActive ? 'APPLIED' : 'LIFTED');
                        const displayAction = entry.action || (isActive ? 'DROP' : 'UNBLOCK');
                        const timestamp = entry.created_at || entry.blocked_at;
                        const ipText = entry.target || entry.ip_address || '—';

                        return (
                          <tr key={entry.id}>
                            <td>
                              <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}>
                                <span style={{ fontFamily: 'monospace', fontWeight: 700, color: 'var(--sev-critical)', fontSize: '0.85rem' }}>
                                  {ipText}
                                </span>
                                <button
                                  onClick={() => handleCopyIp(ipText)}
                                  title="Copy IP Address"
                                  style={{
                                    background: 'transparent',
                                    border: 'none',
                                    cursor: 'pointer',
                                    padding: '2px 4px',
                                    fontSize: '0.78rem',
                                    color: copiedIp === ipText ? '#10b981' : 'var(--text-muted)',
                                    display: 'inline-flex',
                                    alignItems: 'center'
                                  }}
                                >
                                  {copiedIp === ipText ? '✓' : '📋'}
                                </button>
                              </div>
                            </td>
                            <td>
                              <span style={{
                                fontFamily: 'monospace',
                                fontSize: '0.74rem',
                                fontWeight: 700,
                                background: isActive ? 'rgba(239,68,68,0.15)' : 'rgba(16,185,129,0.15)',
                                color: isActive ? '#f87171' : '#34d399',
                                padding: '3px 8px',
                                borderRadius: 4,
                                border: `1px solid ${isActive ? 'rgba(239,68,68,0.3)' : 'rgba(16,185,129,0.3)'}`,
                                letterSpacing: '0.04em',
                                display: 'inline-block',
                                whiteSpace: 'nowrap'
                              }}>
                                {displayAction}
                              </span>
                            </td>
                            <td>
                              <div
                                style={{
                                  fontSize: '0.84rem',
                                  color: 'var(--text-primary)',
                                  overflow: 'hidden',
                                  textOverflow: 'ellipsis',
                                  whiteSpace: 'nowrap'
                                }}
                                title={entry.reason || 'Autonomous Threat Mitigation Rule'}
                              >
                                {entry.reason || 'Autonomous Threat Mitigation Rule'}
                              </div>
                            </td>
                            <td>
                              <span
                                className={`badge ${isActive ? 'badge-applied' : 'badge-lifted'}`}
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: 6,
                                  fontSize: '0.72rem',
                                  fontWeight: 700,
                                  padding: '3px 8px',
                                  borderRadius: 6,
                                  whiteSpace: 'nowrap'
                                }}
                              >
                                <span style={{
                                  width: 6,
                                  height: 6,
                                  borderRadius: '50%',
                                  background: isActive ? '#ef4444' : '#10b981',
                                  boxShadow: isActive ? '0 0 6px #ef4444' : '0 0 6px #10b981'
                                }} />
                                {displayStatus}
                              </span>
                            </td>
                            <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                              {timestamp ? new Date(timestamp).toLocaleString() : 'Just now'}
                            </td>
                            <td className="sticky-col-right" style={{ textAlign: 'right', paddingRight: 16 }}>
                              {isActive ? (
                                <button
                                  className="btn btn-ghost btn-sm"
                                  style={{
                                    color: 'var(--sev-critical)',
                                    padding: '3px 10px',
                                    fontSize: '0.75rem',
                                    border: '1px solid rgba(239, 68, 68, 0.3)',
                                    borderRadius: 4,
                                    background: 'rgba(239, 68, 68, 0.08)',
                                    whiteSpace: 'nowrap'
                                  }}
                                  onClick={() => handleUnblock(entry.id)}
                                >
                                  🔓 Unblock
                                </button>
                              ) : (
                                <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>LIFTED</span>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* Pagination Controls */}
            <Pagination
              currentPage={currentPage}
              pageSize={pageSize}
              totalItems={filteredList.length}
              label="blocked IPs & mitigations"
              loading={loading}
              onPageChange={(page) => setCurrentPage(page)}
              onPageSizeChange={(newSize) => {
                setPageSize(newSize);
                setCurrentPage(1);
              }}
            />
          </>
        )}
      </div>

      {/* Modal to Block IP - Centered */}
      {showModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0,0,0,0.75)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 9999,
            padding: 20
          }}
          onClick={() => setShowModal(false)}
        >
          <div
            className="glass-card"
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '100%',
              maxWidth: 480,
              padding: 28,
              border: '1px solid var(--border-glow)',
              boxShadow: '0 24px 60px rgba(0,0,0,0.8)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  🛡️ Enforce IP Quarantine Block
                </h3>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  Deploy instant kernel-level drop rule across all sensor nodes
                </span>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setShowModal(false)}
                style={{ fontSize: '1.1rem', padding: '4px 8px' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleBlock}>
              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Target IP or CIDR Subnet
                </label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. 198.51.100.42 or 10.240.0.0/16"
                  value={formData.target}
                  onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                  style={{ fontSize: '0.86rem', fontFamily: 'monospace' }}
                />
              </div>

              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Mitigation Reason / Ticket Ref
                </label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. Rapid C2 beaconing / Brute Force attempt detected"
                  value={formData.reason}
                  onChange={(e) => setFormData({ ...formData, reason: e.target.value })}
                  style={{ fontSize: '0.86rem' }}
                />
              </div>

              <div style={{ marginBottom: 20 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Quarantine Duration
                </label>
                <select
                  className="select"
                  value={formData.duration_minutes}
                  onChange={(e) => setFormData({ ...formData, duration_minutes: Number(e.target.value) })}
                  style={{ width: '100%', fontSize: '0.86rem' }}
                >
                  <option value={15}>15 Minutes (Temporary Quarantine)</option>
                  <option value={60}>1 Hour (Standard Investigation)</option>
                  <option value={1440}>24 Hours (Prolonged Threat Containment)</option>
                  <option value={0}>Permanent Block (Zero TTL)</option>
                </select>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => setShowModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-danger btn-sm" style={{ padding: '6px 16px' }}>
                  Enforce Immediate Drop
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
