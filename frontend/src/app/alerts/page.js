'use client';

import { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import Sidebar from '@/components/Sidebar';
import PCAPViewerModal from '@/components/PCAPViewerModal';
import { PageLayout, SeverityBadge, StatusBadge, Spinner, EmptyState, Pagination } from '@/components/ui';
import { api } from '@/lib/api';
import { useLiveFeed } from '@/lib/useLiveFeed';
import { exportToCSV, formatRelativeTime } from '@/lib/utils';
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';

const STATUSES = ['', 'OPEN', 'AUTO_BLOCKED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'];
const SEVERITIES = ['', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const SEV_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981'
};

const STATUS_COLORS = {
  OPEN: '#f59e0b',
  AUTO_BLOCKED: '#00d4ff',
  INVESTIGATING: '#a855f7',
  RESOLVED: '#10b981',
  FALSE_POSITIVE: '#64748b'
};

import { useTimeRange } from '@/context/TimeRangeContext';

function CustomPieTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    const color = data.payload?.color || data.color || '#ef4444';
    const name = data.name || data.payload?.name || 'Severity';
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
        minWidth: 140
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 6px ${color}` }} />
          <span style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc' }}>{name}</span>
        </div>
        <div style={{ fontSize: '1rem', fontWeight: 900, color, fontFamily: 'monospace' }}>
          {value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>threat alerts</span>
        </div>
      </div>
    );
  }
  return null;
}

function CustomBarTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    const fill = data.payload?.fill || data.color || '#38bdf8';
    return (
      <div style={{
        background: 'rgba(6, 13, 24, 0.96)',
        border: `1px solid ${fill}`,
        borderRadius: 8,
        padding: '8px 12px',
        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.8)',
        pointerEvents: 'none',
        zIndex: 9999
      }}>
        <div style={{ fontSize: '0.78rem', fontWeight: 700, color: '#f8fafc', marginBottom: 2 }}>
          {label || data.name}
        </div>
        <div style={{ fontSize: '0.95rem', fontWeight: 800, color: fill, fontFamily: 'monospace' }}>
          {data.value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>alerts</span>
        </div>
      </div>
    );
  }
  return null;
}

export default function AlertsPage() {
  const { days, dateSpanText } = useTimeRange();
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [batchResolving, setBatchResolving] = useState(false);
  const [severity, setSeverity] = useState('');
  const [alertStatus, setAlertStatus] = useState('');
  const [searchFilter, setSearchFilter] = useState('');
  const [selectedAlertForPCAP, setSelectedAlertForPCAP] = useState(null);
  const [showAnalytics, setShowAnalytics] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const tableWrapperRef = useRef(null);
  const lastProcessedLiveIdRef = useRef(null);

  // Reset pagination to page 1 whenever filters or time range change
  useEffect(() => {
    setCurrentPage(1);
  }, [severity, alertStatus, days, searchFilter, pageSize]);

  const scrollTable = (direction) => {
    if (tableWrapperRef.current) {
      tableWrapperRef.current.scrollBy({
        left: direction === 'left' ? -380 : 380,
        behavior: 'smooth'
      });
    }
  };

  const { messages: liveMessages } = useLiveFeed(20);

  const load = useCallback(async (showSpinner = true) => {
    if (showSpinner) setLoading(true);
    try {
      const params = { limit: 1000 };
      if (severity) params.severity = severity;
      if (alertStatus) params.status = alertStatus;
      if (days) params.days = days;
      const data = await api.getAlerts(params);
      setAlerts(data?.items || []);
      setTotal(data?.total || (data?.items?.length || 0));
    } catch (e) {
      console.error('Failed to load alerts:', e);
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [severity, alertStatus, days]);

  useEffect(() => { load(true); }, [load]);

  // Real-time WebSocket Auto-Update Handler: Instantly prepend new alert to table without breaking active page
  useEffect(() => {
    if (!liveMessages || liveMessages.length === 0) return;
    const latest = liveMessages[0];
    if (!latest || !latest.signature || !latest.id) return;
    if (lastProcessedLiveIdRef.current === latest.id) return;
    lastProcessedLiveIdRef.current = latest.id;

    setAlerts((prev) => {
      if (prev.some((a) => a.id === latest.id)) return prev;
      return [latest, ...prev];
    });
    setTotal((prev) => prev + 1);
  }, [liveMessages]);

  const handleStatusChange = async (id, newStatus) => {
    try {
      await api.updateAlertStatus(id, newStatus);
      load(false);
    } catch (e) {
      alert(e.message);
    }
  };

  const handleBatchResolve = async (flag) => {
    try {
      setBatchResolving(true);
      const payload = flag === 'OPEN' ? { resolve_all_open: true } : { resolve_all_blocked: true };
      await api.batchResolveAlerts(payload);
      load(false);
    } catch (e) {
      alert(e.message);
    } finally {
      setBatchResolving(false);
    }
  };

  // Filtered slice across all loaded alerts in the timeframe
  const displayedAlerts = useMemo(() => {
    if (!searchFilter.trim()) return alerts;
    const q = searchFilter.toLowerCase();
    return alerts.filter(a =>
      (a.signature || '').toLowerCase().includes(q) ||
      (a.src_ip || '').toLowerCase().includes(q) ||
      (a.dst_ip || '').toLowerCase().includes(q) ||
      (a.category || '').toLowerCase().includes(q)
    );
  }, [alerts, searchFilter]);

  // Paginated slice for current page
  const paginatedAlerts = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return displayedAlerts.slice(start, start + pageSize);
  }, [displayedAlerts, currentPage, pageSize]);

  // Metrics
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const autoBlockedCount = alerts.filter(a => a.status === 'AUTO_BLOCKED').length;
  const avgRisk = alerts.length > 0
    ? Math.round(alerts.reduce((acc, a) => acc + (a.risk_score || 0), 0) / alerts.length)
    : 0;

  // Chart: Severity Donut
  const severityChartData = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    alerts.forEach(a => {
      if (counts[a.severity] !== undefined) counts[a.severity]++;
    });
    return Object.entries(counts)
      .filter(([_, val]) => val > 0)
      .map(([name, value]) => ({
        name,
        value,
        color: SEV_COLORS[name] || '#38bdf8'
      }));
  }, [alerts]);

  // Chart: Status Breakdown
  const statusChartData = useMemo(() => {
    const counts = { OPEN: 0, AUTO_BLOCKED: 0, INVESTIGATING: 0, RESOLVED: 0, FALSE_POSITIVE: 0 };
    alerts.forEach(a => {
      if (counts[a.status] !== undefined) counts[a.status]++;
    });
    return Object.entries(counts).map(([name, count]) => ({
      name: name.replace(/_/g, ' '),
      rawKey: name,
      count,
      fill: STATUS_COLORS[name] || '#38bdf8'
    }));
  }, [alerts]);

  return (
    <PageLayout sidebar={<Sidebar />}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <h1 className="page-title glow-text" style={{ margin: 0 }}>Alerts Queue</h1>
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
              STREAM INGESTION LIVE
            </span>
          </div>
          <p className="page-subtitle" style={{ margin: '4px 0 0' }}>
            Real-time correlated telemetry stream from DPI heuristics and autonomous IPS kernel enforcement
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setShowAnalytics(!showAnalytics)}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            title="Toggle alert telemetry graphs"
          >
            <span>📊</span>
            <span>{showAnalytics ? 'Hide Analytics' : 'Show Analytics'}</span>
          </button>
          <button
            className="btn-export"
            onClick={() => exportToCSV(
              displayedAlerts,
              ['timestamp','severity','status','signature','src_ip','src_port','dst_ip','dst_port','protocol','category','risk_score'],
              ['Timestamp','Severity','Status','Signature','Src IP','Src Port','Dst IP','Dst Port','Protocol','Category','Risk Score'],
              `alerts_export_${new Date().toISOString().slice(0,10)}.csv`
            )}
            title="Export visible alerts to CSV"
          >
            ⬇ Export CSV
          </button>
          <button className="btn btn-secondary btn-sm" onClick={() => load(true)}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Enterprise Operations Metric Ribbon */}
      <div className="enterprise-soc-ribbon">
        <div className="metric-card-enterprise">
          <div className="metric-label">Ingress Alert Volume</div>
          <div className="metric-value" style={{ color: 'var(--text-primary)' }}>
            {total}
          </div>
          <div className="metric-subtext">Total alerts recorded in telemetry warehouse</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => { setSeverity(severity === 'CRITICAL' ? '' : 'CRITICAL'); setSkip(0); }}
          style={{ cursor: 'pointer' }}
          title="Click to filter by Critical severity"
        >
          <div className="metric-label">Critical Tier Queue</div>
          <div className="metric-value" style={{ color: criticalCount > 0 ? '#ef4444' : 'var(--text-primary)' }}>
            {criticalCount}
          </div>
          <div className="metric-subtext">Requires immediate analyst triage (click to filter)</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => { setAlertStatus(alertStatus === 'AUTO_BLOCKED' ? '' : 'AUTO_BLOCKED'); setSkip(0); }}
          style={{ cursor: 'pointer' }}
          title="Click to filter by auto-quarantined threats"
        >
          <div className="metric-label">Autonomous Quarantines</div>
          <div className="metric-value" style={{ color: '#00d4ff' }}>
            {autoBlockedCount}
          </div>
          <div className="metric-subtext">Auto-neutralized at edge via IPS (click to filter)</div>
        </div>

        <div className="metric-card-enterprise">
          <div className="metric-label">Correlated Risk Index</div>
          <div className="metric-value" style={{ color: avgRisk >= 70 ? '#f59e0b' : '#10b981' }}>
            {avgRisk}/100
          </div>
          <div className="metric-subtext">Average threat severity across active sample</div>
        </div>
      </div>

      {/* Visual Analytics Graphs */}
      {showAnalytics && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20, marginBottom: 20 }}>
          {/* Severity Donut Chart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Severity Classification Ratio
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Threat ratio categorized by impact level
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#f87171', fontWeight: 700, background: 'rgba(239, 68, 68, 0.12)', padding: '2px 8px', borderRadius: 10 }}>
                RISK MATRIX
              </span>
            </div>

            {severityChartData.length > 0 ? (
              <div style={{ width: '100%', height: 210 }}>
                <ResponsiveContainer width="100%" height={210}>
                  <PieChart>
                    <Pie
                      data={severityChartData}
                      nameKey="name"
                      dataKey="value"
                      cx="50%"
                      cy="48%"
                      innerRadius={44}
                      outerRadius={74}
                      paddingAngle={4}
                      isAnimationActive={false}
                      onClick={(entry) => { setSeverity(entry.name); setSkip(0); }}
                      cursor="pointer"
                    >
                      {severityChartData.map((entry, index) => (
                        <Cell key={`sev-${index}`} fill={entry.color} stroke="transparent" />
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
              <EmptyState message="No alert severity telemetry" />
            )}
          </div>

          {/* Status Breakdown Bar Chart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Lifecycle Status Breakdown
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Active queue distribution across mitigation states
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 700, background: 'rgba(16, 185, 129, 0.12)', padding: '2px 8px', borderRadius: 10 }}>
                QUEUED
              </span>
            </div>

            <div style={{ width: '100%', height: 210 }}>
              <ResponsiveContainer width="100%" height={210}>
                <BarChart data={statusChartData} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="name" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                  <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                  <Tooltip
                    content={<CustomBarTooltip />}
                    wrapperStyle={{ zIndex: 9999, pointerEvents: 'none' }}
                  />
                  <Bar
                    dataKey="count"
                    radius={[4, 4, 0, 0]}
                    isAnimationActive={false}
                    cursor="pointer"
                    onClick={(entry) => { setAlertStatus(entry.rawKey); setSkip(0); }}
                  >
                    {statusChartData.map((entry, index) => (
                      <Cell key={`bar-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Filters & Actions Toolbar */}
      <div className="glass-card" style={{ padding: '14px 20px', marginBottom: 20, display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
        <input
          type="text"
          className="input"
          placeholder="Filter by signature or IP..."
          value={searchFilter}
          onChange={e => setSearchFilter(e.target.value)}
          style={{ width: 220, fontSize: '0.82rem', padding: '6px 12px' }}
        />

        <select
          id="filter-severity"
          className="select"
          style={{ width: 150, fontSize: '0.82rem' }}
          value={severity}
          onChange={e => { setSeverity(e.target.value); setSkip(0); }}
        >
          {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All Severities'}</option>)}
        </select>

        <select
          id="filter-status"
          className="select"
          style={{ width: 160, fontSize: '0.82rem' }}
          value={alertStatus}
          onChange={e => { setAlertStatus(e.target.value); setSkip(0); }}
        >
          {STATUSES.map(s => <option key={s} value={s}>{s ? s.replace(/_/g, ' ') : 'All Statuses'}</option>)}
        </select>

        {(severity || alertStatus || searchFilter) && (
          <button className="btn btn-ghost btn-sm" onClick={() => { setSeverity(''); setAlertStatus(''); setSearchFilter(''); setSkip(0); }}>
            Clear Filters
          </button>
        )}

        <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginLeft: 'auto', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => scrollTable('left')}
              title="Pan table left"
              style={{ fontSize: '0.75rem', padding: '5px 10px', border: '1px solid var(--border-subtle)', background: 'rgba(255,255,255,0.04)' }}
            >
              ◀ Scroll Left
            </button>
            <button
              type="button"
              className="btn btn-ghost btn-sm"
              onClick={() => scrollTable('right')}
              title="Pan table right"
              style={{ fontSize: '0.75rem', padding: '5px 10px', border: '1px solid var(--border-subtle)', background: 'rgba(255,255,255,0.04)' }}
            >
              Scroll Right ▶
            </button>
          </div>

          <button
            className="btn btn-sm"
            disabled={batchResolving}
            style={{
              background: 'rgba(16, 185, 129, 0.12)',
              color: 'var(--accent-green)',
              border: '1px solid rgba(16, 185, 129, 0.3)',
              fontSize: '0.75rem',
              padding: '5px 12px',
            }}
            onClick={() => handleBatchResolve('OPEN')}
            title="Batch resolve all OPEN alerts"
          >
            ✓ Resolve All Open
          </button>
          <button
            className="btn btn-sm"
            disabled={batchResolving}
            style={{
              background: 'rgba(124, 58, 237, 0.12)',
              color: 'var(--accent-purple)',
              border: '1px solid rgba(124, 58, 237, 0.3)',
              fontSize: '0.75rem',
              padding: '5px 12px',
            }}
            onClick={() => handleBatchResolve('BLOCKED')}
            title="Batch resolve all AUTO_BLOCKED threats"
          >
            🛡️ Resolve All Quarantined
          </button>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginLeft: 8, whiteSpace: 'nowrap' }}>
            Showing {displayedAlerts.length === 0 ? 0 : (currentPage - 1) * pageSize + 1}–{Math.min(currentPage * pageSize, displayedAlerts.length)} of {displayedAlerts.length}
          </span>
        </div>
      </div>

      {/* Alerts Table with Guaranteed Text Bounding & Sticky Right Action Column */}
      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : displayedAlerts.length === 0 ? (
          <EmptyState message="No alerts match your search or filter criteria" />
        ) : (
          <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-wrapper" ref={tableWrapperRef}>
              <table className="data-table" style={{ tableLayout: 'fixed', width: '100%', minWidth: 1400 }}>
                <colgroup>
                  <col style={{ width: '23%' }} />
                  <col style={{ width: '15%' }} />
                  <col style={{ width: '9%' }} />
                  <col style={{ width: '5%' }} />
                  <col style={{ width: '8%' }} />
                  <col style={{ width: '9%' }} />
                  <col style={{ width: '6%' }} />
                  <col style={{ width: '8%' }} />
                  <col style={{ width: '17%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Threat Signature & Heuristic</th>
                    <th>Source → Destination</th>
                    <th>Category</th>
                    <th>Proto</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Risk</th>
                    <th>Time</th>
                    <th className="sticky-col-right" style={{ textAlign: 'right', paddingRight: 16 }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedAlerts.map(a => (
                    <tr key={a.id}>
                      <td>
                        <div
                          style={{
                            fontWeight: 600,
                            color: 'var(--text-primary)',
                            fontSize: '0.85rem',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}
                          title={a.signature}
                        >
                          {a.signature}
                        </div>
                      </td>
                      <td>
                        <div
                          className="mono"
                          style={{
                            fontSize: '0.78rem',
                            color: 'var(--text-secondary)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}
                          title={`${a.src_ip || '?'}:${a.src_port || '*'} → ${a.dst_ip || '?'}:${a.dst_port || '*'}`}
                        >
                          {a.src_ip || '?'}:{a.src_port || '*'} → {a.dst_ip || '?'}:{a.dst_port || '*'}
                        </div>
                      </td>
                      <td>
                        <span style={{
                          fontSize: '0.72rem',
                          textTransform: 'uppercase',
                          letterSpacing: '0.04em',
                          padding: '2px 8px',
                          borderRadius: 4,
                          background: 'rgba(56, 189, 248, 0.08)',
                          color: '#38bdf8',
                          border: '1px solid rgba(56, 189, 248, 0.2)',
                          fontWeight: 600,
                          display: 'inline-block',
                          maxWidth: '100%',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap'
                        }} title={a.category || 'Threat'}>
                          {a.category || 'threat'}
                        </span>
                      </td>
                      <td>
                        <span style={{
                          fontSize: '0.72rem',
                          fontFamily: 'monospace',
                          background: 'rgba(255,255,255,0.06)',
                          padding: '2px 6px',
                          borderRadius: 4,
                          color: 'var(--text-muted)'
                        }}>
                          {a.protocol || '—'}
                        </span>
                      </td>
                      <td>
                        <SeverityBadge severity={a.severity} />
                      </td>
                      <td>
                        <StatusBadge status={a.status} />
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div style={{ width: 36, height: 4, borderRadius: 2, background: 'rgba(255,255,255,0.1)', overflow: 'hidden' }}>
                            <div
                              style={{
                                width: `${Math.min(100, a.risk_score || 0)}%`,
                                height: '100%',
                                background: (a.risk_score || 0) > 75 ? '#ef4444' : (a.risk_score || 0) > 50 ? '#f97316' : '#10b981'
                              }}
                            />
                          </div>
                          <span style={{ fontSize: '0.75rem', fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                            {a.risk_score || 0}
                          </span>
                        </div>
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {(() => { const { relative, absolute } = formatRelativeTime(a.timestamp); return <span className="rel-time" title={absolute}>{relative}</span>; })()}
                      </td>
                      <td className="sticky-col-right" style={{ textAlign: 'right', paddingRight: 16 }}>
                        <div style={{ display: 'inline-flex', gap: 6, alignItems: 'center', whiteSpace: 'nowrap', justifyContent: 'flex-end' }}>
                          <button
                            className="btn btn-ghost btn-sm"
                            style={{ fontSize: '0.72rem', padding: '3px 8px', border: '1px solid var(--border-subtle)' }}
                            title="Deep Packet Inspection & PCAP Trace"
                            onClick={() => setSelectedAlertForPCAP(a.id)}
                          >
                            📦 DPI
                          </button>
                          {a.status !== 'RESOLVED' && (
                            <button
                              className="btn btn-sm"
                              style={{
                                fontSize: '0.7rem',
                                padding: '3px 8px',
                                background: 'rgba(16, 185, 129, 0.12)',
                                color: 'var(--accent-green)',
                                border: '1px solid rgba(16, 185, 129, 0.3)',
                              }}
                              title="Mark alert as Resolved"
                              onClick={() => handleStatusChange(a.id, 'RESOLVED')}
                            >
                              ✓
                            </button>
                          )}
                          <select
                            className="select"
                            style={{ width: 110, padding: '3px 6px', fontSize: '0.72rem' }}
                            value={a.status}
                            onChange={e => handleStatusChange(a.id, e.target.value)}
                          >
                            {['OPEN', 'AUTO_BLOCKED', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map(s =>
                              <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
                            )}
                          </select>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Pagination */}
        <Pagination
          currentPage={currentPage}
          pageSize={pageSize}
          totalItems={displayedAlerts.length}
          label="threat alerts"
          loading={loading}
          onPageChange={(page) => {
            setCurrentPage(page);
            if (tableWrapperRef.current) {
              tableWrapperRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
          }}
          onPageSizeChange={(newSize) => {
            setPageSize(newSize);
            setCurrentPage(1);
          }}
        />
      </div>

      {/* PCAP / DPI Forensics Modal */}
      {selectedAlertForPCAP && (
        <PCAPViewerModal
          alertId={selectedAlertForPCAP}
          onClose={() => setSelectedAlertForPCAP(null)}
        />
      )}
    </PageLayout>
  );
}
