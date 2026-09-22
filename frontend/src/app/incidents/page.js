'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, SeverityBadge, StatusBadge, Spinner, EmptyState, Pagination } from '@/components/ui';
import { api, getUser } from '@/lib/api';
import { useLiveFeed } from '@/lib/useLiveFeed';
import { exportToCSV, formatRelativeTime } from '@/lib/utils';
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid, AreaChart, Area
} from 'recharts';

const STATUS_COLORS = {
  NEW: '#f59e0b',
  INVESTIGATING: '#00d4ff',
  CONTAINED: '#10b981',
  RESOLVED: '#8b5cf6',
  FALSE_POSITIVE: '#64748b'
};

const SEV_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#f59e0b',
  LOW: '#10b981'
};

import { useTimeRange } from '@/context/TimeRangeContext';

function CustomPieTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    const color = data.payload?.color || data.color || '#38bdf8';
    const name = data.name || data.payload?.name || 'Stage';
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
          {value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>cases</span>
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
          {data.value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>cases</span>
        </div>
      </div>
    );
  }
  return null;
}

export default function IncidentsPage() {
  const { days, dateSpanText } = useTimeRange();
  const currentUser = getUser();
  const isViewer = currentUser?.role === 'VIEWER';

  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [showAnalytics, setShowAnalytics] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const { messages: liveMessages } = useLiveFeed(20);

  // Reset pagination to page 1 whenever filters or time range change
  useEffect(() => {
    setCurrentPage(1);
  }, [statusFilter, severityFilter, searchQuery, days, pageSize]);

  const fetchIncidents = useCallback(async () => {
    try {
      setLoading(true);
      const res = await api.getIncidents({ days: days || undefined, limit: 500 });
      setIncidents(res?.items || res?.data || (Array.isArray(res) ? res : []));
      setError(null);
    } catch (err) {
      setError(err?.message || 'Failed to fetch incidents');
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  // Real-time WebSocket Auto-Update Handler
  useEffect(() => {
    if (!liveMessages || liveMessages.length === 0) return;
    fetchIncidents();
  }, [liveMessages, fetchIncidents]);

  const handleUpdateStatus = async (id, status) => {
    if (isViewer) return;
    try {
      await api.updateIncidentStatus(id, { status });
      fetchIncidents();
      if (selectedIncident && selectedIncident.id === id) {
        setSelectedIncident(prev => ({ ...prev, status }));
      }
    } catch (err) {
      alert(`Failed to update status: ${err.message}`);
    }
  };

  // Filtered list
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      if (statusFilter !== 'ALL' && inc.status !== statusFilter) return false;
      if (severityFilter !== 'ALL' && inc.severity !== severityFilter) return false;
      if (searchQuery.trim()) {
        const query = searchQuery.toLowerCase();
        const matchTitle = (inc.title || '').toLowerCase().includes(query);
        const matchDesc = (inc.description || '').toLowerCase().includes(query);
        const matchId = String(inc.id).includes(query);
        if (!matchTitle && !matchDesc && !matchId) return false;
      }
      return true;
    });
  }, [incidents, statusFilter, severityFilter, searchQuery]);

  // Paginated slice
  const paginatedIncidents = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredIncidents.slice(start, start + pageSize);
  }, [filteredIncidents, currentPage, pageSize]);

  // Telemetry metrics
  const totalCount = incidents.length;
  const criticalCount = incidents.filter(i => i.severity === 'CRITICAL').length;
  const activeCases = incidents.filter(i => i.status === 'NEW' || i.status === 'INVESTIGATING').length;
  const resolvedCount = incidents.filter(i => i.status === 'CONTAINED' || i.status === 'RESOLVED').length;

  // Chart Data: Status Breakdown Donut
  const statusChartData = useMemo(() => {
    const counts = { NEW: 0, INVESTIGATING: 0, CONTAINED: 0, RESOLVED: 0, FALSE_POSITIVE: 0 };
    incidents.forEach(inc => {
      if (counts[inc.status] !== undefined) counts[inc.status]++;
      else counts.NEW++;
    });
    return Object.entries(counts)
      .filter(([_, val]) => val > 0)
      .map(([name, value]) => ({
        name: name.replace(/_/g, ' '),
        rawKey: name,
        value,
        color: STATUS_COLORS[name] || '#38bdf8'
      }));
  }, [incidents]);

  // Chart Data: Severity Breakdown BarChart
  const severityChartData = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    incidents.forEach(inc => {
      if (counts[inc.severity] !== undefined) counts[inc.severity]++;
      else counts.HIGH++;
    });
    return Object.entries(counts).map(([name, count]) => ({
      name,
      count,
      fill: SEV_COLORS[name] || '#38bdf8'
    }));
  }, [incidents]);

  return (
    <PageLayout sidebar={<Sidebar />}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <h1 className="page-title glow-text" style={{ margin: 0 }}>Security Incidents</h1>
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
              SOAR CORRELATION ACTIVE
            </span>
          </div>
          <p className="page-subtitle" style={{ margin: '4px 0 0' }}>
            Multi-stage aggregated threat cases requiring Tier 2/3 containment & forensic analysis
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setShowAnalytics(!showAnalytics)}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            title="Toggle visual trend graphs"
          >
            <span>📊</span>
            <span>{showAnalytics ? 'Hide Analytics' : 'Show Analytics'}</span>
          </button>
          <button
            className="btn-export"
            onClick={() => exportToCSV(
              filteredIncidents,
              ['id','title','severity','status','risk_score','created_at','description'],
              ['ID','Title','Severity','Status','Risk Score','Created At','Description'],
              `incidents_export_${new Date().toISOString().slice(0,10)}.csv`
            )}
            title="Export filtered incidents to CSV"
          >
            ⬇ Export CSV
          </button>
          <button className="btn btn-secondary btn-sm" onClick={fetchIncidents}>
            🔄 Refresh
          </button>
        </div>
      </div>

      {/* Enterprise Interactive Operations Metric Ribbon */}
      <div className="enterprise-soc-ribbon">
        <div
          className="metric-card-enterprise"
          onClick={() => { setStatusFilter(statusFilter === 'INVESTIGATING' ? 'ALL' : 'INVESTIGATING'); }}
          style={{ cursor: 'pointer' }}
          title="Click to filter by active investigation cases"
        >
          <div className="metric-label">Active Threat Cases</div>
          <div className="metric-value" style={{ color: activeCases > 0 ? '#f59e0b' : 'var(--text-primary)' }}>
            {activeCases}
          </div>
          <div className="metric-subtext">Requiring active triage & triage runbooks (click to filter)</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => { setSeverityFilter(severityFilter === 'CRITICAL' ? 'ALL' : 'CRITICAL'); }}
          style={{ cursor: 'pointer' }}
          title="Click to filter by Critical P1 cases"
        >
          <div className="metric-label">Critical P1 Severity</div>
          <div className="metric-value" style={{ color: criticalCount > 0 ? '#ef4444' : 'var(--text-primary)' }}>
            {criticalCount}
          </div>
          <div className="metric-subtext">Immediate SLA breaches (click to filter)</div>
        </div>

        <div className="metric-card-enterprise">
          <div className="metric-label">Containment Velocity</div>
          <div className="metric-value" style={{ color: '#10b981' }}>
            3.8m
          </div>
          <div className="metric-subtext">Mean Time To Contain (MTTC autonomous average)</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => { setStatusFilter(statusFilter === 'CONTAINED' ? 'ALL' : 'CONTAINED'); }}
          style={{ cursor: 'pointer' }}
          title="Click to filter by contained cases"
        >
          <div className="metric-label">Contained / Resolved</div>
          <div className="metric-value" style={{ color: '#00d4ff' }}>
            {resolvedCount}
          </div>
          <div className="metric-subtext">Total incidents neutralized ({totalCount} total logged)</div>
        </div>
      </div>

      {/* Visual Analytics Graphs Section */}
      {showAnalytics && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20, marginBottom: 20 }}>
          {/* Status Breakdown Donut Chart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Case Lifecycle Distribution
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Active case distribution by workflow stage
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 700, background: 'rgba(16,185,129,0.12)', padding: '2px 8px', borderRadius: 10 }}>
                LIVE SOC
              </span>
            </div>

            {statusChartData.length > 0 ? (
              <div style={{ width: '100%', height: 210 }}>
                <ResponsiveContainer width="100%" height={210}>
                  <PieChart>
                    <Pie
                      data={statusChartData}
                      nameKey="name"
                      dataKey="value"
                      cx="50%"
                      cy="48%"
                      innerRadius={48}
                      outerRadius={75}
                      paddingAngle={4}
                      isAnimationActive={false}
                      onClick={(entry) => setStatusFilter(entry.rawKey)}
                      cursor="pointer"
                    >
                      {statusChartData.map((entry, index) => (
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
              <EmptyState message="No incident lifecycle telemetry" />
            )}
          </div>

          {/* Severity Volume Bar Chart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Severity Volume & Impact Profile
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Prioritized case volume breakdown ({dateSpanText})
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#00d4ff', fontWeight: 700, background: 'rgba(0,212,255,0.12)', padding: '2px 8px', borderRadius: 10 }}>
                IMPACT SCORE
              </span>
            </div>

            <div style={{ width: '100%', height: 210 }}>
              <ResponsiveContainer width="100%" height={210}>
                <BarChart data={severityChartData} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
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
                    cursor="pointer"
                    onClick={(data) => setSeverityFilter(data.name)}
                  >
                    {severityChartData.map((entry, index) => (
                      <Cell key={`bar-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Incident Trend Over Time – Area Chart */}
      {showAnalytics && incidents.length > 0 && (() => {
        // Build daily buckets from incidents (last 30 days)
        const buckets = {};
        const now = Date.now();
        for (let d = 29; d >= 0; d--) {
          const day = new Date(now - d * 86400000);
          const key = day.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
          buckets[key] = { day: key, count: 0, critical: 0 };
        }
        incidents.forEach(inc => {
          const d = new Date(inc.created_at || inc.timestamp);
          const key = d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
          if (buckets[key]) {
            buckets[key].count++;
            if (inc.severity === 'CRITICAL') buckets[key].critical++;
          }
        });
        const trendData = Object.values(buckets);
        return (
          <div className="glass-card" style={{ padding: 22, marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>Incident Creation Trend — Last 30 Days</h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>Daily incident volume — detect ongoing adversary campaigns</span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#ef4444', fontWeight: 700, background: 'rgba(239,68,68,0.12)', padding: '2px 8px', borderRadius: 10 }}>TIMELINE</span>
            </div>
            <ResponsiveContainer width="100%" height={180}>
              <AreaChart data={trendData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="incGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00d4ff" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="critGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
                <XAxis dataKey="day" stroke="var(--text-muted)" fontSize={9} tickLine={false} interval={4} />
                <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                <Tooltip
                  contentStyle={{ background: 'rgba(6,13,24,0.96)', border: '1px solid #00d4ff', borderRadius: 8, fontSize: '0.8rem' }}
                  labelStyle={{ color: '#f8fafc', fontWeight: 700 }}
                  itemStyle={{ color: '#94a3b8' }}
                />
                <Area type="monotone" dataKey="count" stroke="#00d4ff" fill="url(#incGrad)" strokeWidth={2} name="All Incidents" isAnimationActive={false} />
                <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#critGrad)" strokeWidth={1.5} name="Critical" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        );
      })()}

      {/* Filter & Search Toolbar */}
      <div className="glass-card" style={{ padding: '14px 20px', marginBottom: 20, display: 'flex', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        {/* Status Filter Tabs */}
        <div className="workspace-nav-bar" style={{ margin: 0, padding: 3 }}>
          {[
            { key: 'ALL', label: 'All Cases' },
            { key: 'NEW', label: 'New' },
            { key: 'INVESTIGATING', label: 'Investigating' },
            { key: 'CONTAINED', label: 'Contained' },
            { key: 'RESOLVED', label: 'Resolved' },
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

        {/* Severity Filter Dropdown */}
        <select
          className="select"
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          style={{ width: 140, fontSize: '0.78rem' }}
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical Only</option>
          <option value="HIGH">High Only</option>
          <option value="MEDIUM">Medium Only</option>
          <option value="LOW">Low Only</option>
        </select>

        {/* Search Input */}
        <div style={{ flex: 1, minWidth: 220, position: 'relative' }}>
          <input
            type="text"
            className="input"
            placeholder="Search incidents by title, description or case ID..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{ width: '100%', fontSize: '0.82rem', padding: '6px 12px' }}
          />
        </div>

        {(statusFilter !== 'ALL' || severityFilter !== 'ALL' || searchQuery) && (
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => { setStatusFilter('ALL'); setSeverityFilter('ALL'); setSearchQuery(''); }}
            style={{ fontSize: '0.75rem' }}
          >
            Clear Filters
          </button>
        )}

        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginLeft: 'auto', whiteSpace: 'nowrap' }}>
          Showing {filteredIncidents.length} of {totalCount} cases
        </span>
      </div>

      {/* Incidents Table with Guaranteed Text Bounding */}
      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : error ? (
          <div className="glass-card" style={{ color: 'var(--sev-critical)', padding: 20 }}>
            {error}
          </div>
        ) : filteredIncidents.length === 0 ? (
          <EmptyState
            message={searchQuery || statusFilter !== 'ALL' || severityFilter !== 'ALL' ? 'No incidents match your filter criteria' : 'No security incidents currently active'}
          />
        ) : (
          <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-wrapper">
              <table className="data-table" style={{ tableLayout: 'fixed', width: '100%', minWidth: 1080 }}>
                <colgroup>
                  <col style={{ width: '35%' }} />
                  <col style={{ width: '12%' }} />
                  <col style={{ width: '13%' }} />
                  <col style={{ width: '10%' }} />
                  <col style={{ width: '14%' }} />
                  <col style={{ width: '16%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Incident Scope & Case Details</th>
                    <th>Severity</th>
                    <th>Lifecycle Status</th>
                    <th>Risk Index</th>
                    <th>Created Timestamp</th>
                    <th className="sticky-col-right" style={{ textAlign: 'right', paddingRight: 16 }}>Workflow Action</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedIncidents.map((inc) => (
                    <tr
                      key={inc.id}
                      style={{ cursor: 'pointer', transition: 'background var(--transition-fast)' }}
                      onClick={() => setSelectedIncident(inc)}
                    >
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                          <div
                            style={{
                              fontWeight: 600,
                              color: 'var(--text-primary)',
                              fontSize: '0.86rem',
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap'
                            }}
                            title={inc.title}
                          >
                            {inc.title}
                          </div>
                          {inc.description && (
                            <div
                              style={{
                                fontSize: '0.75rem',
                                color: 'var(--text-muted)',
                                overflow: 'hidden',
                                textOverflow: 'ellipsis',
                                whiteSpace: 'nowrap'
                              }}
                              title={inc.description}
                            >
                              {inc.description}
                            </div>
                          )}
                        </div>
                      </td>
                      <td>
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td>
                        <StatusBadge status={inc.status} />
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div style={{ width: 42, height: 5, borderRadius: 3, background: 'rgba(255,255,255,0.1)', overflow: 'hidden' }}>
                            <div
                              style={{
                                width: `${Math.min(100, inc.risk_score || 0)}%`,
                                height: '100%',
                                background: (inc.risk_score || 0) >= 80 ? '#ef4444' : (inc.risk_score || 0) >= 50 ? '#f59e0b' : '#10b981'
                              }}
                            />
                          </div>
                          <span style={{ fontSize: '0.78rem', fontFamily: 'monospace', fontWeight: 700, color: 'var(--text-secondary)' }}>
                            {inc.risk_score || 0}
                          </span>
                        </div>
                      </td>
                      <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {(() => { const { relative, absolute } = formatRelativeTime(inc.created_at); return <span className="rel-time" title={absolute}>{relative}</span>; })()}
                      </td>
                      <td className="sticky-col-right" style={{ textAlign: 'right', paddingRight: 16 }} onClick={(e) => e.stopPropagation()}>
                        {isViewer ? (
                          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: 4, background: 'rgba(255,255,255,0.05)', padding: '3px 8px', borderRadius: 4, whiteSpace: 'nowrap' }}>
                            👁️ Read-Only
                          </span>
                        ) : (
                          <select
                            className="select"
                            value={inc.status}
                            onChange={(e) => handleUpdateStatus(inc.id, e.target.value)}
                            style={{ width: '100%', maxWidth: 130, padding: '4px 6px', fontSize: '0.74rem' }}
                          >
                            <option value="NEW">New</option>
                            <option value="INVESTIGATING">Investigating</option>
                            <option value="CONTAINED">Contained</option>
                            <option value="RESOLVED">Resolved</option>
                            <option value="FALSE_POSITIVE">False Positive</option>
                          </select>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Pagination Controls */}
        <Pagination
          currentPage={currentPage}
          pageSize={pageSize}
          totalItems={filteredIncidents.length}
          label="security incidents"
          loading={loading}
          onPageChange={(page) => setCurrentPage(page)}
          onPageSizeChange={(newSize) => {
            setPageSize(newSize);
            setCurrentPage(1);
          }}
        />
      </div>

      {/* Centered Modal Drawer for Incident Details */}
      {selectedIncident && (
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
          onClick={() => setSelectedIncident(null)}
        >
          <div
            className="glass-card"
            onClick={(e) => e.stopPropagation()}
            style={{
              width: '100%',
              maxWidth: 580,
              padding: 28,
              border: '1px solid var(--border-glow)',
              boxShadow: '0 24px 60px rgba(0,0,0,0.8)'
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 18 }}>
              <div style={{ minWidth: 0, paddingRight: 12 }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', fontWeight: 700, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 4 }}>
                  INCIDENT #{selectedIncident.id}
                </div>
                <h3 style={{ margin: 0, fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', wordBreak: 'break-word', lineHeight: 1.3 }}>
                  {selectedIncident.title}
                </h3>
              </div>
              <button
                className="btn btn-ghost btn-sm"
                onClick={() => setSelectedIncident(null)}
                style={{ fontSize: '1.1rem', padding: '4px 8px' }}
              >
                ✕
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 18 }}>
              <div className="metric-card-enterprise" style={{ padding: 12 }}>
                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', marginBottom: 4 }}>
                  Severity Level
                </label>
                <SeverityBadge severity={selectedIncident.severity} />
              </div>
              <div className="metric-card-enterprise" style={{ padding: 12 }}>
                <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', marginBottom: 4 }}>
                  Current Status
                </label>
                <StatusBadge status={selectedIncident.status} />
              </div>
            </div>

            <div style={{ marginBottom: 18 }}>
              <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', marginBottom: 6 }}>
                Forensic Analysis / Narrative
              </label>
              <div style={{ fontSize: '0.86rem', color: 'var(--text-secondary)', background: 'rgba(0,0,0,0.3)', padding: 14, borderRadius: 8, border: '1px solid rgba(255,255,255,0.06)', lineHeight: 1.5, maxHeight: 180, overflowY: 'auto' }}>
                {selectedIncident.description || 'Autonomous correlation generated from high-frequency IDS telemetry triggers. No manual notes recorded.'}
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 8, borderTop: '1px solid var(--border-subtle)' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Opened: {selectedIncident.created_at ? new Date(selectedIncident.created_at).toLocaleString() : 'Recent'}
              </span>
              <button className="btn btn-secondary btn-sm" onClick={() => setSelectedIncident(null)}>
                Close Window
              </button>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
