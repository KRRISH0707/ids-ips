'use client';

import { useState, useEffect, useCallback, useMemo } from 'react';
import Sidebar from '@/components/Sidebar';
import { PageLayout, Spinner, EmptyState } from '@/components/ui';
import { api } from '@/lib/api';
import { useOnLiveEvent } from '@/lib/useLiveFeed';
import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid
} from 'recharts';

function CustomPieTooltip({ active, payload }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    const color = data.payload?.color || data.color || '#60a5fa';
    const name = data.name || data.payload?.name || 'Indicator Type';
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
          {value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>indicators</span>
        </div>
      </div>
    );
  }
  return null;
}

function CustomBarTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    const data = payload[0];
    const fill = data.payload?.fill || data.color || '#10b981';
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
          {data.value} <span style={{ fontSize: '0.72rem', fontWeight: 500, color: 'var(--text-secondary)' }}>verified feeds</span>
        </div>
      </div>
    );
  }
  return null;
}

const TYPE_COLORS = {
  IP: '#60a5fa',
  DOMAIN: '#fbbf24',
  HASH: '#c084fc',
};

export default function ThreatIntelPage() {
  const [intel, setIntel] = useState([]);
  const [breakdown, setBreakdown] = useState({});
  const [loading, setLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [lookupResult, setLookupResult] = useState(null);
  const [lookingUp, setLookingUp] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showAnalytics, setShowAnalytics] = useState(true);
  const [newIOC, setNewIOC] = useState({ ioc_type: 'IP', value: '', threat_type: '', confidence: 90, source: 'SOC Analyst' });

  const fetchIntel = useCallback(async (showSpinner = true) => {
    try {
      if (showSpinner) setLoading(true);
      const res = await api.getThreatIntel({ limit: 250 });
      setIntel(res?.items || []);
      setBreakdown(res?.breakdown || {});
    } catch (err) {
      console.error('Failed to load threat intel:', err);
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchIntel(true);
  }, [fetchIntel]);

  // Real-time synchronization
  useOnLiveEvent((event) => {
    if (event.src_ip) {
      setIntel((prev) => {
        if (prev.some((i) => i.value === event.src_ip)) return prev;
        return [
          {
            id: `ioc-${Date.now()}`,
            ioc_type: 'IP',
            value: event.src_ip,
            threat_type: `Live Intercept: ${event.signature ? event.signature.slice(0, 50) : 'Threat'}`,
            confidence: event.risk_score || 95,
            source: 'Apex Autonomous Sensor',
            tags: [event.category || 'threat', 'autonomous_quarantine'],
            created_at: new Date().toISOString(),
          },
          ...prev,
        ];
      });

      setBreakdown((prev) => ({
        ...prev,
        IP: (prev?.IP || 0) + 1,
      }));
    }

    fetchIntel(false);
  });

  const handleLookup = async (e) => {
    e.preventDefault();
    if (!searchQuery.trim()) return;

    try {
      setLookingUp(true);
      const res = await api.lookupThreatIndicator({ value: searchQuery.trim() });
      setLookupResult(res);
    } catch (err) {
      alert(`Lookup failed: ${err.message}`);
    } finally {
      setLookingUp(false);
    }
  };

  const handleAddIOC = async (e) => {
    e.preventDefault();
    try {
      await api.addThreatIndicator(newIOC);
      setShowAddModal(false);
      setNewIOC({ ioc_type: 'IP', value: '', threat_type: '', confidence: 90, source: 'SOC Analyst' });
      await fetchIntel();
    } catch (err) {
      alert(`Failed to add indicator: ${err.message}`);
    }
  };

  const filteredIntel = useMemo(() => {
    return intel.filter(item => {
      if (typeFilter !== 'ALL' && item.ioc_type !== typeFilter) return false;
      if (searchQuery.trim() && !lookupResult) {
        const q = searchQuery.toLowerCase();
        const v = (item.value || '').toLowerCase();
        const t = (item.threat_type || '').toLowerCase();
        const s = (item.source || '').toLowerCase();
        if (!v.includes(q) && !t.includes(q) && !s.includes(q)) return false;
      }
      return true;
    });
  }, [intel, typeFilter, searchQuery, lookupResult]);

  // Chart Data: Type Distribution Donut
  const typeChartData = useMemo(() => {
    return [
      { name: 'IP Addresses', rawType: 'IP', value: breakdown['IP'] || 0, color: TYPE_COLORS.IP },
      { name: 'Hostile Domains', rawType: 'DOMAIN', value: breakdown['DOMAIN'] || 0, color: TYPE_COLORS.DOMAIN },
      { name: 'Malware Hashes', rawType: 'HASH', value: breakdown['HASH'] || 0, color: TYPE_COLORS.HASH },
    ].filter(item => item.value > 0);
  }, [breakdown]);

  // Chart Data: Confidence Tiers BarChart
  const confidenceChartData = useMemo(() => {
    const tiers = {
      'Critical (90-100%)': 0,
      'High (75-89%)': 0,
      'Medium (50-74%)': 0,
    };
    intel.forEach(item => {
      const conf = item.confidence || 90;
      if (conf >= 90) tiers['Critical (90-100%)']++;
      else if (conf >= 75) tiers['High (75-89%)']++;
      else tiers['Medium (50-74%)']++;
    });
    return [
      { tier: 'Critical (90-100%)', count: tiers['Critical (90-100%)'], fill: '#ef4444' },
      { tier: 'High (75-89%)', count: tiers['High (75-89%)'], fill: '#f59e0b' },
      { tier: 'Medium (50-74%)', count: tiers['Medium (50-74%)'], fill: '#10b981' },
    ];
  }, [intel]);

  return (
    <PageLayout sidebar={<Sidebar />}>
      {/* Page Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <h1 className="page-title glow-text" style={{ margin: 0 }}>Threat Intelligence Hub</h1>
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
              GLOBAL FEEDS SYNCHRONIZED
            </span>
          </div>
          <p className="page-subtitle" style={{ margin: '4px 0 0' }}>
            Real-time Indicators of Compromise (IOC) matching & global reputation scoring
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setShowAnalytics(!showAnalytics)}
            style={{ display: 'flex', alignItems: 'center', gap: 6 }}
            title="Toggle visual threat graphs"
          >
            <span>📊</span>
            <span>{showAnalytics ? 'Hide Analytics' : 'Show Analytics'}</span>
          </button>
          <button className="btn btn-secondary btn-sm" onClick={() => fetchIntel(true)}>
            🔄 Refresh
          </button>
          <button className="btn btn-primary btn-sm" onClick={() => setShowAddModal(true)}>
            + Ingest IOC
          </button>
        </div>
      </div>

      {/* Enterprise Operations Metric Ribbon */}
      <div className="enterprise-soc-ribbon">
        <div
          className="metric-card-enterprise"
          onClick={() => setTypeFilter('ALL')}
          style={{ cursor: 'pointer' }}
          title="Click to view all IOC indicators"
        >
          <div className="metric-label">Total Active IOCs</div>
          <div className="metric-value" style={{ color: 'var(--text-primary)' }}>
            {intel.length}
          </div>
          <div className="metric-subtext">Aggregated threat signatures (click to reset)</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => setTypeFilter(typeFilter === 'IP' ? 'ALL' : 'IP')}
          style={{ cursor: 'pointer' }}
          title="Click to filter by IP indicators"
        >
          <div className="metric-label">Malicious IP Indicators</div>
          <div className="metric-value" style={{ color: '#ef4444' }}>
            {breakdown['IP'] || 0}
          </div>
          <div className="metric-subtext">Actively dropped on perimeter (click to filter)</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => setTypeFilter(typeFilter === 'DOMAIN' ? 'ALL' : 'DOMAIN')}
          style={{ cursor: 'pointer' }}
          title="Click to filter by Domain indicators"
        >
          <div className="metric-label">Hostile C2 Domains</div>
          <div className="metric-value" style={{ color: '#f59e0b' }}>
            {breakdown['DOMAIN'] || 0}
          </div>
          <div className="metric-subtext">DNS sinkholed in resolver (click to filter)</div>
        </div>

        <div
          className="metric-card-enterprise"
          onClick={() => setTypeFilter(typeFilter === 'HASH' ? 'ALL' : 'HASH')}
          style={{ cursor: 'pointer' }}
          title="Click to filter by file hashes"
        >
          <div className="metric-label">Malware Hashes</div>
          <div className="metric-value" style={{ color: '#a855f7' }}>
            {breakdown['HASH'] || 0}
          </div>
          <div className="metric-subtext">SHA256 payloads indexed (click to filter)</div>
        </div>
      </div>

      {/* Visual Analytics Graphs */}
      {showAnalytics && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: 20, marginBottom: 20 }}>
          {/* IOC Distribution Donut Chart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Indicator Vector Distribution
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Breakdown by indicator format
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#60a5fa', fontWeight: 700, background: 'rgba(96,165,250,0.12)', padding: '2px 8px', borderRadius: 10 }}>
                FEED RATIO
              </span>
            </div>

            {typeChartData.length > 0 ? (
              <div style={{ width: '100%', height: 210 }}>
                <ResponsiveContainer width="100%" height={210}>
                  <PieChart>
                    <Pie
                      data={typeChartData}
                      nameKey="name"
                      dataKey="value"
                      cx="50%"
                      cy="48%"
                      innerRadius={44}
                      outerRadius={74}
                      paddingAngle={4}
                      isAnimationActive={false}
                      onClick={(entry) => setTypeFilter(entry.rawType)}
                      cursor="pointer"
                    >
                      {typeChartData.map((entry, index) => (
                        <Cell key={`type-${index}`} fill={entry.color} stroke="transparent" />
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
              <EmptyState message="No indicator distribution telemetry" />
            )}
          </div>

          {/* Confidence Distribution Bar Chart */}
          <div className="glass-card" style={{ padding: 22 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '0.92rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Intelligence Confidence Spectrum
                </h3>
                <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
                  Indicator certainty rating from threat feeds
                </span>
              </div>
              <span style={{ fontSize: '0.7rem', color: '#10b981', fontWeight: 700, background: 'rgba(16,185,129,0.12)', padding: '2px 8px', borderRadius: 10 }}>
                CERTAINTY
              </span>
            </div>

            <div style={{ width: '100%', height: 210 }}>
              <ResponsiveContainer width="100%" height={210}>
                <BarChart data={confidenceChartData} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="tier" stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                  <YAxis stroke="var(--text-muted)" fontSize={10} tickLine={false} />
                  <Tooltip
                    content={<CustomBarTooltip />}
                    wrapperStyle={{ zIndex: 9999, pointerEvents: 'none' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]} isAnimationActive={false}>
                    {confidenceChartData.map((entry, index) => (
                      <Cell key={`bar-${index}`} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      {/* Quick Lookup Bar */}
      <div className="glass-card" style={{ padding: '18px 24px', marginBottom: 20 }}>
        <form onSubmit={handleLookup} style={{ display: 'flex', gap: 12 }}>
          <input
            type="text"
            className="input"
            style={{ flex: 1, fontSize: '0.86rem' }}
            placeholder="Search or lookup reputation for any IP, Domain, or File Hash (e.g. 45.33.32.156, update-service-cdn-telemetry.org)..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
          <button
            type="submit"
            disabled={lookingUp}
            className="btn btn-primary"
            style={{ padding: '0 24px', fontSize: '0.85rem' }}
          >
            {lookingUp ? 'Checking...' : 'Check Reputation'}
          </button>
        </form>

        {/* Lookup Result Card */}
        {lookupResult && (
          <div
            style={{
              marginTop: 16,
              padding: 16,
              borderRadius: 8,
              background: lookupResult.reputation_level === 'MALICIOUS' ? 'rgba(239, 68, 68, 0.12)' : 'rgba(16, 185, 129, 0.12)',
              border: `1px solid ${lookupResult.reputation_level === 'MALICIOUS' ? '#ef4444' : '#10b981'}`,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: '1.2rem' }}>
                  {lookupResult.reputation_level === 'MALICIOUS' ? '🚨' : '🛡️'}
                </span>
                <span style={{ fontWeight: 700, fontSize: '1rem', color: lookupResult.reputation_level === 'MALICIOUS' ? '#f87171' : '#34d399' }}>
                  {lookupResult.reputation_level}: {lookupResult.threat_family}
                </span>
              </div>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: 4 }}>
                Query: <b style={{ fontFamily: 'monospace', color: 'var(--text-primary)' }}>{lookupResult.query}</b> | Source: {lookupResult.source}
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Threat Confidence</div>
              <div style={{ fontSize: '1.5rem', fontWeight: 800, color: lookupResult.reputation_score > 80 ? '#f87171' : '#60a5fa' }}>
                {lookupResult.reputation_score}%
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Filter Tabs */}
      <div className="glass-card" style={{ padding: '12px 20px', marginBottom: 20, display: 'flex', gap: 14, alignItems: 'center' }}>
        <div className="workspace-nav-bar" style={{ margin: 0, padding: 3 }}>
          {[
            { key: 'ALL', label: `All IOCs (${intel.length})` },
            { key: 'IP', label: `IPs (${breakdown['IP'] || 0})` },
            { key: 'DOMAIN', label: `Domains (${breakdown['DOMAIN'] || 0})` },
            { key: 'HASH', label: `Hashes (${breakdown['HASH'] || 0})` },
          ].map(tab => (
            <button
              key={tab.key}
              className={`workspace-tab-btn ${typeFilter === tab.key ? 'active' : ''}`}
              onClick={() => setTypeFilter(tab.key)}
              style={{ padding: '5px 12px', fontSize: '0.78rem' }}
            >
              {tab.label}
            </button>
          ))}
        </div>
        <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>
          Displaying {filteredIntel.length} indicators
        </span>
      </div>

      {/* IOC Table with Guaranteed Text Bounding */}
      <div className="page-body">
        {loading ? (
          <Spinner />
        ) : filteredIntel.length === 0 ? (
          <EmptyState message="No threat intelligence indicators found" />
        ) : (
          <div className="glass-card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-wrapper">
              <table className="data-table" style={{ tableLayout: 'fixed', width: '100%', minWidth: 980 }}>
                <colgroup>
                  <col style={{ width: '9%' }} />
                  <col style={{ width: '25%' }} />
                  <col style={{ width: '25%' }} />
                  <col style={{ width: '12%' }} />
                  <col style={{ width: '15%' }} />
                  <col style={{ width: '14%' }} />
                </colgroup>
                <thead>
                  <tr>
                    <th>Type</th>
                    <th>Indicator Value</th>
                    <th>Threat Classification</th>
                    <th>Confidence</th>
                    <th>Intel Source</th>
                    <th>Tags</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredIntel.map((row) => (
                    <tr key={row.id}>
                      <td>
                        <span
                          style={{
                            fontSize: '0.72rem',
                            fontWeight: 800,
                            padding: '2px 6px',
                            borderRadius: 4,
                            background: row.ioc_type === 'IP' ? 'rgba(59, 130, 246, 0.2)' : row.ioc_type === 'DOMAIN' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(139, 92, 246, 0.2)',
                            color: row.ioc_type === 'IP' ? '#60a5fa' : row.ioc_type === 'DOMAIN' ? '#fbbf24' : '#c084fc',
                            display: 'inline-block',
                            whiteSpace: 'nowrap'
                          }}
                        >
                          {row.ioc_type}
                        </span>
                      </td>
                      <td>
                        <div
                          style={{
                            fontFamily: 'monospace',
                            fontWeight: 600,
                            color: 'var(--text-primary)',
                            fontSize: '0.82rem',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}
                          title={row.value}
                        >
                          {row.value}
                        </div>
                      </td>
                      <td>
                        <div
                          style={{
                            fontSize: '0.82rem',
                            fontWeight: 600,
                            color: '#f87171',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}
                          title={row.threat_type}
                        >
                          {row.threat_type}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <div style={{ width: 45, height: 6, borderRadius: 3, background: 'rgba(255,255,255,0.1)', overflow: 'hidden' }}>
                            <div style={{ width: `${row.confidence}%`, height: '100%', background: row.confidence > 80 ? '#ef4444' : '#f59e0b' }} />
                          </div>
                          <span style={{ fontSize: '0.75rem', fontWeight: 700 }}>{row.confidence}%</span>
                        </div>
                      </td>
                      <td>
                        <div
                          style={{
                            fontSize: '0.8rem',
                            color: 'var(--text-muted)',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap'
                          }}
                          title={row.source}
                        >
                          {row.source}
                        </div>
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 4, overflow: 'hidden' }}>
                          {(row.tags || []).slice(0, 3).map((t, i) => (
                            <span
                              key={i}
                              style={{
                                fontSize: '0.65rem',
                                padding: '1px 5px',
                                borderRadius: 3,
                                background: 'rgba(255,255,255,0.08)',
                                color: '#94a3b8',
                                border: '1px solid rgba(255,255,255,0.05)',
                                whiteSpace: 'nowrap'
                              }}
                            >
                              {t}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Centered Add IOC Modal */}
      {showAddModal && (
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
          onClick={() => setShowAddModal(false)}
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
                  Ingest Threat Indicator (IOC)
                </h3>
                <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  Add vetted intelligence to IDS/IPS matching engine
                </span>
              </div>
              <button
                type="button"
                className="btn btn-ghost btn-sm"
                onClick={() => setShowAddModal(false)}
                style={{ fontSize: '1.1rem', padding: '4px 8px' }}
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleAddIOC}>
              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Indicator Type
                </label>
                <select
                  className="input"
                  value={newIOC.ioc_type}
                  onChange={(e) => setNewIOC({ ...newIOC, ioc_type: e.target.value })}
                  style={{ fontSize: '0.86rem' }}
                >
                  <option value="IP">IP Address</option>
                  <option value="DOMAIN">Domain Name / FQDN</option>
                  <option value="HASH">File Hash (SHA256)</option>
                </select>
              </div>

              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Indicator Value
                </label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder={newIOC.ioc_type === 'IP' ? 'e.g. 198.51.100.22' : newIOC.ioc_type === 'DOMAIN' ? 'e.g. evil-c2-listener.biz' : 'e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
                  value={newIOC.value}
                  onChange={(e) => setNewIOC({ ...newIOC, value: e.target.value })}
                  style={{ fontSize: '0.86rem', fontFamily: 'monospace' }}
                />
              </div>

              <div style={{ marginBottom: 14 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Threat Classification / Family
                </label>
                <input
                  type="text"
                  className="input"
                  required
                  placeholder="e.g. Cobalt Strike Beacon C2 / LockBit Ransomware"
                  value={newIOC.threat_type}
                  onChange={(e) => setNewIOC({ ...newIOC, threat_type: e.target.value })}
                  style={{ fontSize: '0.86rem' }}
                />
              </div>

              <div style={{ marginBottom: 20 }}>
                <label className="label" style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
                  Confidence Score ({newIOC.confidence}%)
                </label>
                <input
                  type="range"
                  min="50"
                  max="100"
                  value={newIOC.confidence}
                  onChange={(e) => setNewIOC({ ...newIOC, confidence: Number(e.target.value) })}
                  style={{ width: '100%' }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="btn btn-secondary btn-sm" onClick={() => setShowAddModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary btn-sm" style={{ padding: '6px 16px' }}>
                  Ingest Indicator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
